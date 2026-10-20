# Security reader v0.5 (steps 1–2)

The detector is independent from the v0.4 collector. It opens `flows.db` with
SQLite URI `mode=ro` plus `query_only=ON` and writes only to its own
`security.db`. R2 profile changes and R4 run only at the `observe` level; notifications and
response actions do not exist.

Each batch reads increasing `flows.id` values. Gap observations, future rule
state, and the checkpoint commit in one `security.db` transaction. A crash
before commit rolls everything back; replay is safe. Gaps are operational
evidence only because SQLite IDs need not be contiguous.

Isolated one-shot verification:

```sh
python3 detector/security_reader.py /path/to/copy/flows.db /tmp/security.db --once
sqlite3 /tmp/security.db 'PRAGMA integrity_check; SELECT * FROM detector_checkpoints;'
python3 -m unittest tests.test_security_reader -v
```

For DS923+ validation, use a consistent copy of `flows.db` first. A later
read-only production rehearsal must mount the complete live database directory
(including WAL/SHM) read-only and a separate writable directory for
`security.db`. Confirm WAL visibility, ingestion latency, checkpoint restart,
and that the collector row count continues to grow. Do not mount the collector
data directory writable into the detector container.

## Traffic identity and v0.5 rules

The verified RB5009 mapping is `br-lan=10` and `WAN=8`. Both IDs are explicit
CLI settings (`--lan-if`, `--wan-if`) so a changed router layout fails visibly
instead of silently reversing direction. Only routed LAN-to-WAN records are
eligible for R2/R4. Private, multicast, loopback, documentation, and otherwise
non-global destinations are excluded. A canonical flow signature suppresses a
duplicate LAN/WAN representation without treating opposite traffic direction
as a duplicate.

Device identity is an observed, valid unicast source MAC from that flow. It is
never reconstructed from the current DHCP state. Missing or ambiguous identity
is `unknown` and is not evaluated by per-device rules.

R2 records the first external peer group per device and destination service.
IPv4 peers default to `/24` and IPv6 peers to `/48`, reducing cloud-IP rotation
noise. TCP/UDP are merged only for DNS port 53 and HTTPS/QUIC port 443; other
ports retain their transport protocol. Baseline completion requires both 1,000
canonical flows and 48 hours of observation. Both values are configurable.
After baseline, a new peer is written to `communication_profile_changes`, not
to `security_events`: it is a profile change, not a security incident.

R4 counts unique external destinations and ports in fixed time windows. Default
thresholds are 120 destinations or 25 ports, at least 20 canonical flows, in 10
minutes. Thresholds are CLI-configurable. Local discovery is excluded before
counting, and an R4 event explicitly records that IPFIX does not prove a
successful connection.

Window timestamps use the stored flow end time. For legacy
`flow_time_source=export_fallback` rows this is only an export/receive-time
approximation; it must not be presented as precise connection timing.
R4 maintains a per-device high-water window: an observation may arrive out of
order within the current ten-minute window, but it cannot reopen an older
window after a newer one has already been processed. This is required because
canonical duplicate signatures expire; without the guard, a duplicate delayed
beyond retention could reconstruct a historical window and create a new event.

## Long-running detector container

The proposed deployment files live in `deploy/detector/`. They build a separate
image and do not alter the v0.4 collector. Mount the complete collector data
directory at `/flows:ro`, not only `flows.db`, so SQLite can see the live WAL
and SHM files. Mount a different persistent directory at `/state:rw` for
`security.db`. The detector has no network and R2/R4 remain observe-only.

On the first start, `detector.bootstrap` atomically creates the `flows`
checkpoint at the current `MAX(flows.id)`. It never advances an existing
checkpoint, so restarts resume from the last committed batch. It fails closed
if detector evidence exists without a checkpoint. Each later batch commits
detection state, audit records, runtime health, and checkpoint together.

Copy `deploy/detector/env.example` to an untracked `.env` next to the compose
file and verify the real Synology paths and numeric UID/GID. Create the state
directory with access only for that identity. Before starting, build the unique
image tag and inspect the resolved Compose configuration. On first start,
verify that the logged initialized checkpoint equals the pre-start source
maximum, then confirm newer flow IDs advance it.

Proposed first-start sequence (paths must be confirmed on the NAS):

```sh
cd /path/to/ai-security-observer/deploy/detector
cp env.example .env
# Edit only paths, UID/GID, and the unique immutable candidate image tag.
docker compose --env-file .env config
docker compose --env-file .env build --pull detector
docker image inspect ai-security-observer-detector:0.5-test-d1386b0-20261021d
docker compose --env-file .env up -d detector
docker compose --env-file .env logs --no-log-prefix detector
docker inspect --format '{{json .State.Health}}' ai-security-observer-detector
```

Before `up`, record `MAX(id)` from `flows.db` using a read-only connection.
The first log line must show that same checkpoint with `initialized=true`.
After a new source row arrives, verify all of the following from read-only
queries: the checkpoint advances, `detector_runtime_health` is current,
`PRAGMA integrity_check` on `security.db` returns `ok`, and the source database
remains unchanged. A second container restart must log `initialized=false` and
retain the checkpoint.

The container healthcheck reports:

- `healthy_processing`: source `MAX(id)` is ahead of the checkpoint;
- `healthy_idle`: the reader polls successfully and is caught up, even if the
  source has not advanced for a long time;
- `unhealthy_reader_stale`: no successful detector poll within 90 seconds;
- `read_error`: either database cannot be opened or queried.

`no_checkpoint_progress_seconds` is diagnostic only. A quiet source therefore
does not make the container unhealthy. Operators should separately compare the
collector's own health when deciding whether prolonged source inactivity is
expected.

Rollback is `docker compose stop detector` followed by removal of only the
detector container. Preserve the state directory for later inspection or
resume. Removing the detector image or state never touches the read-only flow
mount or the v0.4 collector. Starting the previous detector image against the
same state is allowed only when its schema compatibility has been verified.

Before production approval, pin the Python base image by digest, replace the
candidate tag with a unique tag tied to the final Git commit, and validate the
complete image on a consistent flow-database copy. The Compose file is kept
separate from the collector project so stopping or rolling back the detector
cannot recreate, stop, or modify the v0.4 collector.

Synology's current Docker kernel rejects NanoCPU/CFS quotas. The detector uses
relative `cpu_shares: 512` instead; the 256 MiB memory limit remains hard.
The same kernel discards Compose PID limits, so no ineffective `pids_limit` is
declared; the container still has no network, no capabilities, and a read-only
root filesystem.

## Canonical-flow retention

`canonical_flows` currently grows by one row for every unique canonical
observation. Its purpose is short-range suppression of duplicate LAN/WAN
representations; restart replay is already prevented by the transactional
checkpoint. R2 profile keys and R4 event deduplication also remain persistent.

Canonical rows carry a `processed_at_ns` ingestion timestamp and are retained
for seven days. Expired rows are processed at most once per hour, in a bounded
maintenance cycle of short transactions that each delete no more than 10,000
rows. The default cycle allows at most 100 chunks. Detector insertions, rule
state, and the checkpoint remain atomic in their original transaction;
retention commits independently and cannot advance the checkpoint. Cleanup
state is persistent, and an interrupted chunk rolls back without losing its
signatures. Retention is deliberately based on processing time rather than
reconstructed flow time, which may precede ingestion.

If more than one million rows are expired, the default 100-chunk ceiling leaves
the remainder for the next hourly cycle. SQLite pages are reused by subsequent
writes, but cleanup deliberately does not run `VACUUM` or promise that the file
size will shrink immediately.

Seven days is much longer than RouterOS export timeouts and the accepted
timestamp reconstruction window. A duplicate arriving after retention can be
evaluated again and increment an existing R2 occurrence counter, but persistent
R2 profile keys prevent creation of a duplicate profile-change. Existing R4
events remain deduplicated, and the per-device R4 window watermark prevents a
late duplicate from creating a new event for a window that has already become
historical.
