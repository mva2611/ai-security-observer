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
