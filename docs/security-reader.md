# Security reader v0.5 (steps 1–2)

The detector is independent from the v0.4 collector. It opens `flows.db` with
SQLite URI `mode=ro` plus `query_only=ON` and writes only to its own
`security.db`. No detection rules, notifications, or response actions exist yet.

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
