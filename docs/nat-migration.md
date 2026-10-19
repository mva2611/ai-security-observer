# NAT collector deployment and SQLite migration

The NAT extension is additive and nullable. Existing and new records retain
`schema_version = 1`, so the original `0.2` collector can read a migrated
database and ignore the extra columns. This is intentional rollback
compatibility.

The same fail-closed migration also adds `flow_time_source`. Existing rows
receive the database default `export_fallback`; their original flow timestamps
cannot be reconstructed because raw RouterOS IE 21/22/160 values were not
stored. New rows are labelled `absolute`, `reconstructed`, or
`export_fallback` by FlowStore. This remains a schema-version-1 additive
extension for rollback compatibility.

Both the new and original FlowStore accept only stored records with
`schema_version = 1`. The NAT collector deliberately does not introduce
version 2: a database containing a version-2 row fails closed, because the
original `0.2` collector could not be used as a lossless rollback target.

FlowStore keeps the 500-record batch size but commits a partial batch five
seconds after its first valid record even when stdin remains open. During an
orderly container stop, GoFlow2 is stopped first so FIFO EOF reaches FlowStore;
the 15-second compose grace period covers final commit and the existing SQLite
lock retry budget.

An explicit `SIGTERM`/`SIGINT` container stop exits with status 0 after this
flush. If GoFlow2 or FlowStore exits without an explicit stop request, the
entrypoint still cleans up the peer process but returns a non-zero status.

## Build immutable images

Do not overwrite the original tag:

```sh
docker image inspect ai-security-observer-collector:0.2 --format '{{.Id}}'
docker build --pull=false -t ai-security-observer-collector:0.3-nat collector
docker image inspect ai-security-observer-collector:0.3-nat --format '{{.Id}}'
```

Record both image IDs. `compose.yaml` defaults to `0.3-nat`; setting
`COLLECTOR_IMAGE=ai-security-observer-collector:0.2` selects the retained
rollback image without retagging either image.

## Isolated full-image test on DS923+

`compose.nat-test.yaml` has no production database mount, publishes only
`127.0.0.1:12056/udp`, has no restart policy, and uses a dedicated named
volume that is never mounted by the production compose file.

```sh
mkdir -p test-fixtures
cp /safe/test/location/mikrotik-ipfix.pcap test-fixtures/

docker volume create ai-security-observer-nat-test-data
docker run --rm --user 0:0 \
  -v ai-security-observer-nat-test-data:/data \
  --entrypoint sh \
  ai-security-observer-collector:0.3-nat \
  -c 'chown collector:collector /data'

docker run --rm \
  -v ai-security-observer-nat-test-data:/data \
  --entrypoint python3 \
  ai-security-observer-collector:0.3-nat \
  -c "import sqlite3; db=sqlite3.connect('/data/flows.db'); db.executescript(open('/app/schema.sql').read()); db.close()"

docker compose -f compose.nat-test.yaml up -d

docker run --rm \
  --network container:ai-security-observer-collector-nat-test \
  -v "$PWD/tests:/tests:ro" \
  -v "$PWD/test-fixtures:/fixtures:ro" \
  --entrypoint python3 \
  ai-security-observer-collector:0.3-nat \
  /tests/replay_ipfix_pcap.py /fixtures/mikrotik-ipfix.pcap --port 12055

docker compose -f compose.nat-test.yaml stop
```

Inspect only the `ai-security-observer-nat-test-data` volume. Verify integrity,
833 decoded rows for the known capture, NAT values, numeric zero for ICMP
ports, and NULL for input JSON without NAT keys. Finally remove the test
container and its disposable volume with:

```sh
docker compose -f compose.nat-test.yaml down
docker volume rm ai-security-observer-nat-test-data
```

For a production-size rehearsal, populate the named volume from a consistent
SQLite backup copy before starting the test collector. The test compose must
never mount `./data` or the production database path.

## Production preflight

1. Record the current image ID, database size, row count, and maximum `id`.
2. Ensure both image tags exist locally.
3. Place backups on a writable backup filesystem. The migration requires the
   logical database size plus the larger of 256 MiB or 10% safety margin.
4. Ensure the backup destination is not the source database and does not
   already exist.
5. Stop the collector and confirm `.State.Running` is false. Do not let another
   process write the database during backup or migration.

Example read-only baseline queries:

```sql
PRAGMA integrity_check;
SELECT count(*), coalesce(max(id), 0) FROM flows;
SELECT schema_version, count(*) FROM flows GROUP BY schema_version;
```

## One-shot migration without DSM Python

The migration utility is included in image `0.3-nat`. It runs through the
image's Python runtime and does not start GoFlow2 or FlowStore:

```sh
docker compose stop collector
docker inspect ai-security-observer-collector --format '{{.State.Running}}'

docker run --rm \
  --read-only \
  --tmpfs /tmp \
  -v "$PWD/data:/data" \
  -v "/absolute/backup/path:/backup" \
  --entrypoint python3 \
  ai-security-observer-collector:0.3-nat \
  /app/migrate_flowstore_nat.py \
  /data/flows.db \
  /backup/flows.before-nat-YYYYmmddTHHMMSS.db
```

The destination directory must be writable by the container's `collector`
user. The tool:

- resolves source and destination paths and rejects the same canonical path;
- rejects an existing or symlink backup destination;
- performs a full source integrity check;
- calculates required free space from SQLite page count and page size;
- creates a consistent SQLite backup, including committed WAL state;
- performs a full backup integrity check;
- refuses a partial prior migration;
- adds the four nullable columns in one transaction;
- performs a final source integrity and schema check.

If backup creation fails, the source schema is unchanged. A partial backup file
may remain and must be inspected or moved aside before retrying.

## Post-migration verification and start

Before starting the collector, use the same image as a one-shot Python process
to verify `PRAGMA integrity_check`, the four column names, baseline row count,
and unchanged maximum `id`. Then start the default `0.3-nat` service:

```sh
docker compose up -d --force-recreate collector
```

Verify container logs, new row growth, NAT values, database integrity, and that
the original standard columns retain their expected values.

## Rollback before new ingest

If migration or validation fails before `0.3-nat` ingests a row:

1. Keep the collector stopped.
2. Preserve the failed database and sidecars for diagnosis.
3. Remove or move aside `flows.db`, `flows.db-wal`, and `flows.db-shm` as one
   set. Never combine the standalone backup with an old WAL/SHM file.
4. Restore the verified standalone backup as `flows.db`.
5. Verify integrity and the recorded baseline row count/max ID.
6. Start the retained image:

   ```sh
   COLLECTOR_IMAGE=ai-security-observer-collector:0.2 \
     docker compose up -d --force-recreate collector
   ```

## Rollback after new ingest

Do **not** restore the pre-migration backup after new rows have arrived; doing
so would discard them. Instead:

1. Stop `0.3-nat` and retain the current migrated DB/WAL/SHM set.
2. Verify database integrity.
3. Start the original `0.2` image against the same migrated database:

   ```sh
   COLLECTOR_IMAGE=ai-security-observer-collector:0.2 \
     docker compose up -d --force-recreate collector
   ```

All rows remain schema version 1. The original FlowStore accepts extra columns
and ignores them; subsequent old-image rows receive NULL NAT values. This
rollback preserves every flow ingested after migration.

No NAT indexes are added. Current ingestion and known queries do not justify
their write and storage cost.
