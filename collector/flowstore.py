#!/usr/bin/env python3

import json
import queue
import sqlite3
import sys
import threading
import time


BATCH_SIZE = 500
BATCH_FLUSH_SECONDS = 5.0
SQLITE_TIMEOUT = 0.25
RETRY_DELAYS = (1, 2, 4)
EOF = object()


class ReaderFailure:
    def __init__(self, error):
        self.error = error

PROTOCOLS = {
    "ICMP": 1,
    "TCP": 6,
    "UDP": 17,
    "ICMPv6": 58,
}

COLUMNS = (
    "schema_version",
    "received_at_ns",
    "exporter_ip",
    "sequence_num",
    "flow_start_ns",
    "flow_end_ns",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "ingress_if",
    "egress_if",
    "next_hop",
    "src_mac",
    "dst_mac",
    "bytes",
    "packets",
    "tcp_flags",
    "observation_domain_id",
    "post_nat_src_ip",
    "post_nat_dst_ip",
    "post_napt_src_port",
    "post_napt_dst_port",
)


def normalize(record):
    if record.get("type") != "IPFIX":
        raise ValueError("record is not IPFIX")

    proto = record.get("proto")
    if isinstance(proto, int):
        protocol = proto
    else:
        try:
            protocol = PROTOCOLS[proto]
        except KeyError:
            raise ValueError(f"unknown protocol: {proto!r}")

    return {
        # NAT columns are a backward-compatible nullable extension. Keeping
        # version 1 permits rollback to the original 0.2 collector without
        # discarding flows ingested after migration.
        "schema_version": 1,
        "received_at_ns": record["time_received_ns"],
        "exporter_ip": record["sampler_address"],
        "sequence_num": record.get("sequence_num"),
        "flow_start_ns": record.get("time_flow_start_ns"),
        "flow_end_ns": record.get("time_flow_end_ns"),
        "src_ip": record["src_addr"],
        "dst_ip": record["dst_addr"],
        "src_port": record.get("src_port"),
        "dst_port": record.get("dst_port"),
        "protocol": protocol,
        "ingress_if": record.get("in_if"),
        "egress_if": record.get("out_if"),
        "next_hop": record.get("next_hop"),
        "src_mac": record.get("src_mac"),
        "dst_mac": record.get("dst_mac"),
        "bytes": record.get("bytes"),
        "packets": record.get("packets"),
        "tcp_flags": record.get("tcp_flags"),
        "observation_domain_id": record.get("observation_domain_id"),
        # get() deliberately preserves JSON numeric zero while mapping an
        # absent key to SQL NULL.
        "post_nat_src_ip": record.get("post_nat_src_addr"),
        "post_nat_dst_ip": record.get("post_nat_dst_addr"),
        "post_napt_src_port": record.get("post_napt_src_port"),
        "post_napt_dst_port": record.get("post_napt_dst_port"),
    }



def validate_database(db):
    row = db.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type='table' AND name='flows'"
    ).fetchone()

    if row is None:
        raise RuntimeError("table 'flows' not found")

    actual_columns = {
        row[1]
        for row in db.execute("PRAGMA table_info(flows)")
    }

    expected_columns = {"id", *COLUMNS}
    missing = expected_columns - actual_columns

    if missing:
        raise RuntimeError(
            "missing columns: " + ", ".join(sorted(missing))
        )

    schema_versions = {
        row[0]
        for row in db.execute(
            "SELECT DISTINCT schema_version FROM flows "
            "WHERE schema_version IS NOT NULL"
        )
    }

    if schema_versions and schema_versions != {1}:
        raise RuntimeError(
            f"unsupported schema versions: {sorted(schema_versions)}"
        )

def insert_batch(db, batch):
    if not batch:
        return

    placeholders = ", ".join("?" for _ in COLUMNS)
    sql = (
        f"INSERT INTO flows ({', '.join(COLUMNS)}) "
        f"VALUES ({placeholders})"
    )

    rows = [
        tuple(flow[column] for column in COLUMNS)
        for flow in batch
    ]

    attempts = 1 + len(RETRY_DELAYS)

    for attempt in range(attempts):
        try:
            with db:
                db.executemany(sql, rows)
            return
        except sqlite3.OperationalError as exc:
            if "database is locked" not in str(exc).lower():
                raise

            if attempt >= len(RETRY_DELAYS):
                raise

            delay = RETRY_DELAYS[attempt]
            print(
                f"database locked; retrying in {delay}s "
                f"(attempt {attempt + 2}/{attempts})",
                file=sys.stderr,
            )
            time.sleep(delay)


def process_stream(
    db,
    stream,
    *,
    batch_size=BATCH_SIZE,
    flush_seconds=BATCH_FLUSH_SECONDS,
):
    """Consume JSONL without leaving a partial batch blocked on stdin."""
    lines = queue.Queue(maxsize=batch_size * 2)

    def read_lines():
        try:
            for line in stream:
                lines.put(line)
        except Exception as exc:
            lines.put(ReaderFailure(exc))
        finally:
            lines.put(EOF)

    reader = threading.Thread(target=read_lines, name="flowstore-stdin", daemon=True)
    reader.start()

    received = 0
    written = 0
    invalid = 0
    line_number = 0
    batch = []
    batch_started = None

    def flush():
        nonlocal written, batch_started
        if not batch:
            return
        count = len(batch)
        # Do not clear the in-memory batch until the transaction succeeds.
        insert_batch(db, batch)
        written += count
        batch.clear()
        batch_started = None

    while True:
        timeout = None
        if batch_started is not None:
            timeout = max(0.0, flush_seconds - (time.monotonic() - batch_started))

        try:
            item = lines.get(timeout=timeout)
        except queue.Empty:
            flush()
            continue

        if item is EOF:
            break
        if isinstance(item, ReaderFailure):
            raise item.error

        line_number += 1
        line = item.strip()
        if not line:
            continue

        received += 1
        try:
            record = json.loads(line)
            flow = normalize(record)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            invalid += 1
            print(
                f"invalid record at line {line_number}: {exc}",
                file=sys.stderr,
            )
            continue

        if not batch:
            batch_started = time.monotonic()
        batch.append(flow)

        if len(batch) >= batch_size:
            flush()

    flush()
    return received, written, invalid


def main():
    if len(sys.argv) != 2:
        print("usage: flowstore.py DATABASE", file=sys.stderr)
        return 2

    db_path = sys.argv[1]
    with sqlite3.connect(db_path, timeout=SQLITE_TIMEOUT) as db:
        try:
            validate_database(db)
        except (sqlite3.Error, RuntimeError) as exc:
            print(
                f"FATAL: database schema validation failed: {exc}",
                file=sys.stderr,
            )
            return 1

        received, written, invalid = process_stream(db, sys.stdin)

    print(
        f"received={received} written={written} invalid={invalid}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
