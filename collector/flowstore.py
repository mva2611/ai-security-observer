#!/usr/bin/env python3

import json
import sqlite3
import sys


BATCH_SIZE = 500

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

    with db:
        db.executemany(sql, rows)


def main():
    if len(sys.argv) != 2:
        print("usage: flowstore.py DATABASE", file=sys.stderr)
        return 2

    db_path = sys.argv[1]
    received = 0
    written = 0
    invalid = 0
    batch = []

    with sqlite3.connect(db_path) as db:
        try:
            validate_database(db)
        except (sqlite3.Error, RuntimeError) as exc:
            print(
                f"FATAL: database schema validation failed: {exc}",
                file=sys.stderr,
            )
            return 1

        for line_number, line in enumerate(sys.stdin, start=1):
            line = line.strip()
            if not line:
                continue

            received += 1

            try:
                record = json.loads(line)
                flow = normalize(record)
                batch.append(flow)
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                invalid += 1
                print(
                    f"invalid record at line {line_number}: {exc}",
                    file=sys.stderr,
                )
                continue

            if len(batch) >= BATCH_SIZE:
                insert_batch(db, batch)
                written += len(batch)
                batch.clear()

        if batch:
            insert_batch(db, batch)
            written += len(batch)

    print(
        f"received={received} written={written} invalid={invalid}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
