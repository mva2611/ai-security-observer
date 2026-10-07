#!/usr/bin/env python3

import json
import sqlite3
import sys


PROTOCOLS = {
    "ICMP": 1,
    "TCP": 6,
    "UDP": 17,
    "ICMPv6": 58,
}


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


def insert_flow(db, flow):
    columns = list(flow.keys())
    placeholders = ", ".join("?" for _ in columns)

    db.execute(
        f"INSERT INTO flows ({', '.join(columns)}) VALUES ({placeholders})",
        [flow[column] for column in columns],
    )
    db.commit()


def main():
    if len(sys.argv) != 2:
        print("usage: flowstore.py DATABASE", file=sys.stderr)
        return 2

    db_path = sys.argv[1]
    received = 0
    written = 0
    invalid = 0

    with sqlite3.connect(db_path) as db:
        for line_number, line in enumerate(sys.stdin, start=1):
            line = line.strip()
            if not line:
                continue

            received += 1

            try:
                record = json.loads(line)
                flow = normalize(record)
                insert_flow(db, flow)
                written += 1
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                invalid += 1
                print(
                    f"invalid record at line {line_number}: {exc}",
                    file=sys.stderr,
                )

    print(
        f"received={received} written={written} invalid={invalid}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
