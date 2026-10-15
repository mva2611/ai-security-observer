#!/usr/bin/env python3
"""Validate GoFlow2 v2.2.6 NAT mapping using an external SLL2 PCAP."""

import argparse
import collections
import ipaddress
import json
import socket
import sqlite3
import struct
import subprocess
import tempfile
import time
from pathlib import Path

from replay_ipfix_pcap import payloads

ROOT = Path(__file__).resolve().parents[1]
MAPPING_SHA256 = "9e0e900da48e51ed4e1ca0dba5e36403e6fd20e25ba258d2799b6368eb8d4a5f"
NAT_KEYS = ("post_nat_src_addr", "post_nat_dst_addr", "post_napt_src_port", "post_napt_dst_port")


def sha256(path):
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def parse_templates(body):
    pos = 0
    templates = []
    while pos + 4 <= len(body):
        template_id, count = struct.unpack_from("!HH", body, pos)
        pos += 4
        fields = []
        for _ in range(count):
            raw_ie, length = struct.unpack_from("!HH", body, pos)
            pos += 4
            if raw_ie & 0x8000:
                pos += 4
            fields.append((raw_ie & 0x7FFF, length))
        templates.append((template_id, fields))
    return templates


def decode_reference(pcap):
    templates = {}
    records = []
    for payload in payloads(pcap):
        _, length, _, _, domain = struct.unpack_from("!HHIII", payload, 0)
        pos = 16
        while pos + 4 <= min(length, len(payload)):
            set_id, set_length = struct.unpack_from("!HH", payload, pos)
            if set_length < 4 or pos + set_length > len(payload):
                break
            body = payload[pos + 4 : pos + set_length]
            if set_id == 2:
                for template_id, fields in parse_templates(body):
                    templates[(domain, template_id)] = fields
            elif set_id == 258 and (domain, set_id) in templates:
                fields = templates[(domain, set_id)]
                record_size = sum(field_length for _, field_length in fields)
                record_pos = 0
                while record_pos + record_size <= len(body):
                    values = {}
                    for ie, field_length in fields:
                        raw = body[record_pos : record_pos + field_length]
                        record_pos += field_length
                        if ie in (8, 12, 225, 226):
                            values[ie] = str(ipaddress.ip_address(raw))
                        elif ie in (1, 2, 7, 10, 11, 14, 227, 228):
                            values[ie] = int.from_bytes(raw, "big")
                    records.append((
                        values.get(8), values.get(12), values.get(7), values.get(11),
                        values.get(10), values.get(14), values.get(1), values.get(2),
                        values.get(225), values.get(226), values.get(227), values.get(228),
                    ))
            pos += set_length
    return records


def run_goflow(binary, pcap, mapping=None):
    port = free_port()
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "flows.jsonl"
        command = [
            str(binary), f"-listen=netflow://127.0.0.1:{port}?count=1&workers=1&blocking=true",
            "-produce=sample", "-format=json", "-transport=file", f"-transport.file={output}", "-addr=",
        ]
        if mapping:
            command.append(f"-mapping={mapping}")
        process = subprocess.Popen(command, stderr=subprocess.PIPE, text=True)
        try:
            time.sleep(0.5)
            subprocess.run(
                ["python3", str(ROOT / "tests/replay_ipfix_pcap.py"), str(pcap), "--port", str(port)],
                check=True,
                capture_output=True,
                text=True,
            )
            time.sleep(1)
        finally:
            process.terminate()
            _, stderr = process.communicate(timeout=5)
        rows = [json.loads(line) for line in output.read_text().splitlines() if line]
        return rows, stderr.count("template error")


def validate_flowstore_timeout_flush(rows):
    with tempfile.TemporaryDirectory() as directory:
        database = Path(directory) / "flows.db"
        with sqlite3.connect(database) as db:
            db.executescript((ROOT / "collector/schema.sql").read_text())

        process = subprocess.Popen(
            ["python3", str(ROOT / "collector/flowstore.py"), str(database)],
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert process.stdin is not None
        assert process.stderr is not None
        for row in rows:
            process.stdin.write(json.dumps(row) + "\n")
        process.stdin.flush()

        # Keep stdin open: the partial 333-record batch must be committed by
        # the five-second deadline rather than by EOF.
        deadline = time.monotonic() + 7
        count = 0
        while time.monotonic() < deadline:
            try:
                with sqlite3.connect(database) as db:
                    count = db.execute("SELECT count(*) FROM flows").fetchone()[0]
            except sqlite3.OperationalError:
                pass
            if count == len(rows):
                break
            time.sleep(0.05)

        process.stdin.close()
        return_code = process.wait(timeout=5)
        stderr = process.stderr.read()
        if return_code != 0:
            raise SystemExit(f"FAIL: FlowStore exited {return_code}: {stderr}")
        if count != len(rows):
            raise SystemExit(
                f"FAIL: timeout flush wrote {count}/{len(rows)} records"
            )

        with sqlite3.connect(database) as db:
            nat = db.execute(
                "SELECT count(*), "
                "sum(post_nat_src_ip IS NOT NULL), "
                "sum(post_nat_dst_ip IS NOT NULL), "
                "sum(post_napt_src_port IS NOT NULL), "
                "sum(post_napt_dst_port IS NOT NULL) FROM flows"
            ).fetchone()
            inbound_zero = db.execute(
                "SELECT count(*) FROM flows WHERE ingress_if=8 AND egress_if=10 "
                "AND (post_napt_src_port=0 OR post_napt_dst_port=0)"
            ).fetchone()[0]
            integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
        if nat != (len(rows),) * 5:
            raise SystemExit(f"FAIL: SQLite NAT coverage mismatch: {nat}")
        if inbound_zero != 4 or integrity != "ok":
            raise SystemExit("FAIL: SQLite NAT zero/integrity mismatch")
        return count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--goflow2", type=Path, required=True)
    args = parser.parse_args()
    mapping = ROOT / "collector/goflow2-mapping.yaml"
    if sha256(mapping) != MAPPING_SHA256:
        raise SystemExit("FAIL: mapping SHA-256 mismatch")
    version = subprocess.run(
        [str(args.goflow2), "-v"], check=True, capture_output=True, text=True
    )
    if "GoFlow2 v2.2.6" not in version.stdout + version.stderr:
        raise SystemExit("FAIL: test requires GoFlow2 v2.2.6")

    baseline, baseline_warnings = run_goflow(args.goflow2, args.pcap)
    mapped, mapped_warnings = run_goflow(args.goflow2, args.pcap, mapping)
    if len(baseline) != len(mapped):
        raise SystemExit("FAIL: flow count changed")
    for old, new in zip(baseline, mapped):
        for key, value in old.items():
            if key == "time_received_ns":
                if type(value) is not type(new.get(key)):
                    raise SystemExit("FAIL: time_received_ns type changed")
            elif new.get(key) != value:
                raise SystemExit(f"FAIL: standard field changed: {key}")

    inbound = [row for row in mapped if row.get("in_if") == 8 and row.get("out_if") == 10]
    if len(inbound) != 403 or any(key not in row for row in inbound for key in NAT_KEYS):
        raise SystemExit("FAIL: inbound NAT coverage mismatch")
    zeros = [row for row in inbound if row["post_napt_src_port"] == 0 or row["post_napt_dst_port"] == 0]
    if len(zeros) != 4 or any(row.get("proto") != "ICMP" for row in zeros):
        raise SystemExit("FAIL: NAT zero behavior mismatch")
    if any("flow_direction" in row for row in mapped):
        raise SystemExit("FAIL: absent mapped IE was not omitted")
    if baseline_warnings != mapped_warnings:
        raise SystemExit("FAIL: mapping changed template warning count")

    mapped_signatures = collections.Counter((
        row.get("src_addr"), row.get("dst_addr"), row.get("src_port"), row.get("dst_port"),
        row.get("in_if"), row.get("out_if"), row.get("bytes"), row.get("packets"),
        row.get("post_nat_src_addr"), row.get("post_nat_dst_addr"),
        row.get("post_napt_src_port"), row.get("post_napt_dst_port"),
    ) for row in mapped)
    reference_signatures = collections.Counter(decode_reference(args.pcap))
    if mapped_signatures != reference_signatures:
        raise SystemExit("FAIL: GoFlow2 NAT values differ from reference decoder")

    stored = validate_flowstore_timeout_flush(mapped)

    print(
        f"PASS flows={len(mapped)} inbound={len(inbound)} "
        f"zero_port_icmp={len(zeros)} template_warnings={mapped_warnings} "
        f"reference_match=yes sqlite_flows={stored}"
    )


if __name__ == "__main__":
    main()
