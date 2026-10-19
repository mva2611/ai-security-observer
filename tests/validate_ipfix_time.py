#!/usr/bin/env python3
"""Offline GoFlow2 v2.2.6 validation for RouterOS IPFIX time mappings."""

import argparse
import importlib.util
import json
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPORT_TIME = int(time.time())
SYSTEM_INIT_MS = (EXPORT_TIME - 100) * 1000
EXPECTED_START_NS = (EXPORT_TIME - 2) * 1_000_000_000
EXPECTED_END_NS = (EXPORT_TIME - 1) * 1_000_000_000


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def ipfix_packet(export_time, sequence, domain, sets):
    body = b"".join(sets)
    return struct.pack("!HHIII", 10, 16 + len(body), export_time, sequence, domain) + body


def template_set(template_id, fields):
    record = struct.pack("!HH", template_id, len(fields))
    record += b"".join(struct.pack("!HH", ie, length) for ie, length in fields)
    return struct.pack("!HH", 2, 4 + len(record)) + record


def data_set(template_id, values):
    body = b"".join(values)
    return struct.pack("!HH", template_id, 4 + len(body)) + body


def records():
    relative_fields = [(8, 4), (12, 4), (4, 1), (22, 4), (21, 4), (160, 8)]
    relative_values = [
        socket.inet_aton("192.0.2.1"),
        socket.inet_aton("198.51.100.1"),
        struct.pack("!B", 6),
        struct.pack("!I", 98_000),
        struct.pack("!I", 99_000),
        struct.pack("!Q", SYSTEM_INIT_MS),
    ]
    absolute_fields = [(8, 4), (12, 4), (4, 1), (152, 8), (153, 8)]
    absolute_values = [
        socket.inet_aton("192.0.2.2"),
        socket.inet_aton("198.51.100.2"),
        struct.pack("!B", 17),
        struct.pack("!Q", EXPECTED_START_NS // 1_000_000),
        struct.pack("!Q", EXPECTED_END_NS // 1_000_000),
    ]
    return [
        ipfix_packet(EXPORT_TIME, 1, 42, [template_set(300, relative_fields)]),
        ipfix_packet(EXPORT_TIME, 2, 42, [data_set(300, relative_values)]),
        ipfix_packet(EXPORT_TIME, 3, 42, [template_set(301, absolute_fields)]),
        ipfix_packet(EXPORT_TIME, 4, 42, [data_set(301, absolute_values)]),
    ]


def run_goflow(binary, mapping=None):
    port = free_port()
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "flows.jsonl"
        command = [
            str(binary),
            f"-listen=netflow://127.0.0.1:{port}?count=1&workers=1&blocking=true",
            "-produce=sample",
            "-format=json",
            "-transport=file",
            f"-transport.file={output}",
            "-addr=",
        ]
        if mapping:
            command.append(f"-mapping={mapping}")
        process = subprocess.Popen(command, stderr=subprocess.PIPE, text=True)
        try:
            time.sleep(0.5)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                for packet in records():
                    sock.sendto(packet, ("127.0.0.1", port))
                    time.sleep(0.05)
            time.sleep(0.5)
        finally:
            process.terminate()
            _, stderr = process.communicate(timeout=5)
        if "error" in stderr.lower():
            raise SystemExit(f"FAIL: GoFlow2 error: {stderr}")
        return [json.loads(line) for line in output.read_text().splitlines() if line]


def load_flowstore():
    spec = importlib.util.spec_from_file_location(
        "flowstore_time_validation", ROOT / "collector/flowstore.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--goflow2", type=Path, required=True)
    args = parser.parse_args()
    version = subprocess.run(
        [str(args.goflow2), "-v"], check=True, capture_output=True, text=True
    )
    if "GoFlow2 v2.2.6" not in version.stdout + version.stderr:
        raise SystemExit("FAIL: test requires GoFlow2 v2.2.6")

    baseline = run_goflow(args.goflow2)
    mapped = run_goflow(args.goflow2, ROOT / "collector/goflow2-mapping.yaml")
    if len(baseline) != 2 or len(mapped) != 2:
        raise SystemExit(f"FAIL: expected two records, got {len(baseline)}/{len(mapped)}")

    added = {
        "flow_start_sys_uptime_ms",
        "flow_end_sys_uptime_ms",
        "system_init_time_ms",
        "native_flow_start_marker",
        "native_flow_end_marker",
        "flow_start_delta_marker",
        "flow_end_delta_marker",
    }
    preexisting_mapping_fields = {
        "flow_direction",
        "bi_flow_direction",
        "ingress_vrf_id",
        "egress_vrf_id",
        "icmp_name",
        "csum",
    }
    for old, new in zip(baseline, mapped):
        for key, value in old.items():
            if key == "time_received_ns":
                if type(value) is not type(new.get(key)):
                    raise SystemExit("FAIL: time_received_ns type changed")
            elif new.get(key) != value:
                raise SystemExit(
                    f"FAIL: standard GoFlow2 JSON field changed: {key}"
                )
        unexpected = set(new) - set(old) - added - preexisting_mapping_fields
        if unexpected:
            raise SystemExit(f"FAIL: unexpected JSON fields: {sorted(unexpected)}")

    relative, absolute = mapped
    expected_relative = {
        "flow_start_sys_uptime_ms": 98_000,
        "flow_end_sys_uptime_ms": 99_000,
        "system_init_time_ms": SYSTEM_INIT_MS,
    }
    for key, value in expected_relative.items():
        if relative.get(key) != value:
            raise SystemExit(f"FAIL: {key}={relative.get(key)!r}, expected {value}")
    if "native_flow_start_marker" in relative or "native_flow_end_marker" in relative:
        raise SystemExit("FAIL: relative record contains absolute markers")
    if "native_flow_start_marker" not in absolute or "native_flow_end_marker" not in absolute:
        raise SystemExit("FAIL: absolute record markers missing")

    flowstore = load_flowstore()
    normalized_relative = flowstore.normalize(relative)
    normalized_absolute = flowstore.normalize(absolute)
    if (
        normalized_relative["flow_start_ns"] != EXPECTED_START_NS
        or normalized_relative["flow_end_ns"] != EXPECTED_END_NS
        or normalized_relative["flow_time_source"] != "reconstructed"
    ):
        raise SystemExit(f"FAIL: relative reconstruction: {normalized_relative}")
    if normalized_absolute["flow_time_source"] != "absolute":
        raise SystemExit(f"FAIL: absolute precedence: {normalized_absolute}")

    print("PASS records=2 mapping=verified standard_fields=unchanged "
          "relative=reconstructed absolute=preferred")


if __name__ == "__main__":
    main()
