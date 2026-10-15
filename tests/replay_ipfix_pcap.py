#!/usr/bin/env python3
"""Replay IPv4/UDP payloads from an SLL2 PCAP to a loopback UDP receiver."""

import argparse
import socket
import struct
import time
from pathlib import Path


def payloads(path: Path):
    raw = path.read_bytes()
    if raw[:4] != b"\xd4\xc3\xb2\xa1":
        raise ValueError("expected little-endian microsecond PCAP")
    if struct.unpack_from("<I", raw, 20)[0] != 276:
        raise ValueError("expected SLL2 PCAP")
    pos = 24
    while pos + 16 <= len(raw):
        _, _, caplen, _ = struct.unpack_from("<IIII", raw, pos)
        pos += 16
        packet = raw[pos : pos + caplen]
        pos += caplen
        if len(packet) < 48 or struct.unpack_from("!H", packet, 0)[0] != 0x0800:
            continue
        ip = packet[20:]
        ihl = (ip[0] & 15) * 4
        if ip[9] != 17 or len(ip) < ihl + 8:
            continue
        total = struct.unpack_from("!H", ip, 2)[0]
        _, _, udp_len, _ = struct.unpack_from("!HHHH", ip, ihl)
        data = ip[ihl + 8 : min(total, ihl + udp_len)]
        if len(data) >= 2 and struct.unpack_from("!H", data, 0)[0] == 10:
            yield data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--delay", type=float, default=0.01)
    args = parser.parse_args()
    sent = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for payload in payloads(args.pcap):
            sock.sendto(payload, ("127.0.0.1", args.port))
            sent += 1
            time.sleep(args.delay)
    print(f"replayed={sent}")


if __name__ == "__main__":
    main()
