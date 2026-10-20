#!/usr/bin/env python3
import argparse
import sqlite3
import time
from pathlib import Path

try:
    from detector.detection import DetectionConfig, process_flows
except ModuleNotFoundError:  # direct execution: python detector/security_reader.py
    from detection import DetectionConfig, process_flows

SCHEMA = Path(__file__).with_name("security_schema.sql")

def open_flows_read_only(path):
    uri = Path(path).resolve().as_uri() + "?mode=ro"
    db = sqlite3.connect(uri, uri=True, timeout=1.0)
    db.execute("PRAGMA query_only=ON")
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='flows'").fetchone() is None:
        db.close(); raise RuntimeError("source table 'flows' not found")
    if "id" not in {r[1] for r in db.execute("PRAGMA table_info(flows)")}:
        db.close(); raise RuntimeError("source flows.id not found")
    return db

def open_security(path):
    db = sqlite3.connect(path, timeout=5.0)
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript(SCHEMA.read_text())
    return db

def process_batch(flows, security, source_name="flows", batch_size=1000,
                  before_commit=None, detection_config=None):
    security.execute("BEGIN IMMEDIATE")
    try:
        row = security.execute(
            "SELECT last_flow_id FROM detector_checkpoints WHERE source_name=?", (source_name,)
        ).fetchone()
        checkpoint = row[0] if row else 0
        cursor = flows.execute(
            "SELECT * FROM flows WHERE id>? ORDER BY id LIMIT ?", (checkpoint, batch_size)
        )
        columns = [item[0] for item in cursor.description]
        rows = [dict(zip(columns, row)) for row in cursor]
        ids = [row["id"] for row in rows]
        previous = checkpoint
        detected_at = time.time_ns()
        for flow_id in ids:
            if flow_id > previous + 1:
                security.execute(
                    "INSERT OR IGNORE INTO source_gaps "
                    "(source_name,missing_after_id,next_present_id,detected_at_ns) VALUES (?,?,?,?)",
                    (source_name, previous, flow_id, detected_at),
                )
            previous = flow_id
        if ids:
            required = {
                "id", "received_at_ns", "flow_start_ns", "flow_end_ns", "exporter_ip",
                "observation_domain_id", "src_ip", "dst_ip", "src_port", "dst_port",
                "protocol", "ingress_if", "egress_if", "src_mac", "bytes", "packets",
            }
            if required <= set(columns):
                process_flows(security, rows, detection_config or DetectionConfig())
            security.execute(
                "INSERT INTO detector_checkpoints(source_name,last_flow_id,updated_at_ns) VALUES(?,?,?) "
                "ON CONFLICT(source_name) DO UPDATE SET last_flow_id=excluded.last_flow_id, "
                "updated_at_ns=excluded.updated_at_ns",
                (source_name, ids[-1], detected_at),
            )
        if before_commit:
            before_commit()
        security.commit()
        return len(ids), (ids[-1] if ids else checkpoint)
    except BaseException:
        security.rollback()
        raise

def main(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument("flows_db"); p.add_argument("security_db")
    p.add_argument("--batch-size",type=int,default=1000)
    p.add_argument("--poll-seconds",type=float,default=5.0)
    p.add_argument("--once",action="store_true")
    p.add_argument("--lan-if",type=int,default=10)
    p.add_argument("--wan-if",type=int,default=8)
    p.add_argument("--r2-learning-flows",type=int,default=1000)
    p.add_argument("--r2-learning-seconds",type=int,default=172800)
    p.add_argument("--r4-window-seconds",type=int,default=600)
    p.add_argument("--r4-destination-threshold",type=int,default=120)
    p.add_argument("--r4-port-threshold",type=int,default=25)
    p.add_argument("--r4-min-flows",type=int,default=20)
    args=p.parse_args(argv)
    with open_flows_read_only(args.flows_db) as flows, open_security(args.security_db) as security:
        while True:
            config = DetectionConfig(
                lan_if=args.lan_if, wan_if=args.wan_if,
                r2_learning_flows=args.r2_learning_flows,
                r2_learning_seconds=args.r2_learning_seconds,
                r4_window_seconds=args.r4_window_seconds,
                r4_destination_threshold=args.r4_destination_threshold,
                r4_port_threshold=args.r4_port_threshold,
                r4_min_flows=args.r4_min_flows,
            )
            count, checkpoint=process_batch(
                flows,security,batch_size=args.batch_size,detection_config=config
            )
            print(f"processed={count} checkpoint={checkpoint}",flush=True)
            if args.once: return 0
            time.sleep(args.poll_seconds if count == 0 else 0)

if __name__ == "__main__": raise SystemExit(main())
