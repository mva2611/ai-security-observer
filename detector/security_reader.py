#!/usr/bin/env python3
import argparse
import sqlite3
import time
from pathlib import Path

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

def process_batch(flows, security, source_name="flows", batch_size=1000, before_commit=None):
    security.execute("BEGIN IMMEDIATE")
    try:
        row = security.execute(
            "SELECT last_flow_id FROM detector_checkpoints WHERE source_name=?", (source_name,)
        ).fetchone()
        checkpoint = row[0] if row else 0
        ids = [r[0] for r in flows.execute(
            "SELECT id FROM flows WHERE id>? ORDER BY id LIMIT ?", (checkpoint, batch_size)
        )]
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
    args=p.parse_args(argv)
    with open_flows_read_only(args.flows_db) as flows, open_security(args.security_db) as security:
        while True:
            count, checkpoint=process_batch(flows,security,batch_size=args.batch_size)
            print(f"processed={count} checkpoint={checkpoint}",flush=True)
            if args.once: return 0
            time.sleep(args.poll_seconds if count == 0 else 0)

if __name__ == "__main__": raise SystemExit(main())
