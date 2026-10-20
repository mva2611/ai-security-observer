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
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript(SCHEMA.read_text())
    columns = {row[1] for row in db.execute("PRAGMA table_info(canonical_flows)")}
    if "processed_at_ns" not in columns:
        migration_ns = time.time_ns()
        db.execute("BEGIN IMMEDIATE")
        try:
            db.execute("ALTER TABLE canonical_flows ADD COLUMN processed_at_ns INTEGER")
            db.execute(
                "UPDATE canonical_flows SET processed_at_ns=? WHERE processed_at_ns IS NULL",
                (migration_ns,),
            )
            db.commit()
        except BaseException:
            db.rollback()
            raise
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_canonical_flows_processed_at "
        "ON canonical_flows(processed_at_ns)"
    )
    db.commit()
    return db


def _cleanup_canonical_chunk(security, cutoff_ns, limit):
    return security.execute(
        "DELETE FROM canonical_flows WHERE flow_signature IN ("
        "SELECT flow_signature FROM canonical_flows WHERE processed_at_ns<? "
        "ORDER BY processed_at_ns LIMIT ?)",
        (cutoff_ns, limit),
    ).rowcount


def run_canonical_cleanup_cycle(
        security, now_ns, retention_seconds=7 * 24 * 60 * 60,
        interval_seconds=60 * 60, limit=10_000, max_chunks=100,
        before_chunk_commit=None):
    if (retention_seconds <= 0 or interval_seconds <= 0
            or not 1 <= limit <= 10_000 or max_chunks <= 0):
        raise ValueError("invalid canonical-flow retention settings")
    task = "canonical_flows_retention"
    interval_ns = interval_seconds * 1_000_000_000
    security.execute("BEGIN IMMEDIATE")
    try:
        previous = security.execute(
            "SELECT last_run_ns FROM detector_maintenance WHERE task_name=?", (task,)
        ).fetchone()
        if previous is not None and now_ns - previous[0] < interval_ns:
            security.rollback()
            return None
        security.execute(
            "INSERT INTO detector_maintenance(task_name,last_run_ns,last_deleted_count) "
            "VALUES(?,?,0) ON CONFLICT(task_name) DO UPDATE SET "
            "last_run_ns=excluded.last_run_ns,last_deleted_count=0",
            (task, now_ns),
        )
        security.commit()
    except BaseException:
        security.rollback()
        raise

    cutoff_ns = now_ns - retention_seconds * 1_000_000_000
    total_deleted = 0
    for _ in range(max_chunks):
        security.execute("BEGIN IMMEDIATE")
        try:
            deleted = _cleanup_canonical_chunk(security, cutoff_ns, limit)
            total_deleted += deleted
            security.execute(
                "UPDATE detector_maintenance SET last_deleted_count=? WHERE task_name=?",
                (total_deleted, task),
            )
            if before_chunk_commit:
                before_chunk_commit()
            security.commit()
        except BaseException:
            security.rollback()
            raise
        if deleted < limit:
            break
    return total_deleted


def should_log_progress(count, last_log_at, now_monotonic, heartbeat_seconds):
    return bool(
        count or last_log_at is None
        or now_monotonic - last_log_at >= heartbeat_seconds
    )


def process_batch(flows, security, source_name="flows", batch_size=1000,
                  before_commit=None, detection_config=None, now_ns=None):
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
        detected_at = time.time_ns() if now_ns is None else now_ns
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
                process_flows(
                    security, rows, detection_config or DetectionConfig(), detected_at
                )
            security.execute(
                "INSERT INTO detector_checkpoints(source_name,last_flow_id,updated_at_ns) VALUES(?,?,?) "
                "ON CONFLICT(source_name) DO UPDATE SET last_flow_id=excluded.last_flow_id, "
                "updated_at_ns=excluded.updated_at_ns",
                (source_name, ids[-1], detected_at),
            )
        final_checkpoint = ids[-1] if ids else checkpoint
        previous_health = security.execute(
            "SELECT last_progress_ns FROM detector_runtime_health WHERE source_name=?",
            (source_name,),
        ).fetchone()
        last_progress = (
            detected_at if ids or previous_health is None else previous_health[0]
        )
        security.execute(
            "INSERT INTO detector_runtime_health "
            "(source_name,last_successful_poll_ns,last_progress_ns,last_batch_count,last_checkpoint) "
            "VALUES(?,?,?,?,?) ON CONFLICT(source_name) DO UPDATE SET "
            "last_successful_poll_ns=excluded.last_successful_poll_ns,"
            "last_progress_ns=excluded.last_progress_ns,"
            "last_batch_count=excluded.last_batch_count,"
            "last_checkpoint=excluded.last_checkpoint",
            (source_name, detected_at, last_progress, len(ids), final_checkpoint),
        )
        if before_commit:
            before_commit()
        security.commit()
        return len(ids), final_checkpoint
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
    p.add_argument("--canonical-retention-seconds",type=int,default=604800)
    p.add_argument("--cleanup-interval-seconds",type=int,default=3600)
    p.add_argument("--cleanup-limit",type=int,default=10000)
    p.add_argument("--cleanup-max-chunks",type=int,default=100)
    p.add_argument("--heartbeat-seconds",type=int,default=300)
    args=p.parse_args(argv)
    with open_flows_read_only(args.flows_db) as flows, open_security(args.security_db) as security:
        last_log_at = None
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
                flows,security,batch_size=args.batch_size,detection_config=config,
            )
            deleted = run_canonical_cleanup_cycle(
                security, time.time_ns(), args.canonical_retention_seconds,
                args.cleanup_interval_seconds, args.cleanup_limit,
                args.cleanup_max_chunks,
            )
            if deleted:
                print(f"maintenance=canonical_flows deleted={deleted}", flush=True)
            log_now = time.monotonic()
            if should_log_progress(count, last_log_at, log_now, args.heartbeat_seconds):
                print(f"processed={count} checkpoint={checkpoint}",flush=True)
                last_log_at = log_now
            if args.once: return 0
            time.sleep(args.poll_seconds if count == 0 else 0)

if __name__ == "__main__": raise SystemExit(main())
