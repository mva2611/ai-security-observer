#!/usr/bin/env python3
import argparse
import json
import sqlite3
import time
from pathlib import Path


def _read_only(path):
    return sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True, timeout=2)


def inspect_health(flows_db, security_db, source_name="flows", max_poll_age=90, now_ns=None):
    now_ns = now_ns if now_ns is not None else time.time_ns()
    with _read_only(flows_db) as flows:
        flows.execute("PRAGMA query_only=ON")
        source_max = flows.execute("SELECT coalesce(max(id),0) FROM flows").fetchone()[0]
    with _read_only(security_db) as security:
        security.execute("PRAGMA query_only=ON")
        checkpoint_row = security.execute(
            "SELECT last_flow_id FROM detector_checkpoints WHERE source_name=?",
            (source_name,),
        ).fetchone()
        health_row = security.execute(
            "SELECT last_successful_poll_ns,last_progress_ns,last_batch_count,last_checkpoint "
            "FROM detector_runtime_health WHERE source_name=?", (source_name,),
        ).fetchone()
    if checkpoint_row is None or health_row is None:
        raise RuntimeError("detector checkpoint or runtime health record is missing")
    checkpoint = checkpoint_row[0]
    poll_age = max(0, (now_ns - health_row[0]) / 1_000_000_000)
    progress_age = max(0, (now_ns - health_row[1]) / 1_000_000_000)
    backlog = max(0, source_max - checkpoint)
    if poll_age > max_poll_age:
        state = "unhealthy_reader_stale"
        healthy = False
    elif backlog:
        state = "healthy_processing"
        healthy = True
    else:
        state = "healthy_idle"
        healthy = True
    return {
        "healthy": healthy, "state": state, "source_max_id": source_max,
        "checkpoint": checkpoint, "backlog": backlog,
        "last_batch_count": health_row[2], "poll_age_seconds": round(poll_age, 3),
        "no_checkpoint_progress_seconds": round(progress_age, 3),
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("flows_db")
    parser.add_argument("security_db")
    parser.add_argument("--source-name", default="flows")
    parser.add_argument("--max-poll-age", type=int, default=90)
    args = parser.parse_args(argv)
    try:
        status = inspect_health(
            args.flows_db, args.security_db, args.source_name, args.max_poll_age
        )
    except Exception as exc:
        print(json.dumps({"healthy": False, "state": "read_error", "error": str(exc)}))
        return 1
    print(json.dumps(status, sort_keys=True))
    return 0 if status["healthy"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
