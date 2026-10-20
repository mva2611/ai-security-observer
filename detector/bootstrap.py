#!/usr/bin/env python3
import argparse
import time

from detector.security_reader import open_flows_read_only, open_security


def initialize_checkpoint(flows, security, source_name="flows"):
    """Create the first checkpoint at the current source maximum.

    Existing checkpoints are never moved.  Checkpoint creation and its health
    record commit atomically in security.db.
    """
    security.execute("BEGIN IMMEDIATE")
    try:
        existing = security.execute(
            "SELECT last_flow_id FROM detector_checkpoints WHERE source_name=?",
            (source_name,),
        ).fetchone()
        if existing is not None:
            security.commit()
            return existing[0], False
        evidence_count = sum(
            security.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in (
                "canonical_flows", "communication_profile_changes", "security_events"
            )
        )
        if evidence_count:
            raise RuntimeError("refusing to initialize checkpoint over existing detector evidence")
        source_max = flows.execute("SELECT coalesce(max(id),0) FROM flows").fetchone()[0]
        now_ns = time.time_ns()
        security.execute(
            "INSERT INTO detector_checkpoints(source_name,last_flow_id,updated_at_ns) "
            "VALUES(?,?,?)", (source_name, source_max, now_ns),
        )
        security.execute(
            "INSERT INTO detector_runtime_health "
            "(source_name,last_successful_poll_ns,last_progress_ns,last_batch_count,last_checkpoint) "
            "VALUES(?,?,?,?,?)",
            (source_name, now_ns, now_ns, 0, source_max),
        )
        security.commit()
        return source_max, True
    except BaseException:
        security.rollback()
        raise


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("flows_db")
    parser.add_argument("security_db")
    parser.add_argument("--source-name", default="flows")
    args = parser.parse_args(argv)
    with open_flows_read_only(args.flows_db) as flows, open_security(args.security_db) as security:
        checkpoint, created = initialize_checkpoint(flows, security, args.source_name)
    print(f"checkpoint={checkpoint} initialized={str(created).lower()}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
