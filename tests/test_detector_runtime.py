import sqlite3
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from detector.bootstrap import initialize_checkpoint
from detector.healthcheck import inspect_health
from detector.security_reader import (
    open_flows_read_only, open_security, process_batch,
    run_canonical_cleanup_cycle, should_log_progress,
)


class DetectorRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.flows_path = root / "flows.db"
        self.security_path = root / "security.db"
        with sqlite3.connect(self.flows_path) as db:
            db.execute("CREATE TABLE flows(id INTEGER PRIMARY KEY, received_at_ns INTEGER)")
            db.executemany("INSERT INTO flows VALUES(?,?)", [(1, 1), (2, 2), (4, 4)])
        self.flows = open_flows_read_only(self.flows_path)
        self.security = open_security(self.security_path)

    def tearDown(self):
        self.flows.close()
        self.security.close()
        self.tmp.cleanup()

    def test_bootstrap_starts_at_current_max_and_is_idempotent(self):
        self.assertEqual(initialize_checkpoint(self.flows, self.security), (4, True))
        with sqlite3.connect(self.flows_path) as db:
            db.execute("INSERT INTO flows VALUES(5,5)")
        self.assertEqual(initialize_checkpoint(self.flows, self.security), (4, False))
        self.assertEqual(process_batch(self.flows, self.security), (1, 5))

    def test_bootstrap_refuses_existing_evidence_without_checkpoint(self):
        self.security.execute(
            "INSERT INTO canonical_flows VALUES(?,?,?,?,?,?)",
            ("sig", 1, "unknown", "outbound", 1, 1),
        )
        self.security.commit()
        with self.assertRaises(RuntimeError):
            initialize_checkpoint(self.flows, self.security)

    def test_health_distinguishes_idle_processing_stale_and_read_error(self):
        initialize_checkpoint(self.flows, self.security)
        row = self.security.execute(
            "SELECT last_successful_poll_ns FROM detector_runtime_health"
        ).fetchone()[0]
        idle = inspect_health(self.flows_path, self.security_path, now_ns=row + 1_000_000_000)
        self.assertEqual(idle["state"], "healthy_idle")
        with sqlite3.connect(self.flows_path) as db:
            db.execute("INSERT INTO flows VALUES(5,5)")
        processing = inspect_health(
            self.flows_path, self.security_path, now_ns=row + 2_000_000_000
        )
        self.assertEqual(processing["state"], "healthy_processing")
        stale = inspect_health(
            self.flows_path, self.security_path, max_poll_age=90,
            now_ns=row + 91_000_000_000,
        )
        self.assertEqual(stale["state"], "unhealthy_reader_stale")
        with self.assertRaises(sqlite3.OperationalError):
            inspect_health(self.flows_path.with_name("missing.db"), self.security_path)

    def test_existing_schema_migrates_processed_timestamp_and_index(self):
        self.security.close()
        self.security_path.unlink()
        with sqlite3.connect(self.security_path) as db:
            db.execute(
                "CREATE TABLE canonical_flows(flow_signature TEXT PRIMARY KEY,"
                "flow_id INTEGER,device_id TEXT,direction TEXT,observed_at_ns INTEGER)"
            )
            db.execute("INSERT INTO canonical_flows VALUES('old',1,'unknown','outbound',1)")
        self.security = open_security(self.security_path)
        columns = {
            row[1] for row in self.security.execute("PRAGMA table_info(canonical_flows)")
        }
        self.assertIn("processed_at_ns", columns)
        self.assertGreater(
            self.security.execute(
                "SELECT processed_at_ns FROM canonical_flows WHERE flow_signature='old'"
            ).fetchone()[0], 0,
        )
        indexes = {
            row[1] for row in self.security.execute("PRAGMA index_list(canonical_flows)")
        }
        self.assertIn("idx_canonical_flows_processed_at", indexes)

    def test_cleanup_is_hourly_bounded_and_transactional(self):
        now = 10 * 24 * 60 * 60 * 1_000_000_000
        self.security.executemany(
            "INSERT INTO canonical_flows VALUES(?,?,?,?,?,?)",
            [(f"old-{i}", i, "unknown", "outbound", 1, 1) for i in range(10_005)],
        )
        self.security.commit()
        self.assertEqual(
            run_canonical_cleanup_cycle(self.security, now, max_chunks=1), 10_000
        )
        self.assertIsNone(
            run_canonical_cleanup_cycle(self.security, now + 1_000_000_000)
        )
        self.assertEqual(
            self.security.execute("SELECT count(*) FROM canonical_flows").fetchone()[0], 5
        )
        self.assertEqual(
            run_canonical_cleanup_cycle(
                self.security, now + 3600 * 1_000_000_000, max_chunks=1
            ), 5
        )
        self.assertEqual(
            self.security.execute("SELECT count(*) FROM canonical_flows").fetchone()[0], 0
        )

    def test_hourly_cycle_uses_multiple_bounded_transactions(self):
        now = 10 * 24 * 60 * 60 * 1_000_000_000
        self.security.executemany(
            "INSERT INTO canonical_flows VALUES(?,?,?,?,?,?)",
            [(f"old-{i}", i, "unknown", "outbound", 1, 1) for i in range(25_000)],
        )
        self.security.commit()
        self.assertEqual(run_canonical_cleanup_cycle(self.security, now), 25_000)
        self.assertEqual(
            self.security.execute("SELECT count(*) FROM canonical_flows").fetchone()[0], 0
        )

    def test_restart_after_cleanup_uses_committed_maintenance_state(self):
        now = 10 * 24 * 60 * 60 * 1_000_000_000
        self.security.execute(
            "INSERT INTO canonical_flows VALUES('old',1,'unknown','outbound',1,1)"
        )
        self.security.commit()

        def interrupt_before_commit():
            raise RuntimeError("simulated restart")

        with self.assertRaises(RuntimeError):
            run_canonical_cleanup_cycle(
                self.security, now, before_chunk_commit=interrupt_before_commit,
            )
        self.assertEqual(
            self.security.execute("SELECT count(*) FROM canonical_flows").fetchone()[0], 1
        )
        self.assertEqual(
            self.security.execute(
                "SELECT last_run_ns,last_deleted_count FROM detector_maintenance"
            ).fetchone(), (now, 0),
        )
        self.security.close()
        self.security = open_security(self.security_path)
        self.assertIsNone(
            run_canonical_cleanup_cycle(self.security, now + 1_000_000_000)
        )
        self.assertEqual(
            run_canonical_cleanup_cycle(
                self.security, now + 3600 * 1_000_000_000
            ), 1
        )
        self.assertEqual(
            self.security.execute("SELECT count(*) FROM canonical_flows").fetchone()[0], 0
        )
        self.assertEqual(
            self.security.execute(
                "SELECT last_deleted_count FROM detector_maintenance"
            ).fetchone()[0], 1
        )

    def test_cleanup_stops_after_committing_current_chunk(self):
        now = 10 * 24 * 60 * 60 * 1_000_000_000
        self.security.executemany(
            "INSERT INTO canonical_flows VALUES(?,?,?,?,?,?)",
            [(f"old-{i}", i, "unknown", "outbound", 1, 1) for i in range(20_005)],
        )
        self.security.commit()
        stop = False

        def request_stop():
            nonlocal stop
            stop = True

        self.assertEqual(
            run_canonical_cleanup_cycle(
                self.security, now, before_chunk_commit=request_stop,
                stop_requested=lambda: stop,
            ),
            10_000,
        )
        self.assertEqual(
            self.security.execute("SELECT count(*) FROM canonical_flows").fetchone()[0],
            10_005,
        )

    def test_sigterm_exits_zero_and_restart_resumes_checkpoint(self):
        initialize_checkpoint(self.flows, self.security)
        self.flows.close()
        self.security.close()
        with sqlite3.connect(self.flows_path) as db:
            db.execute("INSERT INTO flows VALUES(5,5)")

        def start_and_wait(expected_checkpoint):
            process = subprocess.Popen(
                [
                    sys.executable, "-m", "detector.security_reader",
                    str(self.flows_path), str(self.security_path),
                    "--poll-seconds", "60",
                ],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    with sqlite3.connect(self.security_path) as db:
                        row = db.execute(
                            "SELECT last_flow_id FROM detector_checkpoints "
                            "WHERE source_name='flows'"
                        ).fetchone()
                    if row and row[0] == expected_checkpoint:
                        return process
                except sqlite3.OperationalError:
                    pass
                time.sleep(0.02)
            process.kill()
            stdout, stderr = process.communicate()
            self.fail(f"checkpoint did not reach {expected_checkpoint}: {stdout} {stderr}")

        first = start_and_wait(5)
        first.send_signal(signal.SIGTERM)
        stdout, stderr = first.communicate(timeout=5)
        self.assertEqual(first.returncode, 0, stderr)
        self.assertIn("shutdown=signal checkpoint=5", stdout)

        with sqlite3.connect(self.flows_path) as db:
            db.execute("INSERT INTO flows VALUES(6,6)")
        second = start_and_wait(6)
        second.send_signal(signal.SIGTERM)
        stdout, stderr = second.communicate(timeout=5)
        self.assertEqual(second.returncode, 0, stderr)
        self.assertIn("shutdown=signal checkpoint=6", stdout)
        with sqlite3.connect(self.security_path) as db:
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(
                db.execute(
                    "SELECT last_flow_id FROM detector_checkpoints WHERE source_name='flows'"
                ).fetchone()[0],
                6,
            )

        self.flows = open_flows_read_only(self.flows_path)
        self.security = open_security(self.security_path)

    def test_idle_progress_logging_is_heartbeat_limited(self):
        self.assertTrue(should_log_progress(0, None, 100, 300))
        self.assertFalse(should_log_progress(0, 100, 399, 300))
        self.assertTrue(should_log_progress(0, 100, 400, 300))
        self.assertTrue(should_log_progress(1, 399, 400, 300))


if __name__ == "__main__":
    unittest.main()
