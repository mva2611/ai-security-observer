#!/usr/bin/env python3

import importlib.util
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL_COLLECTOR_COMMIT = "58e254eac95740ebac5cf0c2e65e68e3d79bbd52"
SPEC = importlib.util.spec_from_file_location("flowstore", ROOT / "collector/flowstore.py")
FLOWSTORE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(FLOWSTORE)


class FlowStoreNatTest(unittest.TestCase):
    def base_record(self):
        return {
            "type": "IPFIX",
            "time_received_ns": 1,
            "sampler_address": "127.0.0.1",
            "src_addr": "198.51.100.1",
            "dst_addr": "10.0.0.100",
            "proto": "ICMP",
        }

    def timed_record(self):
        record = self.base_record()
        record["time_received_ns"] = 1_700_000_100_000_000_000
        record["time_flow_start_ns"] = 1_700_000_099_000_000_000
        record["time_flow_end_ns"] = 1_700_000_099_500_000_000
        return record

    def legacy_schema(self):
        schema = (ROOT / "collector/schema.sql").read_text()
        schema = schema.replace(
            "    flow_time_source      TEXT NOT NULL DEFAULT 'export_fallback'\n"
            "                          CHECK (flow_time_source IN\n"
            "                                 ('absolute', 'reconstructed', 'export_fallback')),\n",
            "",
        )
        for column in (
            "    post_nat_src_ip       TEXT,\n",
            "    post_nat_dst_ip       TEXT,\n",
            "    post_napt_src_port    INTEGER,\n",
            "    post_napt_dst_port    INTEGER\n",
        ):
            schema = schema.replace(column, "")
        return schema.replace(
            "    observation_domain_id INTEGER,\n\n);",
            "    observation_domain_id INTEGER\n);",
        )

    def test_missing_nat_keys_become_none(self):
        flow = FLOWSTORE.normalize(self.base_record())
        self.assertEqual(flow["schema_version"], 1)
        self.assertIsNone(flow["post_nat_src_ip"])
        self.assertIsNone(flow["post_nat_dst_ip"])
        self.assertIsNone(flow["post_napt_src_port"])
        self.assertIsNone(flow["post_napt_dst_port"])

    def test_numeric_zero_is_preserved(self):
        record = self.base_record()
        record.update({
            "post_nat_src_addr": "198.51.100.1",
            "post_nat_dst_addr": "192.168.1.125",
            "post_napt_src_port": 0,
            "post_napt_dst_port": 0,
        })
        flow = FLOWSTORE.normalize(record)
        self.assertEqual(flow["post_napt_src_port"], 0)
        self.assertEqual(flow["post_napt_dst_port"], 0)

    def test_export_fallback_is_explicit(self):
        flow = FLOWSTORE.normalize(self.timed_record())
        self.assertEqual(flow["flow_start_ns"], 1_700_000_099_000_000_000)
        self.assertEqual(flow["flow_end_ns"], 1_700_000_099_500_000_000)
        self.assertEqual(flow["flow_time_source"], "export_fallback")

    def test_native_absolute_times_take_precedence(self):
        record = self.timed_record()
        record.update({
            "native_flow_start_marker": 1,
            "native_flow_end_marker": 1,
            "system_init_time_ms": 1_699_999_000_000,
            "flow_start_sys_uptime_ms": 100,
            "flow_end_sys_uptime_ms": 200,
        })
        flow = FLOWSTORE.normalize(record)
        self.assertEqual(flow["flow_start_ns"], 1_700_000_099_000_000_000)
        self.assertEqual(flow["flow_end_ns"], 1_700_000_099_500_000_000)
        self.assertEqual(flow["flow_time_source"], "absolute")

    def test_routeros_relative_times_are_reconstructed(self):
        record = self.timed_record()
        record.update({
            "system_init_time_ms": 1_700_000_000_000,
            "flow_start_sys_uptime_ms": 98_000,
            "flow_end_sys_uptime_ms": 99_000,
        })
        flow = FLOWSTORE.normalize(record)
        self.assertEqual(flow["flow_start_ns"], 1_700_000_098_000_000_000)
        self.assertEqual(flow["flow_end_ns"], 1_700_000_099_000_000_000)
        self.assertEqual(flow["flow_time_source"], "reconstructed")

    def test_goflow_delta_times_are_reconstructed(self):
        record = self.timed_record()
        record.update({
            "flow_start_delta_marker": 1,
            "flow_end_delta_marker": 1,
        })
        flow = FLOWSTORE.normalize(record)
        self.assertEqual(flow["flow_time_source"], "reconstructed")

    def test_incomplete_relative_times_fall_back(self):
        record = self.timed_record()
        record.update({
            "system_init_time_ms": 1_700_000_000_000,
            "flow_start_sys_uptime_ms": 98_000,
        })
        flow = FLOWSTORE.normalize(record)
        self.assertEqual(flow["flow_time_source"], "export_fallback")

    def test_reversed_relative_interval_falls_back(self):
        record = self.timed_record()
        record.update({
            "system_init_time_ms": 1_700_000_000_000,
            "flow_start_sys_uptime_ms": 99_000,
            "flow_end_sys_uptime_ms": 98_000,
        })
        flow = FLOWSTORE.normalize(record)
        self.assertEqual(flow["flow_time_source"], "export_fallback")

    def test_implausibly_old_relative_interval_falls_back(self):
        record = self.timed_record()
        record.update({
            "system_init_time_ms": 1_699_000_000_000,
            "flow_start_sys_uptime_ms": 1_000,
            "flow_end_sys_uptime_ms": 2_000,
        })
        flow = FLOWSTORE.normalize(record)
        self.assertEqual(flow["flow_time_source"], "export_fallback")

    def test_invalid_goflow_fallback_uses_receive_time_second(self):
        record = self.timed_record()
        record["time_flow_start_ns"] = record["time_received_ns"] + 20
        record["time_flow_end_ns"] = record["time_received_ns"] - 20
        flow = FLOWSTORE.normalize(record)
        expected = (
            record["time_received_ns"] // 1_000_000_000
        ) * 1_000_000_000
        self.assertEqual(flow["flow_start_ns"], expected)
        self.assertEqual(flow["flow_end_ns"], expected)
        self.assertEqual(flow["flow_time_source"], "export_fallback")

    def test_non_time_attributes_are_unchanged_by_reconstruction(self):
        record = self.timed_record()
        record.update({
            "src_port": 443,
            "dst_port": 54321,
            "bytes": 1234,
            "packets": 12,
            "post_nat_dst_addr": "192.168.1.10",
            "system_init_time_ms": 1_700_000_000_000,
            "flow_start_sys_uptime_ms": 98_000,
            "flow_end_sys_uptime_ms": 99_000,
        })
        flow = FLOWSTORE.normalize(record)
        self.assertEqual(flow["src_ip"], record["src_addr"])
        self.assertEqual(flow["dst_ip"], record["dst_addr"])
        self.assertEqual(flow["src_port"], 443)
        self.assertEqual(flow["dst_port"], 54321)
        self.assertEqual(flow["bytes"], 1234)
        self.assertEqual(flow["packets"], 12)
        self.assertEqual(flow["post_nat_dst_ip"], "192.168.1.10")

    def test_existing_rows_and_schema_version_remain_compatible_after_migration(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            database = directory / "flows.db"
            backup = directory / "flows.before-nat.db"
            schema = self.legacy_schema()
            with sqlite3.connect(database) as db:
                db.executescript(schema)
                old = FLOWSTORE.normalize(self.base_record())
                old["schema_version"] = 1
                old_columns = tuple(
                    column for column in FLOWSTORE.COLUMNS
                    if column not in {
                        "flow_time_source",
                        "post_nat_src_ip",
                        "post_nat_dst_ip",
                        "post_napt_src_port",
                        "post_napt_dst_port",
                    }
                )
                db.execute(
                    f"INSERT INTO flows ({', '.join(old_columns)}) VALUES "
                    f"({', '.join('?' for _ in old_columns)})",
                    tuple(old[column] for column in old_columns),
                )

            result = subprocess.run(
                [sys.executable, str(ROOT / "collector/migrate_flowstore_nat.py"), str(database), str(backup)],
                check=True,
                text=True,
                capture_output=True,
            )
            self.assertIn("migration complete", result.stdout)
            with sqlite3.connect(database) as db:
                FLOWSTORE.validate_database(db)
                row = db.execute(
                    "SELECT schema_version, flow_time_source, "
                    "post_nat_src_ip, post_napt_src_port FROM flows"
                ).fetchone()
                self.assertEqual(row, (1, "export_fallback", None, None))
                self.assertEqual(db.execute("PRAGMA integrity_check").fetchone(), ("ok",))
            with sqlite3.connect(backup) as db:
                self.assertEqual(db.execute("PRAGMA integrity_check").fetchone(), ("ok",))

    def test_original_production_flowstore_writes_after_nat_ingest(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            database = directory / "flows.db"
            backup = directory / "flows.before-nat.db"
            original_flowstore = directory / "flowstore-0.2.py"

            original_schema = subprocess.run(
                [
                    "git", "-C", str(ROOT), "show",
                    f"{ORIGINAL_COLLECTOR_COMMIT}:collector/schema.sql",
                ],
                check=True,
                text=True,
                capture_output=True,
            ).stdout
            original_source = subprocess.run(
                [
                    "git", "-C", str(ROOT), "show",
                    f"{ORIGINAL_COLLECTOR_COMMIT}:collector/flowstore.py",
                ],
                check=True,
                text=True,
                capture_output=True,
            ).stdout
            original_flowstore.write_text(original_source)

            with sqlite3.connect(database) as db:
                db.executescript(original_schema)

            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "collector/migrate_flowstore_nat.py"),
                    str(database),
                    str(backup),
                ],
                check=True,
                text=True,
                capture_output=True,
            )

            nat_record = self.base_record()
            nat_record.update({
                "post_nat_src_addr": "198.51.100.1",
                "post_nat_dst_addr": "192.168.1.125",
                "post_napt_src_port": 0,
                "post_napt_dst_port": 0,
            })
            current = subprocess.run(
                [sys.executable, str(ROOT / "collector/flowstore.py"), str(database)],
                input=json.dumps(nat_record) + "\n",
                check=True,
                text=True,
                capture_output=True,
            )
            self.assertIn("written=1 invalid=0", current.stderr)

            original = subprocess.run(
                [sys.executable, str(original_flowstore), str(database)],
                input=json.dumps(self.base_record()) + "\n",
                check=True,
                text=True,
                capture_output=True,
            )
            self.assertIn("written=1 invalid=0", original.stderr)

            with sqlite3.connect(database) as db:
                self.assertEqual(
                    db.execute(
                        "SELECT schema_version, count(*) FROM flows "
                        "GROUP BY schema_version"
                    ).fetchall(),
                    [(1, 2)],
                )
                rows = db.execute(
                    "SELECT post_nat_dst_ip, post_napt_dst_port "
                    "FROM flows ORDER BY id"
                ).fetchall()
                self.assertEqual(rows, [("192.168.1.125", 0), (None, None)])
                self.assertEqual(
                    db.execute("PRAGMA integrity_check").fetchone(), ("ok",)
                )

    def test_schema_version_2_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "flows.db"
            with sqlite3.connect(database) as db:
                db.executescript((ROOT / "collector/schema.sql").read_text())
                flow = FLOWSTORE.normalize(self.base_record())
                flow["schema_version"] = 2
                db.execute(
                    f"INSERT INTO flows ({', '.join(FLOWSTORE.COLUMNS)}) VALUES "
                    f"({', '.join('?' for _ in FLOWSTORE.COLUMNS)})",
                    tuple(flow[column] for column in FLOWSTORE.COLUMNS),
                )
                with self.assertRaisesRegex(RuntimeError, "unsupported schema versions"):
                    FLOWSTORE.validate_database(db)


if __name__ == "__main__":
    unittest.main()
