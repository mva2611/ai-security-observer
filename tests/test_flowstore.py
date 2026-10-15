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

    def test_existing_rows_and_schema_version_remain_compatible_after_migration(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            database = directory / "flows.db"
            backup = directory / "flows.before-nat.db"
            schema = (ROOT / "collector/schema.sql").read_text()
            for column in (
                "    post_nat_src_ip       TEXT,\n",
                "    post_nat_dst_ip       TEXT,\n",
                "    post_napt_src_port    INTEGER,\n",
                "    post_napt_dst_port    INTEGER\n",
            ):
                schema = schema.replace(column, "")
            schema = schema.replace("    observation_domain_id INTEGER,\n\n);", "    observation_domain_id INTEGER\n);")
            with sqlite3.connect(database) as db:
                db.executescript(schema)
                old = FLOWSTORE.normalize(self.base_record())
                old["schema_version"] = 1
                old_columns = FLOWSTORE.COLUMNS[:-4]
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
                    "SELECT schema_version, post_nat_src_ip, post_napt_src_port FROM flows"
                ).fetchone()
                self.assertEqual(row, (1, None, None))
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
