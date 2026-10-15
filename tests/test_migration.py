#!/usr/bin/env python3

import importlib.util
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "migration", ROOT / "collector/migrate_flowstore_nat.py"
)
MIGRATION = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MIGRATION)


class MigrationSafetyTest(unittest.TestCase):
    def make_database(self, path):
        schema = (ROOT / "collector/schema.sql").read_text()
        for column in (
            "    post_nat_src_ip       TEXT,\n",
            "    post_nat_dst_ip       TEXT,\n",
            "    post_napt_src_port    INTEGER,\n",
            "    post_napt_dst_port    INTEGER\n",
        ):
            schema = schema.replace(column, "")
        schema = schema.replace(
            "    observation_domain_id INTEGER,\n\n);",
            "    observation_domain_id INTEGER\n);",
        )
        with sqlite3.connect(path) as db:
            db.executescript(schema)

    def test_same_canonical_source_and_backup_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "flows.db"
            self.make_database(database)
            with self.assertRaisesRegex(RuntimeError, "same path"):
                MIGRATION.migrate(database, Path(directory) / "." / "flows.db")

    def test_insufficient_space_is_rejected_before_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "flows.db"
            backup = Path(directory) / "backup.db"
            self.make_database(database)
            usage = mock.Mock(free=0)
            with mock.patch.object(MIGRATION.shutil, "disk_usage", return_value=usage):
                with self.assertRaisesRegex(RuntimeError, "insufficient backup space"):
                    MIGRATION.migrate(database, backup)
            self.assertFalse(backup.exists())

    def test_missing_backup_parent_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "flows.db"
            self.make_database(database)
            with self.assertRaisesRegex(RuntimeError, "path not found"):
                MIGRATION.migrate(database, Path(directory) / "missing" / "backup.db")


if __name__ == "__main__":
    unittest.main()
