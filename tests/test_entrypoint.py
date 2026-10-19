#!/usr/bin/env python3

import json
import os
import signal
import sqlite3
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "collector/entrypoint.sh"
FLOWSTORE = ROOT / "collector/flowstore.py"
SCHEMA = ROOT / "collector/schema.sql"


def flow_record():
    return {
        "type": "IPFIX",
        "time_received_ns": 1_700_000_000_000_000_000,
        "sampler_address": "192.0.2.254",
        "sequence_num": 1,
        "src_addr": "192.0.2.1",
        "dst_addr": "198.51.100.1",
        "proto": "TCP",
    }


class EntrypointShutdownTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.database = self.directory / "flows.db"
        with sqlite3.connect(self.database) as db:
            db.executescript(SCHEMA.read_text())

    def tearDown(self):
        self.temp.cleanup()

    def environment(self, goflow):
        return {
            **os.environ,
            "FLOWSTORE_FIFO": str(self.directory / "goflow.json"),
            "GOFLOW2_BIN": str(goflow),
            "FLOWSTORE_BIN": str(FLOWSTORE),
            "FLOWSTORE_DB": str(self.database),
        }

    def executable(self, name, body):
        path = self.directory / name
        path.write_text("#!/bin/sh\nset -eu\n" + body)
        path.chmod(0o755)
        return path

    def test_sigterm_returns_zero_and_flushes_partial_batch(self):
        record = json.dumps(flow_record())
        goflow = self.executable(
            "goflow-ok",
            f"printf '%s\\n' '{record}'\n"
            "trap 'exit 0' TERM INT\n"
            "while :; do sleep 1; done\n",
        )
        process = subprocess.Popen(
            ["sh", str(ENTRYPOINT)], env=self.environment(goflow)
        )
        try:
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                if (self.directory / "goflow.json").exists():
                    break
                time.sleep(0.01)
            process.send_signal(signal.SIGTERM)
            self.assertEqual(process.wait(timeout=15), 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()

        with sqlite3.connect(self.database) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM flows").fetchone()[0], 1)

    def test_unexpected_child_exit_is_nonzero(self):
        goflow = self.executable("goflow-fail", "exit 7\n")
        result = subprocess.run(
            ["sh", str(ENTRYPOINT)],
            env=self.environment(goflow),
            timeout=15,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
