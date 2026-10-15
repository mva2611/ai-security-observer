#!/usr/bin/env python3

import importlib.util
import io
import json
import sqlite3
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("flowstore_batch", ROOT / "collector/flowstore.py")
FLOWSTORE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(FLOWSTORE)


def record(sequence):
    return json.dumps({
        "type": "IPFIX",
        "time_received_ns": sequence,
        "sampler_address": "127.0.0.1",
        "sequence_num": sequence,
        "src_addr": "198.51.100.1",
        "dst_addr": "192.168.1.1",
        "proto": "TCP",
    }) + "\n"


class BlockingLines:
    def __init__(self):
        import queue
        self.lines = queue.Queue()

    def write(self, line):
        self.lines.put(line)

    def close(self):
        self.lines.put(None)

    def __iter__(self):
        while True:
            line = self.lines.get()
            if line is None:
                return
            yield line


class BatchFlushTest(unittest.TestCase):
    def database(self):
        db = sqlite3.connect(":memory:", check_same_thread=False)
        db.executescript((ROOT / "collector/schema.sql").read_text())
        return db

    def test_configured_flush_deadline_is_five_seconds(self):
        self.assertEqual(FLOWSTORE.BATCH_FLUSH_SECONDS, 5.0)

    def test_partial_batch_flushes_while_input_stays_open(self):
        db = self.database()
        stream = BlockingLines()
        result = []
        worker = threading.Thread(
            target=lambda: result.append(
                FLOWSTORE.process_stream(db, stream, flush_seconds=0.05)
            )
        )
        worker.start()
        for sequence in range(3):
            stream.write(record(sequence))

        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            if db.execute("SELECT count(*) FROM flows").fetchone()[0] == 3:
                break
            time.sleep(0.01)
        self.assertEqual(db.execute("SELECT count(*) FROM flows").fetchone()[0], 3)
        stream.close()
        worker.join(1)
        self.assertEqual(result, [(3, 3, 0)])

    def test_exact_batch_flushes_without_eof(self):
        db = self.database()
        stream = BlockingLines()
        result = []
        worker = threading.Thread(
            target=lambda: result.append(
                FLOWSTORE.process_stream(db, stream, flush_seconds=60)
            )
        )
        worker.start()
        for sequence in range(500):
            stream.write(record(sequence))

        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if db.execute("SELECT count(*) FROM flows").fetchone()[0] == 500:
                break
            time.sleep(0.01)
        self.assertEqual(db.execute("SELECT count(*) FROM flows").fetchone()[0], 500)
        stream.close()
        worker.join(1)
        self.assertEqual(result, [(500, 500, 0)])

    def test_full_and_partial_batches_are_written(self):
        db = self.database()
        stream = io.StringIO("".join(record(i) for i in range(833)))
        self.assertEqual(
            FLOWSTORE.process_stream(db, stream, flush_seconds=60),
            (833, 833, 0),
        )
        self.assertEqual(db.execute("SELECT count(*) FROM flows").fetchone()[0], 833)

    def test_eof_flushes_remaining_batch(self):
        db = self.database()
        stream = io.StringIO("".join(record(i) for i in range(7)))
        self.assertEqual(
            FLOWSTORE.process_stream(db, stream, flush_seconds=60),
            (7, 7, 0),
        )
        self.assertEqual(db.execute("SELECT count(*) FROM flows").fetchone()[0], 7)

    def test_sqlite_failure_is_not_silently_accepted_or_cleared(self):
        db = self.database()
        stream = io.StringIO(record(1))
        captured_batch = None

        def fail(_db, batch):
            nonlocal captured_batch
            captured_batch = batch
            raise sqlite3.OperationalError("disk I/O error")

        with mock.patch.object(FLOWSTORE, "insert_batch", side_effect=fail):
            with self.assertRaisesRegex(sqlite3.OperationalError, "disk I/O error"):
                FLOWSTORE.process_stream(db, stream, flush_seconds=60)
        self.assertIsNotNone(captured_batch)
        self.assertEqual(len(captured_batch), 1)
        self.assertEqual(db.execute("SELECT count(*) FROM flows").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
