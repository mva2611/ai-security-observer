import importlib.util, sqlite3, tempfile, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("security_reader",ROOT/"detector/security_reader.py")
reader=importlib.util.module_from_spec(spec); spec.loader.exec_module(reader)

class SecurityReaderTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); root=Path(self.tmp.name)
        self.flows_path=root/"flows.db"; self.security_path=root/"security.db"
        with sqlite3.connect(self.flows_path) as db:
            db.execute("CREATE TABLE flows(id INTEGER PRIMARY KEY, received_at_ns INTEGER)")
            db.executemany("INSERT INTO flows(id,received_at_ns) VALUES(?,?)",[(1,1),(2,2),(4,4)])
        self.flows=reader.open_flows_read_only(self.flows_path)
        self.security=reader.open_security(self.security_path)
    def tearDown(self): self.flows.close(); self.security.close(); self.tmp.cleanup()
    def checkpoint(self):
        row=self.security.execute("SELECT last_flow_id FROM detector_checkpoints WHERE source_name='flows'").fetchone()
        return row[0] if row else None
    def test_read_only_source(self):
        with self.assertRaises(sqlite3.OperationalError): self.flows.execute("DELETE FROM flows")
    def test_incremental_resume_and_idempotence(self):
        self.assertEqual(reader.process_batch(self.flows,self.security,batch_size=2),(2,2))
        self.assertEqual(reader.process_batch(self.flows,self.security,batch_size=2),(1,4))
        self.assertEqual(reader.process_batch(self.flows,self.security,batch_size=2),(0,4))
        self.assertEqual(self.security.execute("SELECT count(*) FROM source_gaps").fetchone()[0],1)
    def test_transaction_failure_does_not_advance(self):
        def fail(): raise RuntimeError("crash")
        with self.assertRaises(RuntimeError): reader.process_batch(self.flows,self.security,before_commit=fail)
        self.assertIsNone(self.checkpoint())
        self.assertEqual(self.security.execute("SELECT count(*) FROM source_gaps").fetchone()[0],0)
        self.assertEqual(reader.process_batch(self.flows,self.security)[1],4)
    def test_missing_ids_are_operational_evidence_not_events(self):
        reader.process_batch(self.flows,self.security)
        self.assertEqual(self.security.execute("SELECT missing_after_id,next_present_id FROM source_gaps").fetchall(),[(2,4)])
        self.assertEqual(self.security.execute("SELECT count(*) FROM security_events").fetchone()[0],0)
    def test_schema_and_event_idempotence(self):
        tables={r[0] for r in self.security.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue({"security_events","event_evidence","decisions","action_attempts","admin_reviews"} <= tables)
        values=("e1","same",1,1,1,"r","1","observe","info","device",None,None,None,"x","open","unresolved","{}")
        self.security.execute("INSERT INTO security_events VALUES("+",".join("?"*len(values))+")",values)
        with self.assertRaises(sqlite3.IntegrityError):
            self.security.execute("INSERT INTO security_events VALUES("+",".join("?"*len(values))+")",("e2",)+values[1:])

if __name__=="__main__": unittest.main()
