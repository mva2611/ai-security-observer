from argparse import Namespace
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest

from analytics.healthcheck import inspect
from analytics.runtime import run
from analytics.shadow import bootstrap_checkpoint,open_target,readonly
from collector.flowstore import COLUMNS

ROOT=Path(__file__).resolve().parents[1]


class AnalyticsRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.base=Path(self.temp.name)
        self.flows=self.base/'flows.db'; db=sqlite3.connect(self.flows)
        db.executescript((ROOT/'collector/schema.sql').read_text()); db.close()
        self.security=self.base/'security.db'; db=sqlite3.connect(self.security)
        db.executescript((ROOT/'detector/security_schema.sql').read_text()); db.close()
        self.analytics=self.base/'analytics.db'; self.log=self.base/'runtime.jsonl'

    def tearDown(self): self.temp.cleanup()

    def put(self,identity):
        db=sqlite3.connect(self.flows); row=dict.fromkeys(COLUMNS); stamp=identity*10**9
        row.update(schema_version=1,received_at_ns=stamp+10**9,exporter_ip='192.168.1.1',
            sequence_num=identity,flow_start_ns=stamp-10**9,flow_end_ns=stamp,
            flow_time_source='absolute',src_ip='192.168.1.2',dst_ip='8.8.8.8',
            src_port=40000+identity,dst_port=443,protocol=6,ingress_if=10,egress_if=8,
            src_mac='02:00:00:00:00:01',bytes=100,packets=2)
        db.execute('INSERT INTO flows(id,'+','.join(COLUMNS)+') VALUES ('+
                   ','.join('?' for _ in range(len(COLUMNS)+1))+')',
                   (identity,)+tuple(row[k] for k in COLUMNS)); db.commit(); db.close()

    def args(self):
        return Namespace(flows_db=str(self.flows),security_db=str(self.security),
            analytics_db=str(self.analytics),bootstrap_current=True,batch_size=10,
            max_batches_per_cycle=2,poll_seconds=.01,stale_seconds=2,
            security_interval_seconds=1,metrics_interval_seconds=1,
            signature_horizon_seconds=604800,cleanup_interval_seconds=1,
            cleanup_limit=10,cleanup_max_chunks=2,max_database_bytes=1610612736,
            log_file=str(self.log))

    def test_bootstrap_is_current_and_idempotent(self):
        self.put(1); source=readonly(self.flows,'flows',('id',)+COLUMNS)
        target=open_target(self.analytics,[self.flows,self.security])
        try:
            self.assertEqual(bootstrap_checkpoint(source,target),(1,True))
            self.assertEqual(bootstrap_checkpoint(source,target),(1,False))
            self.assertEqual(target.execute('SELECT count(*) FROM aggregates').fetchone()[0],0)
        finally: source.close(); target.close()

    def test_runtime_restart_preserves_checkpoint_and_metrics(self):
        self.put(1); stop=threading.Event(); result=[]
        thread=threading.Thread(target=lambda:result.append(run(self.args(),stop))); thread.start()
        for _ in range(100):
            if self.analytics.exists() and inspect(self.analytics,2)['state']=='healthy': break
            time.sleep(.01)
        self.put(2)
        for _ in range(100):
            if inspect(self.analytics,2).get('checkpoint')==2: break
            time.sleep(.01)
        stop.set(); thread.join(3); self.assertEqual(result,[0])
        db=sqlite3.connect(self.analytics)
        self.assertEqual(db.execute("SELECT cursor FROM checkpoints WHERE source='flows'").fetchone()[0],'2')
        self.assertEqual(db.execute("SELECT sum(flows) FROM aggregates WHERE scope='raw' AND width_s=3600").fetchone()[0],1)
        self.assertTrue(db.execute('SELECT payload_json FROM daily_metrics').fetchone())
        self.assertEqual(db.execute("SELECT state FROM worker_runtime WHERE worker='flows'").fetchone()[0],'stopped')
        db.close()
        stop=threading.Event(); result=[]
        thread=threading.Thread(target=lambda:result.append(run(self.args(),stop))); thread.start()
        for _ in range(100):
            if inspect(self.analytics,2).get('state')=='healthy': break
            time.sleep(.01)
        stop.set(); thread.join(3); self.assertEqual(result,[0])
        db=sqlite3.connect(self.analytics)
        self.assertEqual(db.execute("SELECT sum(flows) FROM aggregates WHERE scope='raw' AND width_s=3600").fetchone()[0],1)
        db.close()

    def test_healthcheck_rejects_stale_and_stopped(self):
        self.put(1); source=readonly(self.flows,'flows',('id',)+COLUMNS)
        target=open_target(self.analytics,[self.flows,self.security])
        try:
            bootstrap_checkpoint(source,target)
            now=time.time_ns()
            target.execute("INSERT INTO worker_runtime(worker,incarnation,state,started_ns,heartbeat_ns) "
                           "VALUES('flows','x','healthy',?,?)",(now-3*10**9,now-3*10**9)); target.commit()
        finally: source.close(); target.close()
        self.assertEqual(inspect(self.analytics,1,now)['state'],'stale')

    def test_capacity_limit_fails_worker_without_touching_sources(self):
        self.put(1); args=self.args(); args.max_database_bytes=1
        self.assertEqual(run(args,threading.Event()),1)
        db=sqlite3.connect(self.analytics)
        row=db.execute("SELECT state,failure_type,failure_cause FROM worker_runtime "
                       "WHERE worker='flows'").fetchone(); db.close()
        self.assertEqual(row[0],'failed')
        self.assertEqual(row[1],'RuntimeError')
        self.assertNotIn(str(self.base),row[2])
        source=sqlite3.connect(f'file:{self.flows}?mode=ro',uri=True)
        self.assertEqual(source.execute('SELECT count(*) FROM flows').fetchone()[0],1)
        source.close()


if __name__=='__main__': unittest.main()
