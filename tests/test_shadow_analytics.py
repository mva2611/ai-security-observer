import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from analytics.shadow import (readonly,open_target,process_batch,project_security,
                              SECURITY_COLUMNS,start_worker,worker_health,worker_failed,
                              cleanup_signatures,run_signature_cleanup_cycle)
from collector.flowstore import COLUMNS

ROOT=Path(__file__).resolve().parents[1]
HOUR=3600*10**9
DAY=24*HOUR

class ShadowTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.base=Path(self.temp.name)
        self.path=self.base/'flows.db'
        self.writer=sqlite3.connect(self.path)
        self.writer.executescript((ROOT/'collector/schema.sql').read_text())
        self.source=readonly(self.path,'flows',('id',)+COLUMNS)
        self.target_path=self.base/'analytics.db'
        self.target=open_target(self.target_path,[self.path])

    def tearDown(self):
        self.source.close(); self.target.close(); self.writer.close(); self.temp.cleanup()

    def put(self,identity=1,stamp=DAY,**changes):
        row=dict.fromkeys(COLUMNS)
        row.update(schema_version=1,received_at_ns=stamp+10**9,exporter_ip='192.168.1.1',
                   sequence_num=identity,flow_start_ns=stamp-10**9,flow_end_ns=stamp,
                   flow_time_source='absolute',src_ip='192.168.1.2',dst_ip='8.8.8.8',
                   src_port=50000,dst_port=443,protocol=6,ingress_if=10,egress_if=8,
                   src_mac='02:00:00:00:00:01',bytes=100,packets=2)
        row.update(changes)
        self.writer.execute('INSERT INTO flows(id,'+','.join(COLUMNS)+') VALUES ('+
                            ','.join('?' for _ in range(len(COLUMNS)+1))+')',
                            (identity,)+tuple(row[k] for k in COLUMNS))
        self.writer.commit()

    def drain(self,batch=2):
        while process_batch(self.source,self.target,batch): pass

    def totals(self,scope='canonical',width=3600):
        return tuple(self.target.execute('SELECT coalesce(sum(flows),0),coalesce(sum(bytes),0),'
                                        'coalesce(sum(packets),0) FROM aggregates WHERE scope=? AND width_s=?',
                                        (scope,width)).fetchone())

    def test_replay_duplicates_and_conservation(self):
        self.put(); self.put(2); self.put(3,stamp=DAY+HOUR); self.put(4,ingress_if=9)
        self.drain(1)
        self.assertEqual(self.totals('raw'),(4,400,8))
        self.assertEqual(self.totals(),(2,200,4))
        self.assertEqual(self.totals('duplicate'),(1,100,2))
        self.assertEqual(self.totals('excluded'),(1,100,2))
        for scope in ('raw','canonical','duplicate','excluded'):
            self.assertEqual(self.totals(scope),self.totals(scope,86400))
        self.drain(); self.assertEqual(self.totals('raw'),(4,400,8))

    def test_signature_expiry_and_late_duplicate_are_explicit(self):
        self.put(1,stamp=DAY)
        self.put(2,stamp=10*DAY,src_port=50001)
        self.drain()
        before={scope:self.totals(scope) for scope in ('raw','canonical','duplicate','excluded')}
        result=cleanup_signatures(self.source,self.target,horizon_s=7*24*60*60)
        self.assertEqual(result['deleted'],1)
        self.assertEqual(self.target.execute('SELECT count(*) FROM signatures').fetchone()[0],1)
        for scope,total in before.items(): self.assertEqual(self.totals(scope),total)
        # Same canonical content as flow 1 arrives with a later source ID.  Its
        # old event time is behind the closed horizon, so it is never recounted.
        self.put(3,stamp=DAY)
        self.drain()
        self.assertEqual(self.totals('canonical'),before['canonical'])
        self.assertEqual(self.totals('late_outside_horizon'),(1,100,2))
        self.assertEqual(self.totals('raw'),(3,300,6))
        self.assertEqual(self.target.execute('SELECT late_outside_total FROM signature_retention').fetchone()[0],1)

    def test_cleanup_restart_and_failure_are_transactional(self):
        self.put(1,stamp=DAY); self.put(2,stamp=10*DAY,src_port=50001); self.drain()
        def fail(): raise RuntimeError('cleanup interrupted')
        with self.assertRaisesRegex(RuntimeError,'cleanup interrupted'):
            cleanup_signatures(self.source,self.target,horizon_s=7*24*60*60,before_commit=fail)
        self.assertEqual(self.target.execute('SELECT count(*) FROM signatures').fetchone()[0],2)
        self.assertEqual(self.target.execute('SELECT closed_before_ns FROM signature_retention').fetchone()[0],0)
        self.target.close(); self.target=open_target(self.target_path,[self.path])
        result=cleanup_signatures(self.source,self.target,horizon_s=7*24*60*60)
        self.assertEqual(result['deleted'],1)
        again=cleanup_signatures(self.source,self.target,horizon_s=7*24*60*60)
        self.assertEqual(again['deleted'],0)
        self.assertEqual(self.totals('raw'),(2,200,4))
        self.assertEqual(self.totals('canonical'),(2,200,4))

    def test_cleanup_requires_complete_checkpoint_and_no_internal_gap(self):
        self.put(1,stamp=DAY); self.put(2,stamp=10*DAY,src_port=50001)
        process_batch(self.source,self.target,1)
        with self.assertRaisesRegex(RuntimeError,'complete source pass'):
            cleanup_signatures(self.source,self.target,horizon_s=1)
        self.drain()
        self.put(4,stamp=11*DAY,src_port=50002); self.drain()
        gap=self.target.execute("SELECT kind,blocks_cleanup FROM source_gaps WHERE after_id=2").fetchone()
        self.assertEqual(gap,('internal',1))
        with self.assertRaisesRegex(RuntimeError,'source gap'):
            cleanup_signatures(self.source,self.target,horizon_s=1)
        self.assertEqual(self.target.execute('SELECT count(*) FROM signatures').fetchone()[0],3)

    def test_initial_source_floor_does_not_block_cleanup(self):
        self.put(100,stamp=DAY); self.put(101,stamp=10*DAY,src_port=50001); self.drain()
        self.assertEqual(self.target.execute("SELECT kind,blocks_cleanup FROM source_gaps").fetchone(),
                         ('initial_boundary',0))
        self.assertEqual(cleanup_signatures(self.source,self.target,horizon_s=7*24*60*60)['deleted'],1)

    def test_cleanup_cycle_is_bounded_and_resumable(self):
        for identity in range(1,26): self.put(identity,stamp=DAY+identity,src_port=40000+identity)
        self.put(26,stamp=10*DAY,src_port=50001); self.drain(100)
        first=run_signature_cleanup_cycle(self.source,self.target,horizon_s=7*24*60*60,
                                          limit=10,max_chunks=2)
        self.assertEqual(first['deleted'],20)
        self.assertEqual(self.target.execute('SELECT count(*) FROM signatures').fetchone()[0],6)
        second=run_signature_cleanup_cycle(self.source,self.target,horizon_s=7*24*60*60,
                                           limit=10,max_chunks=2)
        self.assertEqual(second['deleted'],5)
        self.assertEqual(self.target.execute('SELECT count(*) FROM signatures').fetchone()[0],1)

    def test_late_prior_day_and_boundary(self):
        self.put(stamp=DAY+HOUR); self.put(2,stamp=DAY-1)
        self.put(3,stamp=DAY); self.put(4,stamp=DAY+HOUR-1)
        self.drain()
        self.assertEqual(self.totals(),(4,400,8))
        days=list(self.target.execute("SELECT start_ns,flows FROM aggregates WHERE scope='raw' AND width_s=86400 ORDER BY start_ns"))
        self.assertEqual(days,[(0,1),(DAY,3)])
        self.assertEqual(self.target.execute("SELECT sum(late_flows) FROM aggregates WHERE scope='raw' AND width_s=3600").fetchone()[0],3)

    def test_reordered_input_same_totals(self):
        for i,stamp in enumerate((DAY+HOUR,DAY-1,DAY,DAY+HOUR-1),1): self.put(i,stamp=stamp)
        self.drain(1)
        first=list(self.target.execute("SELECT start_ns,flows,bytes,packets FROM aggregates WHERE scope='canonical' AND width_s=3600 ORDER BY start_ns"))
        other=open_target(self.base/'other.db',[self.path])
        try:
            while process_batch(self.source,other,100): pass
            self.assertEqual(first,list(other.execute("SELECT start_ns,flows,bytes,packets FROM aggregates WHERE scope='canonical' AND width_s=3600 ORDER BY start_ns")))
        finally: other.close()

    def test_null_negative_and_fallback(self):
        self.put(bytes=None,packets=-2,flow_end_ns=None,flow_time_source='export_fallback')
        self.put(2,bytes=0,packets=0,flow_time_source='reconstructed')
        self.drain()
        self.assertEqual(self.totals('raw'),(2,0,0))
        self.assertEqual(tuple(self.target.execute("SELECT sum(missing_bytes),sum(missing_packets),sum(invalid_counters) FROM aggregates WHERE scope='raw' AND width_s=3600").fetchone()),(1,0,1))
        self.assertEqual(self.target.execute("SELECT flows FROM aggregates WHERE scope='raw' AND width_s=3600 AND time_source='invalid_fallback'").fetchone()[0],1)

    def test_unknown_identity_and_reverse_direction(self):
        self.put(src_mac=None)
        self.put(2,ingress_if=8,egress_if=10,src_ip='8.8.8.8',dst_ip='1.1.1.1',
                 src_port=443,dst_port=50000,post_nat_dst_ip='192.168.1.2',post_napt_dst_port=50000)
        self.drain()
        self.assertEqual(self.totals(),(2,200,4))
        self.assertEqual({x[0] for x in self.target.execute("SELECT device FROM aggregates WHERE scope='canonical'")},{'unknown'})
        self.assertEqual({x[0] for x in self.target.execute("SELECT direction FROM aggregates WHERE scope='canonical'")},{'outbound','inbound'})

    def test_ipv6_peer_nat_and_time_provenance(self):
        self.put(dst_ip='2606:4700:4700::1111',src_ip='fd00::2',flow_time_source='reconstructed')
        self.put(2,ingress_if=8,egress_if=10,src_ip='2001:4860:4860::8888',dst_ip='2001:db8::1',
                 src_port=443,dst_port=50000,post_nat_dst_ip='fd00::2',post_napt_dst_port=50000,
                 src_mac=None,flow_time_source='export_fallback')
        self.drain()
        peers={x[0] for x in self.target.execute("SELECT peer FROM aggregates WHERE scope='canonical'")}
        self.assertEqual(peers,{'2606:4700:4700::/48','2001:4860:4860::/48'})
        self.assertEqual({x[0] for x in self.target.execute("SELECT time_source FROM aggregates WHERE scope='canonical'")},
                         {'reconstructed','export_fallback'})

    def test_gaps_are_numeric_observations(self):
        self.put(3); self.put(7,stamp=DAY+HOUR); self.drain(1)
        self.assertEqual(list(self.target.execute('SELECT after_id,next_id FROM source_gaps ORDER BY after_id')),[(0,3),(3,7)])
        self.assertEqual(self.target.execute('SELECT numeric_gap_count FROM presentation_health').fetchone()[0],2)

    def test_boundary_mutation_fails_closed(self):
        self.put(); self.drain()
        self.writer.execute('UPDATE flows SET bytes=999 WHERE id=1'); self.writer.commit()
        with self.assertRaisesRegex(RuntimeError,'boundary'): self.drain()
        self.assertEqual(self.totals(),(1,100,2))

    def test_missing_boundary_fails_closed(self):
        self.put(); self.drain()
        self.writer.execute('DELETE FROM flows'); self.writer.commit() # isolated fixture only
        with self.assertRaisesRegex(RuntimeError,'boundary'): self.drain()

    def test_atomic_failure_and_restart(self):
        self.put()
        def fail(): raise RuntimeError('injected crash')
        with self.assertRaisesRegex(RuntimeError,'injected'): process_batch(self.source,self.target,before_commit=fail)
        self.assertEqual(self.totals('raw'),(0,0,0))
        self.assertEqual(self.target.execute('SELECT count(*) FROM checkpoints').fetchone()[0],0)
        self.target.close(); self.target=open_target(self.target_path,[self.path]); self.drain()
        self.assertEqual(self.totals(),(1,100,2))

    def test_process_death_before_commit(self):
        self.put()
        code="""import os,sys
from analytics.shadow import *
from collector.flowstore import COLUMNS
s=readonly(sys.argv[1],'flows',('id',)+COLUMNS)
t=open_target(sys.argv[2],[sys.argv[1]])
process_batch(s,t,before_commit=lambda: os._exit(23))
"""
        result=subprocess.run([sys.executable,'-c',code,str(self.path),str(self.target_path)],cwd=ROOT)
        self.assertEqual(result.returncode,23)
        self.assertEqual(self.totals('raw'),(0,0,0))
        self.drain(); self.assertEqual(self.totals(),(1,100,2))
        self.assertEqual(self.target.execute('PRAGMA integrity_check').fetchone()[0],'ok')

    def test_read_only_and_path_alias(self):
        with self.assertRaises(sqlite3.OperationalError): self.source.execute('CREATE TABLE forbidden(x)')
        with self.assertRaises(ValueError): open_target(self.path,[self.path])
        link=self.base/'link.db'; os.link(self.path,link)
        with self.assertRaises(ValueError): open_target(link,[self.path])

    def test_contract_and_binding(self):
        with self.assertRaises(ValueError): readonly(self.path,'missing',('id',))
        with self.assertRaises(ValueError): open_target(self.target_path,[self.base/'other-source.db'])
        bad=self.base/'bad.db'; db=sqlite3.connect(bad); db.execute('CREATE TABLE flows(id TEXT PRIMARY KEY)'); db.close()
        with self.assertRaises(ValueError): readonly(bad,'flows',('id',))

    def test_previous_shadow_schema_migrates_without_losing_signatures(self):
        path=self.base/'previous-analytics.db'; db=sqlite3.connect(path)
        db.executescript("CREATE TABLE analytics_metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);"
                         "INSERT INTO analytics_metadata VALUES('schema_version','1');"
                         "CREATE TABLE signatures(signature TEXT PRIMARY KEY);"
                         "INSERT INTO signatures VALUES('legacy');"
                         "CREATE TABLE source_gaps(source TEXT,after_id INTEGER,next_id INTEGER,"
                         "PRIMARY KEY(source,after_id,next_id));"
                         "INSERT INTO source_gaps VALUES('flows',0,100);")
        db.commit(); db.close()
        migrated=open_target(path,[self.path])
        try:
            self.assertEqual(migrated.execute('SELECT signature,observed_ns,flow_id FROM signatures').fetchone(),
                             ('legacy',None,None))
            self.assertEqual(migrated.execute('SELECT kind,blocks_cleanup FROM source_gaps').fetchone(),
                             ('initial_boundary',0))
        finally: migrated.close()

    def test_version_and_batch_validation(self):
        self.put(schema_version=2)
        with self.assertRaises(ValueError): self.drain()
        with self.assertRaises(ValueError): process_batch(self.source,self.target,0)
        self.assertEqual(self.totals('raw'),(0,0,0))

    def test_security_mutable_projection_and_checkpoint(self):
        path=self.base/'security.db'; writer=sqlite3.connect(path)
        writer.executescript((ROOT/'detector/security_schema.sql').read_text())
        writer.execute("INSERT INTO security_events VALUES ('e','d',1,1,1,'R4','1','observe','info','device','unknown',NULL,NULL,'fanout','open','unresolved','{}')")
        writer.execute("INSERT INTO detector_runtime_health VALUES('flows',10,9,1,5)")
        writer.commit(); source=readonly(path,'security_events',SECURITY_COLUMNS)
        try:
            self.assertEqual(project_security(source,self.target,1),1)
            self.assertEqual(self.target.execute('SELECT last_checkpoint FROM presentation_detector_health').fetchone()[0],5)
            first=self.target.execute('SELECT freshness,source_created_ns,source_first_seen_ns,'
                                      'source_last_seen_ns,source_sweep_completed_ns FROM presentation_security_v2').fetchone()
            self.assertEqual(first[0:4],('current',1,1,1)); self.assertIsNotNone(first[4])
            writer.execute("UPDATE security_events SET detection_status='closed',last_seen_ns=2"); writer.commit()
            def fail(): raise RuntimeError('crash')
            with self.assertRaises(RuntimeError): project_security(source,self.target,before_commit=fail)
            self.assertEqual(self.target.execute('SELECT detection_status,freshness FROM presentation_security_v2').fetchone(),('open','uncertain'))
            project_security(source,self.target)
            self.assertEqual(self.target.execute('SELECT detection_status,freshness FROM presentation_security_v2').fetchone(),('closed','current'))
            self.assertEqual(self.target.execute('SELECT count(*) FROM security_projection_history').fetchone()[0],2)
            self.assertEqual(self.target.execute("SELECT count(*) FROM checkpoints WHERE source='flows'").fetchone()[0],0)
        finally: source.close(); writer.close()

    def test_disappeared_security_event_becomes_historical(self):
        path=self.base/'security.db'; writer=sqlite3.connect(path)
        writer.executescript((ROOT/'detector/security_schema.sql').read_text())
        writer.execute("INSERT INTO security_events VALUES ('e','d',1,1,1,'R4','1','observe','info','device','unknown',NULL,NULL,'fanout','open','unresolved','{}')")
        writer.commit(); source=readonly(path,'security_events',SECURITY_COLUMNS)
        try:
            project_security(source,self.target)
            writer.execute("DELETE FROM security_events"); writer.commit()
            project_security(source,self.target)
            self.assertEqual(self.target.execute('SELECT freshness FROM security_projection_v2').fetchone()[0],'historical')
        finally: source.close(); writer.close()

    def test_worker_health_current_incarnation_failure_stale_and_recovery(self):
        start_worker(self.target,now=100,incarnation='one')
        self.assertEqual(worker_health(self.target,now=101)['state'],'initializing')
        self.put(); self.drain()
        self.assertEqual(worker_health(self.target,now=time.time_ns())['state'],'healthy')
        start_worker(self.target,now=200,incarnation='two')
        self.assertEqual(worker_health(self.target,now=201)['state'],'initializing')
        worker_failed(self.target,RuntimeError('token=secret /private/source'),now=300)
        state=worker_health(self.target,now=301)
        self.assertEqual(state['state'],'failed'); self.assertNotIn('secret',state['failure_cause'])
        start_worker(self.target,now=400,incarnation='three')
        self.target.execute("UPDATE worker_runtime SET state='healthy',heartbeat_ns=400,last_success_ns=400 "
                            "WHERE worker='flows'"); self.target.commit()
        self.assertEqual(worker_health(self.target,now=91_000_000_401,stale_s=90)['state'],'stale')

    def test_source_pass_completion_is_not_claimed_for_partial_batch(self):
        self.put(); self.put(2)
        start_worker(self.target,now=100,incarnation='pass-test')
        self.assertEqual(process_batch(self.source,self.target,batch_size=1),1)
        row=self.target.execute("SELECT last_success_ns,last_source_pass_completed_ns "
                                "FROM worker_runtime WHERE worker='flows'").fetchone()
        self.assertIsNotNone(row[0])
        self.assertIsNone(row[1])
        while process_batch(self.source,self.target,batch_size=10):
            pass
        completed=self.target.execute("SELECT last_source_pass_completed_ns FROM worker_runtime "
                                      "WHERE worker='flows'").fetchone()[0]
        self.assertIsNotNone(completed)

    def test_security_failure_before_sweep_id_preserves_original_error(self):
        path=self.base/'broken-security.db'; writer=sqlite3.connect(path)
        writer.execute('CREATE TABLE security_events('+','.join(f'{name} TEXT' for name in SECURITY_COLUMNS)+')')
        writer.commit(); source=readonly(path,'security_events',SECURITY_COLUMNS)
        try:
            with self.assertRaisesRegex(sqlite3.OperationalError,'detector_checkpoints'):
                project_security(source,self.target)
        finally:
            source.close(); writer.close()

    def test_write_failure_records_failure_without_advancing_data(self):
        self.put(); start_worker(self.target)
        def disk_full(): raise sqlite3.OperationalError('database or disk is full')
        with self.assertRaises(sqlite3.OperationalError):
            process_batch(self.source,self.target,before_commit=disk_full)
        self.assertEqual(self.totals('raw'),(0,0,0))
        self.assertEqual(worker_health(self.target)['state'],'failed')
        self.assertIsNone(self.target.execute("SELECT cursor FROM checkpoints WHERE source='flows'").fetchone())

    def test_real_sqlite_full_uses_reserve_to_record_failure(self):
        for identity in range(1,201):
            self.put(identity,src_port=40000+identity,stamp=DAY+identity)
        start_worker(self.target)
        pages=self.target.execute('PRAGMA page_count').fetchone()[0]
        self.target.execute(f'PRAGMA max_page_count={pages}')
        with self.assertRaises(sqlite3.OperationalError):
            process_batch(self.source,self.target,200)
        self.assertEqual(self.totals('raw'),(0,0,0))
        self.assertIsNone(self.target.execute("SELECT cursor FROM checkpoints WHERE source='flows'").fetchone())
        self.assertEqual(worker_health(self.target)['state'],'failed')
        self.assertEqual(self.target.execute('SELECT count(*) FROM failure_reserve').fetchone()[0],0)

    def test_longer_wal_writer_reader_overlap(self):
        self.writer.execute('PRAGMA journal_mode=WAL'); self.writer.commit()
        stop=threading.Event()
        def write_rows():
            connection=sqlite3.connect(self.path)
            for identity in range(1,101):
                row=dict.fromkeys(COLUMNS); stamp=DAY+identity
                row.update(schema_version=1,received_at_ns=stamp+10**9,exporter_ip='192.168.1.1',
                    sequence_num=identity,flow_start_ns=stamp-10**9,flow_end_ns=stamp,
                    flow_time_source='absolute',src_ip='192.168.1.2',dst_ip='8.8.8.8',
                    src_port=40000+identity,dst_port=443,protocol=6,ingress_if=10,egress_if=8,
                    src_mac='02:00:00:00:00:01',bytes=100,packets=2)
                connection.execute('INSERT INTO flows(id,'+','.join(COLUMNS)+') VALUES ('+
                    ','.join('?' for _ in range(len(COLUMNS)+1))+')',(identity,)+tuple(row[k] for k in COLUMNS))
                if identity%10==0: connection.commit(); time.sleep(.002)
            connection.commit(); connection.close(); stop.set()
        thread=threading.Thread(target=write_rows); thread.start()
        while not stop.is_set() or self.target.execute("SELECT coalesce(cursor,0) FROM checkpoints WHERE source='flows'").fetchone() is None:
            process_batch(self.source,self.target,7)
            if stop.is_set(): break
        thread.join(); self.drain(7)
        self.assertEqual(self.totals(),(100,10000,200))
        self.assertEqual(self.target.execute('PRAGMA integrity_check').fetchone()[0],'ok')

    def test_actual_reordering_across_sources(self):
        self.put(1,stamp=DAY+HOUR); self.put(2,stamp=DAY-1); self.put(3,stamp=DAY)
        self.drain()
        expected=list(self.target.execute("SELECT start_ns,flows,bytes,packets FROM aggregates WHERE scope='canonical' AND width_s=3600 ORDER BY start_ns"))
        path=self.base/'reordered.db'; writer=sqlite3.connect(path)
        writer.executescript((ROOT/'collector/schema.sql').read_text())
        rows=self.writer.execute('SELECT * FROM flows ORDER BY flow_end_ns').fetchall()
        for identity,row in enumerate(rows,1):
            writer.execute('INSERT INTO flows VALUES('+','.join('?' for _ in row)+')',(identity,)+row[1:])
        writer.commit(); writer.close()
        source=readonly(path,'flows',('id',)+COLUMNS)
        target=open_target(self.base/'ordered-analytics.db',[path])
        try:
            while process_batch(source,target,1): pass
            actual=list(target.execute("SELECT start_ns,flows,bytes,packets FROM aggregates WHERE scope='canonical' AND width_s=3600 ORDER BY start_ns"))
            self.assertEqual(expected,actual)
        finally: source.close(); target.close()

    def test_restart_after_successful_commit(self):
        self.put(); self.drain()
        self.target.close(); self.target=open_target(self.target_path,[self.path]); self.drain()
        self.assertEqual(self.totals(),(1,100,2))
        self.put(2,stamp=DAY+HOUR); self.drain()
        self.assertEqual(self.totals(),(2,200,4))

    def test_cli_bounded_replay(self):
        self.put(); self.put(2,stamp=DAY+HOUR)
        path=self.base/'cli-analytics.db'
        command=[sys.executable,'-m','analytics.shadow',str(self.path),str(path),'--batch-size','1','--max-batches','1']
        subprocess.run(command,cwd=ROOT,check=True)
        db=sqlite3.connect(path)
        self.assertEqual(db.execute("SELECT cursor FROM checkpoints WHERE source='flows'").fetchone()[0],'1')
        subprocess.run(command,cwd=ROOT,check=True)
        self.assertEqual(db.execute("SELECT cursor FROM checkpoints WHERE source='flows'").fetchone()[0],'2')
        db.close()

    def test_baseline_prepared_only(self):
        self.put(); self.drain()
        self.assertEqual(self.target.execute('SELECT count(*) FROM baseline_models').fetchone()[0],0)
        self.assertEqual(self.target.execute('SELECT utc_hour FROM baseline_hourly_inputs').fetchone()[0],0)

if __name__=='__main__': unittest.main()
