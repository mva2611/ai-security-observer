"""Local shadow analytics. Sources are read-only; no retention or deployment."""
import argparse
import hashlib
import ipaddress
import json
import re
from pathlib import Path
import sqlite3
import time
import uuid
from contextlib import closing

from collector.flowstore import COLUMNS, valid_flow_interval
from detector.detection import DetectionConfig, normalize_traffic

SCHEMA = Path(__file__).with_name('schema.sql')
SECURITY_COLUMNS = ('event_id','rule_id','decision_level','severity','subject_id','summary',
                    'detection_status','resolution_status','created_at_ns',
                    'first_seen_ns','last_seen_ns')


def safe_failure(error):
    kind=type(error).__name__[:80]
    cause=' '.join(str(error).split())
    cause=re.sub(r'(?i)(token|password|secret|authorization)\s*[=:]\s*\S+',
                 r'\1=<redacted>',cause)
    cause=re.sub(r'(?:/[^\s:]+)+','<path>',cause)
    return kind,(cause[:240] or kind)


def start_worker(db,worker='flows',now=None,incarnation=None):
    now=time.time_ns() if now is None else now
    incarnation=incarnation or uuid.uuid4().hex
    db.execute("INSERT INTO worker_runtime(worker,incarnation,state,started_ns,heartbeat_ns,last_attempt_ns) "
               "VALUES(?,?,'initializing',?,?,?) ON CONFLICT(worker) DO UPDATE SET "
               "incarnation=excluded.incarnation,state='initializing',started_ns=excluded.started_ns,"
               "heartbeat_ns=excluded.heartbeat_ns,last_attempt_ns=excluded.last_attempt_ns,"
               "last_success_ns=NULL,last_source_pass_completed_ns=NULL,last_failure_ns=NULL,"
               "failure_type=NULL,failure_cause=NULL",(worker,incarnation,now,now,now))
    db.commit(); return incarnation


def worker_health(db,worker='flows',now=None,stale_s=90):
    now=time.time_ns() if now is None else now
    db.row_factory=sqlite3.Row
    row=db.execute('SELECT * FROM worker_runtime WHERE worker=?',(worker,)).fetchone()
    if row is None: return {'state':'initializing','reason':'never_started'}
    result=dict(row); age=max(0,now-row['heartbeat_ns'])/10**9
    if row['state']=='failed': state,reason='failed','last_attempt_failed'
    elif row['state'] in ('initializing','stopped'):
        state,reason=row['state'],'no_success_current_incarnation'
    elif age>stale_s: state,reason='stale','heartbeat_expired'
    else: state,reason='healthy','recent_success_and_heartbeat'
    result.update(state=state,reason=reason,heartbeat_age_s=age)
    return result


def worker_failed(db,error,worker='flows',now=None):
    now=time.time_ns() if now is None else now; kind,cause=safe_failure(error)
    try:
        db.execute('DELETE FROM failure_reserve WHERE id=1')
        db.execute("UPDATE worker_runtime SET state='failed',heartbeat_ns=?,last_attempt_ns=?,"
                   "last_failure_ns=?,failure_type=?,failure_cause=? WHERE worker=?",
                   (now,now,now,kind,cause,worker)); db.commit()
    except BaseException:
        db.rollback()
        raise error


def stop_worker(db,worker='flows',now=None):
    now=time.time_ns() if now is None else now
    db.execute("UPDATE worker_runtime SET state='stopped',heartbeat_ns=? WHERE worker=?",
               (now,worker)); db.commit()


def readonly(path, table, columns):
    db = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True, timeout=1)
    try:
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA query_only=ON')
        info = list(db.execute(f'PRAGMA table_info({table})'))
        if not set(columns) <= {r['name'] for r in info}:
            raise ValueError(f'unsupported source contract: {table}')
        if table == 'flows' and not any(r['name'] == 'id' and r['type'].upper() == 'INTEGER'
                                         and r['pk'] == 1 for r in info):
            raise ValueError('flows.id must be INTEGER PRIMARY KEY')
        return db
    except BaseException:
        db.close()
        raise


def open_target(path, sources, config=DetectionConfig()):
    target = Path(path).resolve()
    for source in sources:
        src = Path(source).resolve()
        protected = [src, Path(str(src)+'-wal'), Path(str(src)+'-shm')]
        if any(target == p or (target.exists() and p.exists() and target.samefile(p)) for p in protected):
            raise ValueError('analytics target aliases source')
    db = sqlite3.connect(target, timeout=5)
    try:
        # Refuse existing unrelated DBs before applying any DDL.
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if tables:
            if 'analytics_metadata' not in tables or db.execute(
                    "SELECT value FROM analytics_metadata WHERE key='schema_version'").fetchone() != ('1',):
                raise ValueError('unsupported analytics database')
            signature_columns={r[1] for r in db.execute('PRAGMA table_info(signatures)')}
            if signature_columns and 'observed_ns' not in signature_columns:
                db.execute('ALTER TABLE signatures ADD COLUMN observed_ns INTEGER')
            if signature_columns and 'flow_id' not in signature_columns:
                db.execute('ALTER TABLE signatures ADD COLUMN flow_id INTEGER')
            gap_columns={r[1] for r in db.execute('PRAGMA table_info(source_gaps)')}
            if gap_columns and 'kind' not in gap_columns:
                db.execute("ALTER TABLE source_gaps ADD COLUMN kind TEXT NOT NULL DEFAULT 'internal'")
            if gap_columns and 'blocks_cleanup' not in gap_columns:
                db.execute('ALTER TABLE source_gaps ADD COLUMN blocks_cleanup INTEGER NOT NULL DEFAULT 1')
            if gap_columns:
                db.execute("UPDATE source_gaps SET kind='initial_boundary',blocks_cleanup=0 "
                           "WHERE after_id=0")
        db.executescript(SCHEMA.read_text())
        binding = json.dumps({'sources': [str(Path(s).resolve()) for s in sources],
                              'lan_if': config.lan_if, 'wan_if': config.wan_if,
                              'contract': 'end-time-utc-v1'}, sort_keys=True)
        old = db.execute("SELECT value FROM analytics_metadata WHERE key='binding'").fetchone()
        if old and old[0] != binding:
            raise ValueError('source/config binding changed; use a new analytics DB')
        db.execute("INSERT OR IGNORE INTO analytics_metadata VALUES('binding',?)", (binding,))
        db.commit()
        return db
    except BaseException:
        db.close()
        raise


def digest(row):
    return hashlib.sha256(json.dumps(dict(row),sort_keys=True).encode()).hexdigest()


def bootstrap_checkpoint(source,target,now=None):
    """Initialize a clean shadow at the current source maximum without replay."""
    now=time.time_ns() if now is None else now
    existing=target.execute("SELECT cursor FROM checkpoints WHERE source='flows'").fetchone()
    if existing is not None: return int(existing[0]),False
    if (target.execute('SELECT 1 FROM aggregates LIMIT 1').fetchone()
            or target.execute('SELECT 1 FROM signatures LIMIT 1').fetchone()):
        raise RuntimeError('refusing bootstrap over existing analytics evidence')
    source.execute('BEGIN')
    try:
        maximum=source.execute('SELECT coalesce(max(id),0) FROM flows').fetchone()[0]
        row=source.execute('SELECT * FROM flows WHERE id=?',(maximum,)).fetchone() if maximum else None
        boundary=digest(row) if row is not None else None
        high=0
        if row is not None:
            valid=valid_flow_interval(row['flow_start_ns'],row['flow_end_ns'],row['received_at_ns'])
            high=row['flow_end_ns'] if valid else row['received_at_ns']
        target.execute('BEGIN IMMEDIATE')
        target.execute("INSERT INTO checkpoints VALUES('flows',?,?,?,?)",
                       (str(maximum),boundary,now,high))
        target.execute("INSERT INTO runtime_health VALUES('flows',?,?,?,?)",
                       (now,0,maximum,maximum))
        target.execute("INSERT INTO analytics_metadata VALUES('bootstrap_flow_id',?)",
                       (str(maximum),))
        target.execute("INSERT INTO analytics_metadata VALUES('bootstrap_ns',?)",(str(now),))
        target.commit(); return maximum,True
    except BaseException:
        target.rollback(); raise
    finally:
        source.rollback()


def record_daily_metrics(db,now=None):
    now=time.time_ns() if now is None else now
    day=time.strftime('%Y-%m-%d',time.gmtime(now/10**9))
    scopes={row[0]:{'flows':row[1],'bytes':row[2],'packets':row[3]}
            for row in db.execute("SELECT scope,sum(flows),sum(bytes),sum(packets) "
                                  "FROM aggregates WHERE width_s=3600 GROUP BY scope")}
    page_size=db.execute('PRAGMA page_size').fetchone()[0]
    pages=db.execute('PRAGMA page_count').fetchone()[0]
    free=db.execute('PRAGMA freelist_count').fetchone()[0]
    checkpoint=db.execute("SELECT cursor FROM checkpoints WHERE source='flows'").fetchone()
    runtime=db.execute("SELECT source_max FROM runtime_health WHERE source='flows'").fetchone()
    retention=db.execute('SELECT closed_before_ns,deleted_total,late_outside_total,status,reason '
                         'FROM signature_retention').fetchone()
    payload={'checkpoint':int(checkpoint[0]) if checkpoint else None,
             'source_max':runtime[0] if runtime else None,
             'lag_ids':max(0,runtime[0]-int(checkpoint[0])) if runtime and checkpoint else None,
             'scopes':scopes,'signatures':db.execute('SELECT count(*) FROM signatures').fetchone()[0],
             'aggregate_rows':db.execute('SELECT count(*) FROM aggregates').fetchone()[0],
             'unknown_canonical':db.execute("SELECT coalesce(sum(flows),0) FROM aggregates "
                                            "WHERE width_s=3600 AND scope='canonical' "
                                            "AND device='unknown'").fetchone()[0],
             'dimensions':{'devices':db.execute("SELECT count(DISTINCT device) FROM aggregates "
                                                "WHERE scope='canonical'").fetchone()[0],
                           'peers':db.execute("SELECT count(DISTINCT peer) FROM aggregates "
                                              "WHERE scope='canonical'").fetchone()[0],
                           'services':db.execute("SELECT count(DISTINCT protocol||':'||port) FROM aggregates "
                                                 "WHERE scope='canonical'").fetchone()[0]},
             'sqlite':{'page_count':pages,'freelist_count':free,'page_size':page_size,
                       'allocated_bytes':pages*page_size,'reusable_bytes':free*page_size},
             'retention':dict(zip(('closed_before_ns','deleted_total','late_outside_total','status','reason'),
                                  retention))}
    encoded=json.dumps(payload,sort_keys=True,separators=(',',':'))
    db.execute('INSERT INTO daily_metrics VALUES(?,?,?) ON CONFLICT(day_utc) DO UPDATE SET '
               'captured_ns=excluded.captured_ns,payload_json=excluded.payload_json',(day,now,encoded))
    db.commit(); return payload


def peer_group(ip):
    address = ipaddress.ip_address(ip)
    return str(ipaddress.ip_network(f'{address}/{24 if address.version == 4 else 48}',strict=False))


def add(db, row, scope, device, direction, peer, protocol, port, stamp, provenance, late):
    byte, packet = row['bytes'], row['packets']
    valid = lambda v: isinstance(v,int) and v >= 0
    counters = (1, byte if valid(byte) else 0, packet if valid(packet) else 0,
                int(byte is None), int(packet is None),
                int(byte is not None and not valid(byte)) + int(packet is not None and not valid(packet)), int(late))
    names = ('flows','bytes','packets','missing_bytes','missing_packets','invalid_counters','late_flows')
    for width in (3600,86400):
        key = (scope,width,stamp//(width*10**9)*(width*10**9),device,direction,peer,
               protocol,port if port is not None else -1,provenance)
        db.execute('INSERT INTO aggregates VALUES('+','.join('?' for _ in range(16))+') '
                   'ON CONFLICT DO UPDATE SET '+','.join(f'{n}={n}+excluded.{n}' for n in names), key+counters)


def process_batch(source, target, batch_size=1000, config=DetectionConfig(), before_commit=None):
    if not 1 <= batch_size <= 10000:
        raise ValueError('batch size must be 1..10000')
    attempt=time.time_ns()
    if target.execute("SELECT 1 FROM worker_runtime WHERE worker='flows'").fetchone():
        target.execute("UPDATE worker_runtime SET heartbeat_ns=?,last_attempt_ns=? WHERE worker='flows'",
                       (attempt,attempt)); target.commit()
    target.execute('BEGIN IMMEDIATE')
    try:
        source.execute('BEGIN')
        state = target.execute("SELECT cursor,boundary_hash,high_id FROM checkpoints WHERE source='flows'").fetchone()
        checkpoint, boundary, high_time = (int(state[0]),state[1],state[2]) if state else (0,None,0)
        maximum = source.execute('SELECT coalesce(max(id),0) FROM flows').fetchone()[0]
        if checkpoint:
            row = source.execute('SELECT * FROM flows WHERE id=?',(checkpoint,)).fetchone()
            if maximum < checkpoint or row is None or digest(row) != boundary:
                raise RuntimeError('source boundary changed/missing; explicit recovery required')
        rows = source.execute('SELECT * FROM flows WHERE id>? ORDER BY id LIMIT ?',
                              (checkpoint,batch_size)).fetchall()
        for item in rows:
            row = dict(item)
            if row['schema_version'] != 1:
                raise ValueError('unsupported flow schema_version')
            if row['id'] > checkpoint+1:
                kind='initial_boundary' if checkpoint == 0 else 'internal'
                target.execute("INSERT OR IGNORE INTO source_gaps"
                               "(source,after_id,next_id,kind,blocks_cleanup) VALUES('flows',?,?,?,?)",
                               (checkpoint,row['id'],kind,int(kind == 'internal')))
            if not isinstance(row['received_at_ns'],int) or row['received_at_ns'] < 0:
                raise ValueError('invalid received timestamp; batch not advanced')
            provenance = row['flow_time_source']
            valid_time = valid_flow_interval(row['flow_start_ns'],row['flow_end_ns'],row['received_at_ns'])
            if provenance not in ('absolute','reconstructed','export_fallback') or not valid_time:
                provenance = 'invalid_fallback'
            stamp = row['flow_end_ns'] if valid_time else row['received_at_ns']
            late = stamp < high_time
            high_time = max(high_time,stamp)
            add(target,row,'raw','all','all','all',-1,-1,stamp,provenance,late)
            observation = normalize_traffic(row,config)
            if observation:
                closed_before=target.execute('SELECT closed_before_ns FROM signature_retention '
                                             'WHERE singleton=1').fetchone()[0]
                if stamp < closed_before:
                    scope='late_outside_horizon'
                    target.execute('UPDATE signature_retention SET late_outside_total=late_outside_total+1 '
                                   'WHERE singleton=1')
                else:
                    inserted = target.execute('INSERT OR IGNORE INTO signatures'
                                              '(signature,observed_ns,flow_id) VALUES(?,?,?)',
                                              (observation['signature'],stamp,row['id'])).rowcount
                    scope = 'canonical' if inserted else 'duplicate'
                add(target,row,scope,observation['device_id'],observation['direction'],
                    peer_group(observation['external_ip']),observation['protocol'],
                    observation['external_port'],stamp,provenance,late)
            else:
                add(target,row,'excluded','unknown','other','all',-1,-1,stamp,provenance,late)
            checkpoint = row['id']
            boundary = digest(item)
        now = time.time_ns()
        target.execute("INSERT INTO checkpoints VALUES('flows',?,?,?,?) ON CONFLICT(source) DO UPDATE SET "
                       'cursor=excluded.cursor,boundary_hash=excluded.boundary_hash,updated_ns=excluded.updated_ns,high_id=excluded.high_id',
                       (str(checkpoint),boundary,now,high_time))
        target.execute("INSERT INTO runtime_health VALUES('flows',?,?,?,?) ON CONFLICT(source) DO UPDATE SET "
                       'polled_ns=excluded.polled_ns,batch_count=excluded.batch_count,checkpoint=excluded.checkpoint,source_max=excluded.source_max',
                       (now,len(rows),checkpoint,maximum))
        pass_complete = checkpoint >= maximum
        target.execute("UPDATE worker_runtime SET state='healthy',heartbeat_ns=?,last_success_ns=?,"
                       "last_source_pass_completed_ns=CASE WHEN ? THEN ? "
                       "ELSE last_source_pass_completed_ns END,failure_type=NULL,failure_cause=NULL "
                       "WHERE worker='flows'",(now,now,pass_complete,now))
        target.execute('INSERT OR IGNORE INTO failure_reserve VALUES(1,zeroblob(65536))')
        if before_commit:
            before_commit()
        target.commit()
        return len(rows)
    except BaseException as error:
        target.rollback()
        if target.execute("SELECT 1 FROM worker_runtime WHERE worker='flows'").fetchone():
            worker_failed(target,error)
        raise
    finally:
        source.rollback()


def cleanup_signatures(source,target,horizon_s=7*24*60*60,limit=10000,now=None,
                       before_commit=None):
    """Close a dedupe horizon and delete only signatures older than it.

    The closure is based on a fully consumed, immutable ID snapshot.  Future
    rows whose event time falls behind the persisted closure are classified as
    late_outside_horizon instead of being counted as new canonical traffic.
    """
    if horizon_s <= 0 or not 1 <= limit <= 10000:
        raise ValueError('invalid signature retention settings')
    now=time.time_ns() if now is None else now
    source.execute('BEGIN')
    try:
        maximum=source.execute('SELECT coalesce(max(id),0) FROM flows').fetchone()[0]
        checkpoint=target.execute("SELECT cursor,boundary_hash,high_id FROM checkpoints "
                                  "WHERE source='flows'").fetchone()
        if checkpoint is None or int(checkpoint[0]) != maximum:
            raise RuntimeError('signature cleanup requires a complete source pass')
        if maximum:
            boundary=source.execute('SELECT * FROM flows WHERE id=?',(maximum,)).fetchone()
            if boundary is None or digest(boundary) != checkpoint[1]:
                raise RuntimeError('signature cleanup source boundary mismatch')
        if target.execute("SELECT 1 FROM source_gaps WHERE source='flows' AND blocks_cleanup=1 "
                          "LIMIT 1").fetchone():
            raise RuntimeError('signature cleanup blocked by unresolved source gap')
        cutoff=max(0,int(checkpoint[2])-horizon_s*10**9)
        target.execute('BEGIN IMMEDIATE')
        current=target.execute('SELECT closed_before_ns FROM signature_retention WHERE singleton=1').fetchone()[0]
        cutoff=max(current,cutoff)
        deleted=target.execute('DELETE FROM signatures WHERE signature IN ('
                               'SELECT signature FROM signatures WHERE observed_ns IS NOT NULL '
                               'AND observed_ns<? ORDER BY observed_ns LIMIT ?)',(cutoff,limit)).rowcount
        target.execute("UPDATE signature_retention SET closed_before_ns=?,last_cleanup_ns=?,"
                       "last_cleanup_checkpoint=?,deleted_total=deleted_total+?,status='complete',reason=? "
                       "WHERE singleton=1",(cutoff,now,maximum,deleted,
                       'horizon_closed' if cutoff>current else 'no_new_horizon'))
        if before_commit: before_commit()
        target.commit()
        return {'deleted':deleted,'closed_before_ns':cutoff,'checkpoint':maximum}
    except BaseException as error:
        target.rollback()
        kind,cause=safe_failure(error)
        target.execute("UPDATE signature_retention SET last_cleanup_ns=?,status='blocked',reason=? "
                       "WHERE singleton=1",(now,f'{kind}:{cause}')); target.commit()
        raise
    finally:
        source.rollback()


def run_signature_cleanup_cycle(source,target,horizon_s=7*24*60*60,limit=10000,
                                max_chunks=100):
    if not 1 <= max_chunks <= 1000:
        raise ValueError('invalid signature cleanup chunk count')
    total=0; last=None
    for _ in range(max_chunks):
        last=cleanup_signatures(source,target,horizon_s,limit)
        total+=last['deleted']
        if last['deleted'] < limit: break
    return {'deleted':total,'closed_before_ns':last['closed_before_ns'],
            'checkpoint':last['checkpoint']}


def _active_security_sweep(target,source,now):
    active=target.execute("SELECT sweep_id,cursor FROM security_sweeps "
                          "WHERE status='running' ORDER BY started_ns DESC LIMIT 1").fetchone()
    if active:
        target.execute("UPDATE security_sweeps SET status='failed',completed_ns=?,"
                       "failure_type='InterruptedSweep',failure_cause='prior process did not complete' "
                       "WHERE sweep_id=?",(now,active[0]))
        target.execute("UPDATE security_projection_v2 SET freshness='uncertain' WHERE sweep_id=?",
                       (active[0],))
    sweep=uuid.uuid4().hex
    checkpoint=source.execute('SELECT max(last_flow_id) FROM detector_checkpoints').fetchone()[0]
    count,maximum=source.execute('SELECT count(*),max(last_seen_ns) FROM security_events').fetchone()
    target.execute("INSERT INTO security_sweeps(sweep_id,status,started_ns,source_checkpoint,"
                   "source_event_count,source_max_event_ns,cursor) VALUES(?,'running',?,?,?,?,?)",
                   (sweep,now,checkpoint,count,maximum,''))
    # Starting a pass revokes the completeness claim of the previous copy.
    target.execute("UPDATE security_projection_v2 SET freshness='uncertain'")
    target.commit()
    return sweep,''


def project_security(source,target,batch_size=1000,before_commit=None):
    """One source read snapshot; only the final commit publishes current rows."""
    if not 1 <= batch_size <= 10000:
        raise ValueError('invalid batch size')
    now=time.time_ns(); sweep=None
    try:
        source.execute('BEGIN')
        sweep,after=_active_security_sweep(target,source,now)
        target.execute('BEGIN IMMEDIATE')
        total=0
        while True:
            rows=source.execute('SELECT '+','.join(SECURITY_COLUMNS)+
                                ' FROM security_events WHERE event_id>? ORDER BY event_id LIMIT ?',
                                (after,batch_size)).fetchall()
            if not rows: break
            for row in rows:
                event=dict(row); payload=json.dumps(event,sort_keys=True,separators=(',',':'))
                content=hashlib.sha256(payload.encode()).hexdigest()
                old=target.execute('SELECT first_projected_ns,content_hash FROM security_projection_v2 '
                                   'WHERE event_id=?',(event['event_id'],)).fetchone()
                first=old[0] if old else now
                target.execute('INSERT INTO security_projection_v2 VALUES('+','.join('?' for _ in range(18))+') '
                               'ON CONFLICT(event_id) DO UPDATE SET rule_id=excluded.rule_id,'
                               'decision_level=excluded.decision_level,severity=excluded.severity,'
                               'subject_id=excluded.subject_id,summary=excluded.summary,'
                               'detection_status=excluded.detection_status,resolution_status=excluded.resolution_status,'
                               'source_created_ns=excluded.source_created_ns,'
                               'source_first_seen_ns=excluded.source_first_seen_ns,'
                               'source_last_seen_ns=excluded.source_last_seen_ns,'
                               'last_verified_ns=excluded.last_verified_ns,source_sweep_completed_ns=NULL,'
                               'sweep_id=excluded.sweep_id,freshness=\'uncertain\','
                               'content_hash=excluded.content_hash,payload_json=excluded.payload_json',
                               (event['event_id'],event['rule_id'],event['decision_level'],event['severity'],
                                event['subject_id'],event['summary'],event['detection_status'],
                                event['resolution_status'],event['created_at_ns'],event['first_seen_ns'],
                                event['last_seen_ns'],first,now,None,sweep,'uncertain',content,payload))
                if old is None or old[1]!=content:
                    target.execute('INSERT OR IGNORE INTO security_projection_history('
                                   'event_id,captured_ns,sweep_id,content_hash,payload_json) VALUES(?,?,?,?,?)',
                                   (event['event_id'],now,sweep,content,payload))
            total+=len(rows); after=rows[-1]['event_id']
            target.execute("UPDATE security_sweeps SET cursor=? WHERE sweep_id=?",(after,sweep))
        for health in source.execute('SELECT * FROM detector_runtime_health'):
            target.execute('INSERT INTO detector_health_projection VALUES(?,?,?,?,?,?) '
                           'ON CONFLICT(source_name) DO UPDATE SET '
                           'last_successful_poll_ns=excluded.last_successful_poll_ns,'
                           'last_progress_ns=excluded.last_progress_ns,last_batch_count=excluded.last_batch_count,'
                           'last_checkpoint=excluded.last_checkpoint,refreshed_ns=excluded.refreshed_ns',
                           tuple(health)+(now,))
        completed=time.time_ns()
        target.execute("UPDATE security_projection_v2 SET freshness='historical' WHERE sweep_id<>?",(sweep,))
        target.execute("UPDATE security_projection_v2 SET freshness='current',"
                       "source_sweep_completed_ns=? WHERE sweep_id=?",(completed,sweep))
        target.execute("UPDATE security_sweeps SET status='complete',completed_ns=?,cursor='' WHERE sweep_id=?",
                       (completed,sweep))
        target.execute("INSERT INTO analytics_metadata VALUES('security_sweep_completed_ns',?) "
                       'ON CONFLICT(key) DO UPDATE SET value=excluded.value',(str(completed),))
        target.execute("INSERT INTO checkpoints VALUES('security',?,NULL,?,0) ON CONFLICT(source) DO UPDATE SET "
                       'cursor=excluded.cursor,updated_ns=excluded.updated_ns',('',completed))
        if before_commit:
            before_commit()
        target.commit()
        return total
    except BaseException as error:
        target.rollback()
        kind,cause=safe_failure(error)
        if sweep is not None:
            target.execute("UPDATE security_sweeps SET status='failed',completed_ns=?,failure_type=?,"
                           "failure_cause=? WHERE sweep_id=?",(time.time_ns(),kind,cause,sweep))
            target.execute("UPDATE security_projection_v2 SET freshness='uncertain' WHERE sweep_id=?",
                           (sweep,)); target.commit()
        raise
    finally:
        source.rollback()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('flows_db'); parser.add_argument('analytics_db')
    parser.add_argument('--max-batches',type=int,default=100)
    parser.add_argument('--security-db'); parser.add_argument('--batch-size',type=int,default=1000)
    parser.add_argument('--health',action='store_true')
    parser.add_argument('--stale-seconds',type=int,default=90)
    parser.add_argument('--signature-horizon-seconds',type=int,default=604800)
    parser.add_argument('--signature-cleanup-limit',type=int,default=10000)
    parser.add_argument('--signature-cleanup-max-chunks',type=int,default=100)
    args = parser.parse_args()
    if args.max_batches < 1:
        parser.error('--max-batches must be positive')
    sources = [args.flows_db] + ([args.security_db] if args.security_db else [])
    with closing(readonly(args.flows_db,'flows',('id',)+COLUMNS)) as flows:
        with closing(open_target(args.analytics_db,sources)) as target:
            if args.health:
                print(json.dumps(worker_health(target,now=time.time_ns(),
                                               stale_s=args.stale_seconds),sort_keys=True))
                return
            start_worker(target)
            try:
                for _ in range(args.max_batches):
                    if not process_batch(flows,target,args.batch_size):
                        break
                health=target.execute("SELECT checkpoint,source_max FROM runtime_health "
                                      "WHERE source='flows'").fetchone()
                if health and health[0] == health[1]:
                    run_signature_cleanup_cycle(flows,target,args.signature_horizon_seconds,
                                                args.signature_cleanup_limit,
                                                args.signature_cleanup_max_chunks)
                if args.security_db:
                    with closing(readonly(args.security_db,'security_events',SECURITY_COLUMNS)) as security:
                        project_security(security,target,args.batch_size)
            except BaseException as error:
                state=target.execute("SELECT state FROM worker_runtime WHERE worker='flows'").fetchone()
                if state is not None and state[0] != 'failed':
                    worker_failed(target,error)
                raise

if __name__ == '__main__':
    main()
