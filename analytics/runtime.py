"""Long-running isolated shadow analytics worker."""
import argparse
from contextlib import closing
import json
from pathlib import Path
import signal
import sqlite3
import threading
import time

from collector.flowstore import COLUMNS
from .shadow import (SECURITY_COLUMNS,bootstrap_checkpoint,cleanup_signatures,
                     open_target,process_batch,project_security,readonly,
                     record_daily_metrics,run_signature_cleanup_cycle,safe_failure,
                     start_worker,stop_worker,worker_failed,worker_health)


def emit(event,log_file=None,**fields):
    record={'at_ns':time.time_ns(),'event':event,**fields}
    line=json.dumps(record,sort_keys=True,separators=(',',':'))
    print(line,flush=True)
    if log_file:
        with Path(log_file).open('a',encoding='utf-8') as handle:
            handle.write(line+'\n'); handle.flush()


def allocated_database_bytes(db):
    page_size=int(db.execute('PRAGMA page_size').fetchone()[0])
    page_count=int(db.execute('PRAGMA page_count').fetchone()[0])
    return page_size*page_count


def run(args,stop=None):
    stop=stop or threading.Event()
    sources=[args.flows_db,args.security_db]
    with closing(readonly(args.flows_db,'flows',('id',)+COLUMNS)) as flows, \
         closing(readonly(args.security_db,'security_events',SECURITY_COLUMNS)) as security, \
         closing(open_target(args.analytics_db,sources)) as target:
        incarnation=start_worker(target)
        checkpoint,created=bootstrap_checkpoint(flows,target) if args.bootstrap_current else (
            int(target.execute("SELECT coalesce((SELECT cursor FROM checkpoints WHERE source='flows'),'0')").fetchone()[0]),False)
        emit('started',args.log_file,incarnation=incarnation,checkpoint=checkpoint,
             initialized=created,mode='shadow')
        last_security=last_cleanup=last_metrics=0
        processed_since=0; started=time.monotonic()
        try:
            while not stop.is_set():
                cycle=0
                for _ in range(args.max_batches_per_cycle):
                    if stop.is_set(): break
                    count=process_batch(flows,target,args.batch_size)
                    cycle+=count; processed_since+=count
                    if count == 0: break
                now=time.time_ns()
                health=worker_health(target,now=now,stale_s=args.stale_seconds)
                caught=target.execute("SELECT checkpoint=source_max FROM runtime_health "
                                      "WHERE source='flows'").fetchone()
                if caught and caught[0] and now-last_cleanup >= args.cleanup_interval_seconds*10**9:
                    cleanup=run_signature_cleanup_cycle(flows,target,args.signature_horizon_seconds,
                                                        args.cleanup_limit,args.cleanup_max_chunks)
                    last_cleanup=now; emit('cleanup',args.log_file,**cleanup)
                if now-last_security >= args.security_interval_seconds*10**9:
                    events=project_security(security,target,args.batch_size)
                    last_security=now; emit('security_sweep',args.log_file,events=events)
                if now-last_metrics >= args.metrics_interval_seconds*10**9:
                    metrics=record_daily_metrics(target,now)
                    elapsed=max(.001,time.monotonic()-started)
                    emit('metrics',args.log_file,processed=processed_since,
                         throughput=round(processed_since/elapsed,3),health=health,metrics=metrics)
                    processed_since=0; started=time.monotonic(); last_metrics=now
                allocated=allocated_database_bytes(target)
                if args.max_database_bytes and allocated > args.max_database_bytes:
                    raise RuntimeError('analytics database capacity limit exceeded')
                if cycle == args.batch_size*args.max_batches_per_cycle:
                    continue
                stop.wait(args.poll_seconds)
            stop_worker(target); emit('stopped',args.log_file,reason='signal')
            return 0
        except BaseException as error:
            state=target.execute("SELECT state FROM worker_runtime WHERE worker='flows'").fetchone()
            if state is not None and state[0] != 'failed': worker_failed(target,error)
            kind,cause=safe_failure(error); emit('failed',args.log_file,error_type=kind,cause=cause)
            return 1


def parser():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('flows_db'); p.add_argument('security_db'); p.add_argument('analytics_db')
    p.add_argument('--bootstrap-current',action='store_true')
    p.add_argument('--batch-size',type=int,default=1000)
    p.add_argument('--max-batches-per-cycle',type=int,default=10)
    p.add_argument('--poll-seconds',type=float,default=5)
    p.add_argument('--stale-seconds',type=int,default=90)
    p.add_argument('--security-interval-seconds',type=int,default=300)
    p.add_argument('--metrics-interval-seconds',type=int,default=300)
    p.add_argument('--signature-horizon-seconds',type=int,default=604800)
    p.add_argument('--cleanup-interval-seconds',type=int,default=3600)
    p.add_argument('--cleanup-limit',type=int,default=10000)
    p.add_argument('--cleanup-max-chunks',type=int,default=100)
    p.add_argument('--max-database-bytes',type=int,default=1610612736)
    p.add_argument('--log-file')
    return p


def main():
    args=parser().parse_args(); stop=threading.Event()
    def requested(signum,frame): stop.set()
    signal.signal(signal.SIGTERM,requested); signal.signal(signal.SIGINT,requested)
    raise SystemExit(run(args,stop))


if __name__=='__main__': main()
