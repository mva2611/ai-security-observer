"""Read-only healthcheck for the shadow analytics worker."""
import argparse
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import time

from .shadow import worker_health


def inspect(path,stale_seconds=90,now=None):
    uri=Path(path).resolve().as_uri()+'?mode=ro'
    with closing(sqlite3.connect(uri,uri=True,timeout=1)) as db:
        db.row_factory=sqlite3.Row; db.execute('PRAGMA query_only=ON')
        result=worker_health(db,now=time.time_ns() if now is None else now,
                             stale_s=stale_seconds)
        result['integrity']=db.execute('PRAGMA quick_check').fetchone()[0]
        checkpoint=db.execute("SELECT cursor FROM checkpoints WHERE source='flows'").fetchone()
        runtime=db.execute("SELECT source_max FROM runtime_health WHERE source='flows'").fetchone()
        result['checkpoint']=int(checkpoint[0]) if checkpoint else None
        result['source_max']=runtime[0] if runtime else None
        result['lag_ids']=max(0,result['source_max']-result['checkpoint']) \
            if checkpoint and runtime else None
        return result


def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('analytics_db')
    p.add_argument('--stale-seconds',type=int,default=90); args=p.parse_args()
    try: result=inspect(args.analytics_db,args.stale_seconds)
    except BaseException as error:
        print(json.dumps({'state':'failed','reason':type(error).__name__})); raise SystemExit(1)
    print(json.dumps(result,sort_keys=True))
    raise SystemExit(0 if result['state']=='healthy' and result['integrity']=='ok' else 1)


if __name__=='__main__': main()
