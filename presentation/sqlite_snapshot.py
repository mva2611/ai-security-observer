"""Publish a consistent read-only presentation copy of analytics.db."""
import argparse
import os
from pathlib import Path
import signal
import sqlite3
import threading
import time


def snapshot(source, destination):
    source_uri=Path(source).resolve().as_uri()+'?mode=ro'
    destination=Path(destination); temporary=destination.with_suffix('.db.next')
    if temporary.exists(): temporary.unlink()
    with sqlite3.connect(source_uri,uri=True,timeout=5) as src, sqlite3.connect(temporary) as dst:
        src.execute('PRAGMA query_only=ON'); src.backup(dst)
        if dst.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
            raise RuntimeError('presentation snapshot integrity failed')
        dst.execute('PRAGMA journal_mode=DELETE'); dst.commit()
    os.chmod(temporary,0o444); os.replace(temporary,destination)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source'); parser.add_argument('destination')
    parser.add_argument('--interval',type=int,default=60)
    args=parser.parse_args(); stop=threading.Event()
    signal.signal(signal.SIGTERM,lambda *_:stop.set())
    signal.signal(signal.SIGINT,lambda *_:stop.set())
    while not stop.is_set():
        try:
            snapshot(args.source,args.destination)
            print(f'presentation_snapshot_ok at_ns={time.time_ns()}',flush=True)
        except BaseException as error:
            print(f'presentation_snapshot_failed type={type(error).__name__}',flush=True)
        stop.wait(args.interval)


if __name__=='__main__': main()
