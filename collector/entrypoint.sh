#!/bin/sh
set -eu

FIFO=/tmp/goflow2.json

mkfifo "$FIFO"

/usr/local/bin/goflow2 -addr ':18080' -listen 'netflow://:12055/?workers=1' -format json > "$FIFO" &
GOFLOW_PID=$!

python3 /app/flowstore.py /data/flows.db < "$FIFO" &
FLOWSTORE_PID=$!

cleanup() {
    kill "$GOFLOW_PID" "$FLOWSTORE_PID" 2>/dev/null || true
    sleep 1
    kill -KILL "$GOFLOW_PID" "$FLOWSTORE_PID" 2>/dev/null || true
    wait "$GOFLOW_PID" 2>/dev/null || true
    wait "$FLOWSTORE_PID" 2>/dev/null || true
    rm -f "$FIFO"
}

trap cleanup EXIT INT TERM

while kill -0 "$GOFLOW_PID" 2>/dev/null && kill -0 "$FLOWSTORE_PID" 2>/dev/null; do
    sleep 1
done

cleanup
trap - EXIT INT TERM

exit 1
