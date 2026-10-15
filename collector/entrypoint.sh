#!/bin/sh
set -eu

FIFO=/tmp/goflow2.json

mkfifo "$FIFO"

/usr/local/bin/goflow2 -addr ':18080' -listen 'netflow://:12055/?workers=1' \
    -format json -mapping /app/goflow2-mapping.yaml > "$FIFO" &
GOFLOW_PID=$!

python3 /app/flowstore.py /data/flows.db < "$FIFO" &
FLOWSTORE_PID=$!

cleanup() {
    # Closing the FIFO writer lets FlowStore observe EOF and commit its final
    # partial batch before it is forcefully terminated.
    kill "$GOFLOW_PID" 2>/dev/null || true
    wait "$GOFLOW_PID" 2>/dev/null || true

    # Covers the existing SQLite lock retry budget (1+2+4 seconds) with room
    # for transaction and scheduler latency.
    remaining=10
    while kill -0 "$FLOWSTORE_PID" 2>/dev/null && [ "$remaining" -gt 0 ]; do
        sleep 1
        remaining=$((remaining - 1))
    done

    kill "$FLOWSTORE_PID" 2>/dev/null || true
    sleep 1
    kill -KILL "$FLOWSTORE_PID" 2>/dev/null || true
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
