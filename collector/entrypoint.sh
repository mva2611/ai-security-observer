#!/bin/sh
set -eu

FIFO=${FLOWSTORE_FIFO:-/tmp/goflow2.json}
GOFLOW2_BIN=${GOFLOW2_BIN:-/usr/local/bin/goflow2}
FLOWSTORE_BIN=${FLOWSTORE_BIN:-/app/flowstore.py}
FLOWSTORE_DB=${FLOWSTORE_DB:-/data/flows.db}
PYTHON_BIN=${PYTHON_BIN:-python3}

mkfifo "$FIFO"

"$GOFLOW2_BIN" -addr ':18080' -listen 'netflow://:12055/?workers=1' \
    -format json -mapping /app/goflow2-mapping.yaml > "$FIFO" &
GOFLOW_PID=$!

"$PYTHON_BIN" "$FLOWSTORE_BIN" "$FLOWSTORE_DB" < "$FIFO" &
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

graceful_shutdown() {
    # Preserve a successful exit status for an explicit container stop. The
    # EXIT trap performs the actual child shutdown and final FlowStore flush.
    exit 0
}

trap cleanup EXIT
trap graceful_shutdown INT TERM

while kill -0 "$GOFLOW_PID" 2>/dev/null && kill -0 "$FLOWSTORE_PID" 2>/dev/null; do
    sleep 1
done

# A child disappearing without an explicit stop request is a runtime failure.
# The EXIT trap still tears down its peer and flushes anything recoverable.
exit 1
