#!/bin/sh
set -eu

python3 -m detector.bootstrap /flows/flows.db /state/security.db

exec python3 -m detector.security_reader \
  /flows/flows.db /state/security.db \
  --batch-size "${BATCH_SIZE:-1000}" \
  --poll-seconds "${POLL_SECONDS:-5}" \
  --lan-if "${LAN_IF:-10}" \
  --wan-if "${WAN_IF:-8}" \
  --r2-learning-flows "${R2_LEARNING_FLOWS:-1000}" \
  --r2-learning-seconds "${R2_LEARNING_SECONDS:-172800}" \
  --r4-window-seconds "${R4_WINDOW_SECONDS:-600}" \
  --r4-destination-threshold "${R4_DESTINATION_THRESHOLD:-120}" \
  --r4-port-threshold "${R4_PORT_THRESHOLD:-25}" \
  --r4-min-flows "${R4_MIN_FLOWS:-20}" \
  --canonical-retention-seconds "${CANONICAL_RETENTION_SECONDS:-604800}" \
  --cleanup-interval-seconds "${CLEANUP_INTERVAL_SECONDS:-3600}" \
  --cleanup-limit "${CLEANUP_LIMIT:-10000}" \
  --cleanup-max-chunks "${CLEANUP_MAX_CHUNKS:-100}" \
  --heartbeat-seconds "${HEARTBEAT_SECONDS:-300}"
