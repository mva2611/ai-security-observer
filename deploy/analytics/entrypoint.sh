#!/bin/sh
set -eu

exec nice -n 10 python3 -m analytics.runtime \
  /flows/flows.db /security/security.db /state/analytics.db \
  --bootstrap-current \
  --batch-size "${BATCH_SIZE:-1000}" \
  --max-batches-per-cycle "${MAX_BATCHES_PER_CYCLE:-10}" \
  --poll-seconds "${POLL_SECONDS:-5}" \
  --stale-seconds "${STALE_SECONDS:-90}" \
  --security-interval-seconds "${SECURITY_INTERVAL_SECONDS:-300}" \
  --metrics-interval-seconds "${METRICS_INTERVAL_SECONDS:-300}" \
  --signature-horizon-seconds "${SIGNATURE_HORIZON_SECONDS:-604800}" \
  --cleanup-interval-seconds "${CLEANUP_INTERVAL_SECONDS:-3600}" \
  --cleanup-limit "${CLEANUP_LIMIT:-10000}" \
  --cleanup-max-chunks "${CLEANUP_MAX_CHUNKS:-100}" \
  --max-database-bytes "${MAX_DATABASE_BYTES:-1610612736}" \
  --log-file /state/analytics-runtime.jsonl
