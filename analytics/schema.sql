PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
CREATE TABLE IF NOT EXISTS analytics_metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
INSERT OR IGNORE INTO analytics_metadata VALUES('schema_version','1');
CREATE TABLE IF NOT EXISTS checkpoints(
 source TEXT PRIMARY KEY, cursor TEXT NOT NULL, boundary_hash TEXT,
 updated_ns INTEGER NOT NULL, high_id INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS source_gaps(
 source TEXT NOT NULL, after_id INTEGER NOT NULL, next_id INTEGER NOT NULL,
 kind TEXT NOT NULL DEFAULT 'internal', blocks_cleanup INTEGER NOT NULL DEFAULT 1,
 PRIMARY KEY(source,after_id,next_id));
CREATE TABLE IF NOT EXISTS signatures(
 signature TEXT PRIMARY KEY, observed_ns INTEGER, flow_id INTEGER);
CREATE INDEX IF NOT EXISTS idx_signatures_observed ON signatures(observed_ns);
CREATE TABLE IF NOT EXISTS signature_retention(
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 closed_before_ns INTEGER NOT NULL DEFAULT 0,
 last_cleanup_ns INTEGER, last_cleanup_checkpoint INTEGER,
 deleted_total INTEGER NOT NULL DEFAULT 0,
 late_outside_total INTEGER NOT NULL DEFAULT 0,
 status TEXT NOT NULL DEFAULT 'initializing', reason TEXT NOT NULL DEFAULT 'never_evaluated');
INSERT OR IGNORE INTO signature_retention(singleton) VALUES(1);
CREATE TABLE IF NOT EXISTS daily_metrics(
 day_utc TEXT PRIMARY KEY, captured_ns INTEGER NOT NULL, payload_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS aggregates(
 scope TEXT NOT NULL, width_s INTEGER NOT NULL, start_ns INTEGER NOT NULL,
 device TEXT NOT NULL, direction TEXT NOT NULL, peer TEXT NOT NULL,
 protocol INTEGER NOT NULL, port INTEGER NOT NULL, time_source TEXT NOT NULL,
 flows INTEGER NOT NULL, bytes INTEGER NOT NULL, packets INTEGER NOT NULL,
 missing_bytes INTEGER NOT NULL, missing_packets INTEGER NOT NULL,
 invalid_counters INTEGER NOT NULL, late_flows INTEGER NOT NULL,
 PRIMARY KEY(scope,width_s,start_ns,device,direction,peer,protocol,port,time_source));
CREATE TABLE IF NOT EXISTS runtime_health(
 source TEXT PRIMARY KEY, polled_ns INTEGER NOT NULL, batch_count INTEGER NOT NULL,
 checkpoint INTEGER NOT NULL, source_max INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS security_projection(
 event_id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, decision_level TEXT NOT NULL,
 severity TEXT NOT NULL, subject_id TEXT, summary TEXT NOT NULL,
 detection_status TEXT NOT NULL, resolution_status TEXT NOT NULL,
 first_seen_ns INTEGER NOT NULL,last_seen_ns INTEGER NOT NULL,
 refreshed_ns INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS baseline_models(
 model_version TEXT NOT NULL, subject_id TEXT NOT NULL, training_start_ns INTEGER NOT NULL,
 training_end_ns INTEGER NOT NULL, status TEXT NOT NULL CHECK(status IN ('prepared','validated')),
 parameters_json TEXT NOT NULL, PRIMARY KEY(model_version,subject_id));
CREATE VIEW IF NOT EXISTS presentation_health AS
 SELECT h.*, source_max-checkpoint AS pending_id_span,
 (SELECT count(*) FROM source_gaps g WHERE g.source=h.source) AS numeric_gap_count
 FROM runtime_health h;
CREATE VIEW IF NOT EXISTS presentation_security AS SELECT *,
 'detector observation; not proof of incident or connection success' AS limitation
 FROM security_projection;
CREATE VIEW IF NOT EXISTS baseline_hourly_inputs AS
 SELECT *, (start_ns/3600000000000)%24 AS utc_hour,
 ((start_ns/86400000000000)+3)%7 AS weekday_monday_zero
 FROM aggregates WHERE scope='canonical' AND width_s=3600;
CREATE VIEW IF NOT EXISTS presentation_overview AS
 SELECT scope,width_s,start_ns,sum(flows) AS flows,sum(bytes) AS bytes,
 sum(packets) AS packets,sum(missing_bytes) AS missing_bytes,
 sum(missing_packets) AS missing_packets,sum(invalid_counters) AS invalid_counters,
 sum(late_flows) AS late_flows FROM aggregates GROUP BY scope,width_s,start_ns;

CREATE TABLE IF NOT EXISTS detector_health_projection(
 source_name TEXT PRIMARY KEY, last_successful_poll_ns INTEGER NOT NULL,
 last_progress_ns INTEGER NOT NULL, last_batch_count INTEGER NOT NULL,
 last_checkpoint INTEGER NOT NULL, refreshed_ns INTEGER NOT NULL);
CREATE VIEW IF NOT EXISTS presentation_detector_health AS
 SELECT *, 'source snapshot; freshness must be evaluated by reader' AS limitation
 FROM detector_health_projection;

-- Runtime truth is deliberately separate from the last successful batch.
-- A new process incarnation starts as initializing and a missing heartbeat is
-- evaluated as stale by the reader; an old success can therefore never imply
-- that the current worker is healthy.
CREATE TABLE IF NOT EXISTS worker_runtime(
 worker TEXT PRIMARY KEY, incarnation TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('initializing','healthy','failed','stopped')),
 started_ns INTEGER NOT NULL, heartbeat_ns INTEGER NOT NULL,
 last_attempt_ns INTEGER, last_success_ns INTEGER,
 last_source_pass_completed_ns INTEGER,
 last_failure_ns INTEGER, failure_type TEXT, failure_cause TEXT);

CREATE TABLE IF NOT EXISTS security_sweeps(
 sweep_id TEXT PRIMARY KEY, status TEXT NOT NULL
  CHECK(status IN ('running','complete','failed')),
 started_ns INTEGER NOT NULL, completed_ns INTEGER,
 source_checkpoint INTEGER, source_event_count INTEGER,
 source_max_event_ns INTEGER, cursor TEXT NOT NULL DEFAULT '',
 failure_type TEXT, failure_cause TEXT);

CREATE TABLE IF NOT EXISTS security_projection_v2(
 event_id TEXT PRIMARY KEY, rule_id TEXT NOT NULL,
 decision_level TEXT NOT NULL, severity TEXT NOT NULL, subject_id TEXT,
 summary TEXT NOT NULL, detection_status TEXT NOT NULL,
 resolution_status TEXT NOT NULL,
 source_created_ns INTEGER NOT NULL, source_first_seen_ns INTEGER NOT NULL,
 source_last_seen_ns INTEGER NOT NULL, first_projected_ns INTEGER NOT NULL,
 last_verified_ns INTEGER NOT NULL, source_sweep_completed_ns INTEGER,
 sweep_id TEXT NOT NULL, freshness TEXT NOT NULL
  CHECK(freshness IN ('current','historical','uncertain')),
 content_hash TEXT NOT NULL, payload_json TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS security_projection_history(
 history_id INTEGER PRIMARY KEY, event_id TEXT NOT NULL,
 captured_ns INTEGER NOT NULL, sweep_id TEXT NOT NULL,
 content_hash TEXT NOT NULL, payload_json TEXT NOT NULL,
 UNIQUE(event_id,content_hash));

CREATE VIEW IF NOT EXISTS presentation_worker_health AS
 SELECT *, 'stored state; caller must enforce heartbeat expiry' AS limitation
 FROM worker_runtime;

CREATE VIEW IF NOT EXISTS presentation_security_v2 AS
 SELECT p.*,s.status AS sweep_status,s.started_ns AS sweep_started_ns,
 s.completed_ns AS sweep_completed_ns,
 'current only when freshness=current and sweep_status=complete' AS limitation
 FROM security_projection_v2 p LEFT JOIN security_sweeps s USING(sweep_id);

-- Space released on a write failure gives the worker a bounded chance to
-- persist its sanitized failure state even when SQLite reports SQLITE_FULL.
CREATE TABLE IF NOT EXISTS failure_reserve(
 id INTEGER PRIMARY KEY CHECK(id=1), reserve BLOB NOT NULL);
INSERT OR IGNORE INTO failure_reserve VALUES(1,zeroblob(65536));
