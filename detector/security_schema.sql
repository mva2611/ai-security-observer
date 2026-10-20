PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT OR IGNORE INTO schema_metadata VALUES ('schema_version', '1');

CREATE TABLE IF NOT EXISTS detector_runtime_health (
    source_name TEXT PRIMARY KEY,
    last_successful_poll_ns INTEGER NOT NULL,
    last_progress_ns INTEGER NOT NULL,
    last_batch_count INTEGER NOT NULL CHECK(last_batch_count >= 0),
    last_checkpoint INTEGER NOT NULL CHECK(last_checkpoint >= 0)
);

CREATE TABLE IF NOT EXISTS canonical_flows (
    flow_signature TEXT PRIMARY KEY,
    flow_id INTEGER NOT NULL,
    device_id TEXT NOT NULL,
    direction TEXT NOT NULL CHECK(direction IN ('outbound','inbound')),
    observed_at_ns INTEGER NOT NULL,
    processed_at_ns INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS detector_maintenance (
    task_name TEXT PRIMARY KEY,
    last_run_ns INTEGER NOT NULL,
    last_deleted_count INTEGER NOT NULL CHECK(last_deleted_count >= 0)
);

CREATE TABLE IF NOT EXISTS observed_peers (
    device_id TEXT NOT NULL,
    peer_group TEXT NOT NULL,
    protocol INTEGER NOT NULL,
    external_port INTEGER NOT NULL,
    first_seen_ns INTEGER NOT NULL,
    last_seen_ns INTEGER NOT NULL,
    flow_count INTEGER NOT NULL,
    PRIMARY KEY(device_id, peer_group, protocol, external_port)
);

CREATE TABLE IF NOT EXISTS device_observation_state (
    device_id TEXT PRIMARY KEY,
    flow_count INTEGER NOT NULL,
    first_seen_ns INTEGER NOT NULL,
    last_seen_ns INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS communication_profile_changes (
    change_key TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    first_seen_ns INTEGER NOT NULL,
    last_seen_ns INTEGER NOT NULL,
    peer_group TEXT NOT NULL,
    transport_scope TEXT NOT NULL,
    external_port INTEGER NOT NULL,
    first_flow_id INTEGER NOT NULL,
    occurrence_count INTEGER NOT NULL,
    details_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS fanout_observations (
    device_id TEXT NOT NULL,
    window_start_ns INTEGER NOT NULL,
    flow_signature TEXT NOT NULL UNIQUE,
    external_ip TEXT NOT NULL,
    external_port INTEGER,
    flow_id INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fanout_device_window
    ON fanout_observations(device_id, window_start_ns);

CREATE TABLE IF NOT EXISTS detector_checkpoints (
    source_name TEXT PRIMARY KEY,
    last_flow_id INTEGER NOT NULL CHECK (last_flow_id >= 0),
    updated_at_ns INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS source_gaps (
    id INTEGER PRIMARY KEY,
    source_name TEXT NOT NULL,
    missing_after_id INTEGER NOT NULL,
    next_present_id INTEGER NOT NULL,
    detected_at_ns INTEGER NOT NULL,
    UNIQUE(source_name, missing_after_id, next_present_id)
);

CREATE TABLE IF NOT EXISTS security_events (
    event_id TEXT PRIMARY KEY,
    dedup_key TEXT NOT NULL UNIQUE,
    created_at_ns INTEGER NOT NULL,
    first_seen_ns INTEGER NOT NULL,
    last_seen_ns INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    decision_level TEXT NOT NULL CHECK(decision_level IN ('observe','review','contain')),
    severity TEXT NOT NULL CHECK(severity IN ('info','low','medium','high')),
    subject_type TEXT NOT NULL,
    subject_id TEXT,
    observed_ip TEXT,
    observed_mac TEXT,
    summary TEXT NOT NULL,
    detection_status TEXT NOT NULL CHECK(detection_status IN ('open','suppressed','acknowledged','closed')),
    resolution_status TEXT NOT NULL CHECK(resolution_status IN ('unresolved','benign','accepted_risk','resolved','unknown')),
    rule_context_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS event_evidence (
    evidence_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL REFERENCES security_events(event_id),
    evidence_type TEXT NOT NULL CHECK(evidence_type IN ('flow','aggregate','inventory','external')),
    flow_id INTEGER,
    first_flow_id INTEGER,
    last_flow_id INTEGER,
    window_start_ns INTEGER,
    window_end_ns INTEGER,
    bytes INTEGER,
    packets INTEGER,
    evidence_json TEXT NOT NULL,
    evidence_hash TEXT
);

CREATE TABLE IF NOT EXISTS decisions (
    decision_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL REFERENCES security_events(event_id),
    decided_at_ns INTEGER NOT NULL,
    decision_level TEXT NOT NULL CHECK(decision_level IN ('observe','review','contain')),
    decided_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    proposed_action_json TEXT,
    approval_required INTEGER NOT NULL CHECK(approval_required IN (0,1))
);

CREATE TABLE IF NOT EXISTS action_attempts (
    action_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL REFERENCES security_events(event_id),
    decision_id TEXT REFERENCES decisions(decision_id),
    action_type TEXT NOT NULL,
    target_json TEXT NOT NULL,
    requested_at_ns INTEGER NOT NULL,
    expires_at_ns INTEGER,
    status TEXT NOT NULL CHECK(status IN ('proposed','approved','executing','applied','verified','failed','expired','rolled_back')),
    result_json TEXT,
    verified_at_ns INTEGER,
    rolled_back_at_ns INTEGER
);

CREATE TABLE IF NOT EXISTS admin_reviews (
    review_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL REFERENCES security_events(event_id),
    reviewed_at_ns INTEGER NOT NULL,
    reviewer TEXT NOT NULL,
    verdict TEXT NOT NULL CHECK(verdict IN ('benign','incident','accepted_risk','unresolved')),
    comment TEXT,
    severity_override TEXT,
    action_approval TEXT CHECK(action_approval IN ('approved','rejected') OR action_approval IS NULL)
);

CREATE TABLE IF NOT EXISTS rule_state (
    rule_id TEXT NOT NULL,
    state_key TEXT NOT NULL,
    state_json TEXT NOT NULL,
    updated_at_ns INTEGER NOT NULL,
    PRIMARY KEY(rule_id, state_key)
);

CREATE TABLE IF NOT EXISTS baseline_buckets (
    rule_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    bucket_key TEXT NOT NULL,
    baseline_json TEXT NOT NULL,
    updated_at_ns INTEGER NOT NULL,
    PRIMARY KEY(rule_id, subject_id, bucket_key)
);
