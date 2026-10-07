PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS flows (
    id                    INTEGER PRIMARY KEY,
    schema_version        INTEGER NOT NULL DEFAULT 1,

    received_at_ns        INTEGER NOT NULL,
    exporter_ip           TEXT NOT NULL,
    sequence_num          INTEGER,

    flow_start_ns         INTEGER,
    flow_end_ns           INTEGER,

    src_ip                TEXT NOT NULL,
    dst_ip                TEXT NOT NULL,
    src_port              INTEGER,
    dst_port              INTEGER,
    protocol              INTEGER NOT NULL,

    ingress_if            INTEGER,
    egress_if             INTEGER,
    next_hop              TEXT,

    src_mac               TEXT,
    dst_mac               TEXT,

    bytes                 INTEGER,
    packets               INTEGER,
    tcp_flags             INTEGER,

    observation_domain_id INTEGER
);

CREATE INDEX IF NOT EXISTS idx_flows_received
    ON flows(received_at_ns);

CREATE INDEX IF NOT EXISTS idx_flows_src
    ON flows(src_ip, received_at_ns);

CREATE INDEX IF NOT EXISTS idx_flows_dst
    ON flows(dst_ip, received_at_ns);
