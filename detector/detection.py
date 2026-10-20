import hashlib
import ipaddress
import json
from dataclasses import dataclass


@dataclass(frozen=True)
class DetectionConfig:
    lan_if: int = 10
    wan_if: int = 8
    r2_ipv4_prefix: int = 24
    r2_ipv6_prefix: int = 48
    r2_learning_flows: int = 1000
    r2_learning_seconds: int = 48 * 60 * 60
    r4_window_seconds: int = 600
    r4_destination_threshold: int = 120
    r4_port_threshold: int = 25
    r4_min_flows: int = 20

    def __post_init__(self):
        values = {
            "lan_if": self.lan_if, "wan_if": self.wan_if,
            "r2_ipv4_prefix": self.r2_ipv4_prefix,
            "r2_ipv6_prefix": self.r2_ipv6_prefix,
            "r4_window_seconds": self.r4_window_seconds,
            "r4_destination_threshold": self.r4_destination_threshold,
            "r4_port_threshold": self.r4_port_threshold,
            "r4_min_flows": self.r4_min_flows,
        }
        if self.r2_learning_flows < 0 or self.r2_learning_seconds < 0:
            raise ValueError("R2 learning requirements must not be negative")
        if any(value <= 0 for value in values.values()):
            raise ValueError("interface IDs, prefixes, windows, and thresholds must be positive")
        if self.lan_if == self.wan_if:
            raise ValueError("LAN and WAN interface IDs must differ")
        if self.r2_ipv4_prefix > 32 or self.r2_ipv6_prefix > 128:
            raise ValueError("invalid peer prefix length")


def _stable_id(prefix, value):
    return prefix + hashlib.sha256(value.encode()).hexdigest()[:32]


def _valid_mac(value):
    if not isinstance(value, str):
        return None
    parts = value.lower().split(":")
    if len(parts) != 6:
        return None
    try:
        raw = bytes(int(part, 16) for part in parts)
    except ValueError:
        return None
    if raw == b"\x00" * 6 or raw[0] & 1:
        return None
    return ":".join(f"{byte:02x}" for byte in raw)


def _ip(value):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _external(value):
    address = _ip(value)
    return bool(
        address and address.is_global and not address.is_multicast
        and not address.is_unspecified and not address.is_reserved
    )


def _peer_group(value, config):
    address = _ip(value)
    if not address:
        return None
    prefix = config.r2_ipv4_prefix if address.version == 4 else config.r2_ipv6_prefix
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def normalize_traffic(row, config):
    """Return one canonical routed observation, or None.

    RouterOS interface IDs are the authoritative direction signal.  NAT fields
    are used to turn a WAN-side representation back into the same canonical
    LAN-device -> external-peer tuple.  A flow without an observed device MAC
    remains unknown and is not attributed from a current DHCP table.
    """
    ingress, egress = row["ingress_if"], row["egress_if"]
    if (ingress, egress) == (config.lan_if, config.wan_if):
        direction = "outbound"
        internal_ip, external_ip = row["src_ip"], row["dst_ip"]
        internal_port, external_port = row["src_port"], row["dst_port"]
        device_mac = _valid_mac(row["src_mac"])
    elif (ingress, egress) == (config.wan_if, config.lan_if):
        direction = "inbound"
        internal_ip = row.get("post_nat_dst_ip")
        external_ip = row["src_ip"]
        internal_port = row.get("post_napt_dst_port")
        external_port = row["src_port"]
        # RouterOS exports router-side MACs for the observed inbound records;
        # NAT identifies the historical LAN IP but not a durable device.
        device_mac = None
    else:
        return None
    if not _external(external_ip):
        return None
    identity = f"mac:{device_mac}" if device_mac else "unknown"
    timestamp = row["flow_end_ns"] or row["received_at_ns"]
    signature_parts = (
        row["exporter_ip"], row["observation_domain_id"], direction, row["protocol"],
        internal_ip, external_ip, internal_port, external_port,
        row["flow_start_ns"], row["flow_end_ns"], row["bytes"], row["packets"],
    )
    return {
        "flow_id": row["id"], "timestamp_ns": timestamp,
        "direction": direction,
        "device_id": identity, "device_mac": device_mac,
        "internal_ip": internal_ip, "external_ip": external_ip,
        "internal_port": internal_port, "external_port": external_port,
        "protocol": row["protocol"], "bytes": row["bytes"] or 0,
        "packets": row["packets"] or 0,
        "signature": hashlib.sha256(repr(signature_parts).encode()).hexdigest(),
    }


def _upsert_event(db, *, dedup_key, timestamp_ns, rule_id, subject_id,
                  observed_ip, summary, context, evidence):
    event_id = _stable_id("evt_", dedup_key)
    db.execute(
        "INSERT INTO security_events "
        "(event_id,dedup_key,created_at_ns,first_seen_ns,last_seen_ns,rule_id,rule_version,"
        "decision_level,severity,subject_type,subject_id,observed_ip,observed_mac,summary,"
        "detection_status,resolution_status,rule_context_json) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(dedup_key) DO UPDATE SET "
        "last_seen_ns=max(last_seen_ns,excluded.last_seen_ns),"
        "rule_context_json=excluded.rule_context_json",
        (event_id, dedup_key, timestamp_ns, timestamp_ns, timestamp_ns, rule_id, "1",
         "observe", "info", "device", subject_id, observed_ip,
         subject_id.removeprefix("mac:") if subject_id.startswith("mac:") else None,
         summary, "open", "unresolved", json.dumps(context, sort_keys=True)),
    )
    evidence_id = _stable_id("evd_", f"{event_id}:{evidence['flow_id']}")
    db.execute(
        "INSERT OR IGNORE INTO event_evidence "
        "(evidence_id,event_id,evidence_type,flow_id,first_flow_id,last_flow_id,"
        "window_start_ns,window_end_ns,bytes,packets,evidence_json,evidence_hash) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (evidence_id, event_id, "flow", evidence["flow_id"], evidence["flow_id"],
         evidence["flow_id"], context.get("window_start_ns"),
         context.get("window_end_ns"), evidence["bytes"], evidence["packets"],
         json.dumps(evidence, sort_keys=True), evidence["signature"]),
    )
    decision_id = _stable_id("dec_", event_id)
    db.execute(
        "INSERT OR IGNORE INTO decisions "
        "(decision_id,event_id,decided_at_ns,decision_level,decided_by,reason,"
        "policy_version,proposed_action_json,approval_required) VALUES(?,?,?,?,?,?,?,?,?)",
        (decision_id, event_id, timestamp_ns, "observe", "detector", "evidence only",
         "v0.5", None, 0),
    )


def _r2(db, observation, config):
    peer_group = _peer_group(observation["external_ip"], config)
    port = observation["external_port"] if observation["external_port"] is not None else -1
    # DNS and HTTPS commonly and safely use both TCP and UDP (QUIC). Other
    # ports retain the transport protocol to avoid unsafe semantic merging.
    profile_protocol = 0 if port in (53, 443) and observation["protocol"] in (6, 17) \
        else observation["protocol"]
    key = (observation["device_id"], peer_group, profile_protocol, port)
    existing = db.execute(
        "SELECT first_seen_ns FROM observed_peers WHERE device_id=? AND peer_group=? "
        "AND protocol=? AND external_port IS ?", key,
    ).fetchone()
    db.execute(
        "INSERT INTO observed_peers(device_id,peer_group,protocol,external_port,first_seen_ns,last_seen_ns,flow_count) "
        "VALUES(?,?,?,?,?,?,1) ON CONFLICT(device_id,peer_group,protocol,external_port) "
        "DO UPDATE SET last_seen_ns=max(last_seen_ns,excluded.last_seen_ns),flow_count=flow_count+1",
        key + (observation["timestamp_ns"], observation["timestamp_ns"]),
    )
    count_row = db.execute(
        "SELECT flow_count,first_seen_ns FROM device_observation_state WHERE device_id=?",
        (observation["device_id"],),
    ).fetchone()
    prior_count = count_row[0] if count_row else 0
    first_seen = count_row[1] if count_row else observation["timestamp_ns"]
    db.execute(
        "INSERT INTO device_observation_state(device_id,flow_count,first_seen_ns,last_seen_ns) "
        "VALUES(?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET "
        "flow_count=flow_count+1,first_seen_ns=min(first_seen_ns,excluded.first_seen_ns),"
        "last_seen_ns=max(last_seen_ns,excluded.last_seen_ns)",
        (observation["device_id"], 1, observation["timestamp_ns"],
         observation["timestamp_ns"]),
    )
    learned_long_enough = (
        observation["timestamp_ns"] - first_seen
        >= config.r2_learning_seconds * 1_000_000_000
    )
    if (existing is None and prior_count >= config.r2_learning_flows
            and learned_long_enough):
        change_key = "R2:" + ":".join(map(str, key))
        db.execute(
            "INSERT INTO communication_profile_changes "
            "(change_key,device_id,first_seen_ns,last_seen_ns,peer_group,"
            "transport_scope,external_port,first_flow_id,occurrence_count,details_json) "
            "VALUES(?,?,?,?,?,?,?,?,1,?) ON CONFLICT(change_key) DO UPDATE SET "
            "last_seen_ns=max(last_seen_ns,excluded.last_seen_ns),"
            "occurrence_count=occurrence_count+1",
            (change_key, observation["device_id"], observation["timestamp_ns"],
             observation["timestamp_ns"], peer_group,
             "tcp_udp" if profile_protocol == 0 else str(profile_protocol), port,
             observation["flow_id"], json.dumps({
                 "classification": "communication_profile_change",
                 "security_incident": False,
                 "observed_protocol": observation["protocol"],
                 "evidence": observation,
             }, sort_keys=True)),
        )
    elif existing is not None:
        change_key = "R2:" + ":".join(map(str, key))
        db.execute(
            "UPDATE communication_profile_changes SET "
            "last_seen_ns=max(last_seen_ns,?),occurrence_count=occurrence_count+1 "
            "WHERE change_key=?",
            (observation["timestamp_ns"], change_key),
        )


def _r4(db, observation, config):
    width_ns = config.r4_window_seconds * 1_000_000_000
    window_start = observation["timestamp_ns"] - observation["timestamp_ns"] % width_ns
    window_end = window_start + width_ns
    db.execute(
        "DELETE FROM fanout_observations WHERE device_id=? AND window_start_ns<?",
        (observation["device_id"], window_start),
    )
    db.execute(
        "INSERT OR IGNORE INTO fanout_observations "
        "(device_id,window_start_ns,flow_signature,external_ip,external_port,flow_id) "
        "VALUES(?,?,?,?,?,?)",
        (observation["device_id"], window_start, observation["signature"],
         observation["external_ip"], observation["external_port"], observation["flow_id"]),
    )
    destinations, ports, flows = db.execute(
        "SELECT count(DISTINCT external_ip),count(DISTINCT external_port),count(*) "
        "FROM fanout_observations WHERE device_id=? AND window_start_ns=?",
        (observation["device_id"], window_start),
    ).fetchone()
    if flows < config.r4_min_flows:
        return
    reasons = []
    if destinations >= config.r4_destination_threshold:
        reasons.append("destinations")
    if ports >= config.r4_port_threshold:
        reasons.append("ports")
    if not reasons:
        return
    dedup = f"R4:{observation['device_id']}:{window_start}"
    context = {"window_start_ns": window_start, "window_end_ns": window_end,
               "distinct_destinations": destinations, "distinct_ports": ports,
               "flow_count": flows, "threshold_reasons": reasons,
               "connection_success_proven": False}
    exists = db.execute(
        "SELECT 1 FROM security_events WHERE dedup_key=?", (dedup,)
    ).fetchone()
    if exists:
        db.execute(
            "UPDATE security_events SET last_seen_ns=max(last_seen_ns,?),"
            "rule_context_json=? WHERE dedup_key=?",
            (observation["timestamp_ns"], json.dumps(context, sort_keys=True), dedup),
        )
    else:
        _upsert_event(
            db, dedup_key=dedup, timestamp_ns=observation["timestamp_ns"], rule_id="R4",
            subject_id=observation["device_id"], observed_ip=None,
            summary="Unusual external fan-out observed", context=context,
            evidence=observation,
        )


def process_flows(db, rows, config):
    for row in rows:
        observation = normalize_traffic(row, config)
        if not observation:
            continue
        inserted = db.execute(
            "INSERT OR IGNORE INTO canonical_flows(flow_signature,flow_id,device_id,direction,observed_at_ns) "
            "VALUES(?,?,?,?,?)",
            (observation["signature"], observation["flow_id"], observation["device_id"],
             observation["direction"], observation["timestamp_ns"]),
        ).rowcount
        if (not inserted or observation["direction"] != "outbound"
                or observation["device_id"] == "unknown"):
            continue
        _r2(db, observation, config)
        _r4(db, observation, config)
