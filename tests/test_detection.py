import sqlite3
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from detector.detection import DetectionConfig
from detector.security_reader import main, open_flows_read_only, open_security, process_batch


FLOW_COLUMNS = """
id INTEGER PRIMARY KEY, received_at_ns INTEGER, flow_start_ns INTEGER,
flow_end_ns INTEGER, exporter_ip TEXT, observation_domain_id INTEGER,
src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER, protocol INTEGER,
ingress_if INTEGER, egress_if INTEGER, src_mac TEXT, dst_mac TEXT,
bytes INTEGER, packets INTEGER, post_nat_src_ip TEXT, post_nat_dst_ip TEXT,
post_napt_src_port INTEGER, post_napt_dst_port INTEGER
"""


class DetectionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.flows_path = root / "flows.db"
        self.security_path = root / "security.db"
        with sqlite3.connect(self.flows_path) as db:
            db.execute(f"CREATE TABLE flows({FLOW_COLUMNS})")
        self.flows = open_flows_read_only(self.flows_path)
        self.security = open_security(self.security_path)
        self.config = DetectionConfig(
            r2_learning_flows=0, r2_learning_seconds=0,
            r4_window_seconds=600, r4_destination_threshold=3,
            r4_port_threshold=3, r4_min_flows=3,
        )

    def tearDown(self):
        self.flows.close()
        self.security.close()
        self.tmp.cleanup()

    def add(self, flow_id, dst_ip="8.8.8.8", dst_port=443,
            src_mac="02:11:22:33:44:55", ingress=10, egress=8,
            timestamp=1_700_000_000_000_000_000, **overrides):
        values = {
            "id": flow_id, "received_at_ns": timestamp, "flow_start_ns": timestamp - 1,
            "flow_end_ns": timestamp, "exporter_ip": "192.0.2.1",
            "observation_domain_id": 0, "src_ip": "192.168.1.50", "dst_ip": dst_ip,
            "src_port": 50000, "dst_port": dst_port, "protocol": 6,
            "ingress_if": ingress, "egress_if": egress, "src_mac": src_mac,
            "dst_mac": "02:aa:bb:cc:dd:ee", "bytes": 100, "packets": 2,
            "post_nat_src_ip": "10.0.0.100", "post_nat_dst_ip": dst_ip,
            "post_napt_src_port": 50000, "post_napt_dst_port": dst_port,
        }
        values.update(overrides)
        with sqlite3.connect(self.flows_path) as db:
            columns = ",".join(values)
            db.execute(
                f"INSERT INTO flows({columns}) VALUES({','.join('?' for _ in values)})",
                tuple(values.values()),
            )

    def process(self, batch_size=100):
        self.flows.close()
        self.flows = open_flows_read_only(self.flows_path)
        return process_batch(
            self.flows, self.security, batch_size=batch_size,
            detection_config=self.config,
        )

    def events(self, rule):
        return self.security.execute(
            "SELECT rule_id,decision_level,subject_id,summary,rule_context_json "
            "FROM security_events WHERE rule_id=? ORDER BY event_id", (rule,)
        ).fetchall()

    def test_r2_groups_cloud_transports_as_profile_change_not_event(self):
        self.add(1, "8.8.8.8")
        self.add(2, "8.8.8.9", src_port=50001, protocol=17)
        self.process()
        self.assertEqual(len(self.events("R2")), 0)
        changes = self.security.execute(
            "SELECT device_id,peer_group,transport_scope,occurrence_count "
            "FROM communication_profile_changes"
        ).fetchall()
        self.assertEqual(
            changes,
            [("mac:02:11:22:33:44:55", "8.8.8.0/24", "tcp_udp", 2)],
        )
        self.assertEqual(
            self.security.execute("SELECT flow_count FROM observed_peers").fetchone()[0], 2
        )
        self.assertEqual(
            self.security.execute("SELECT count(*) FROM action_attempts").fetchone()[0], 0
        )

    def test_r2_keeps_tcp_udp_separate_on_other_ports(self):
        self.add(1, "8.8.8.8", 8443, protocol=6)
        self.add(2, "8.8.8.9", 8443, protocol=17, src_port=50001)
        self.process()
        self.assertEqual(
            self.security.execute(
                "SELECT transport_scope FROM communication_profile_changes ORDER BY 1"
            ).fetchall(),
            [("17",), ("6",)],
        )

    def test_repeat_batch_and_duplicate_perspective_are_idempotent(self):
        self.add(1)
        self.add(2)  # same canonical signature, different exported row
        self.process()
        self.process()
        self.assertEqual(self.security.execute("SELECT count(*) FROM canonical_flows").fetchone()[0], 1)
        self.assertEqual(
            self.security.execute(
                "SELECT count(*) FROM communication_profile_changes"
            ).fetchone()[0], 1
        )
        self.assertEqual(self.security.execute("SELECT flow_count FROM observed_peers").fetchone()[0], 1)

    def test_unknown_identity_is_not_attributed_or_detected(self):
        self.add(1, src_mac=None)
        self.process()
        self.assertEqual(self.security.execute("SELECT count(*) FROM security_events").fetchone()[0], 0)
        self.assertEqual(
            self.security.execute("SELECT device_id FROM canonical_flows").fetchone()[0],
            "unknown",
        )

    def test_non_outbound_and_discovery_traffic_do_not_trigger(self):
        self.add(1, "239.255.255.250", 1900, protocol=17)
        self.add(2, "8.8.8.8", ingress=8, egress=10)
        self.process()
        self.assertEqual(self.security.execute("SELECT count(*) FROM security_events").fetchone()[0], 0)

    def test_r4_conservative_window_and_no_success_claim(self):
        self.add(1, "8.8.8.8", 443)
        self.add(2, "9.9.9.9", 8443, src_port=50001)
        self.assertEqual(self.process(batch_size=2), (2, 2))
        self.assertEqual(len(self.events("R4")), 0)
        self.add(3, "1.1.1.1", 9443, src_port=50002)
        self.process()
        events = self.events("R4")
        self.assertEqual(len(events), 1)
        self.assertIn('"connection_success_proven": false', events[0][4])
        decisions = self.security.execute(
            "SELECT decision_level,approval_required FROM decisions WHERE event_id IN "
            "(SELECT event_id FROM security_events WHERE rule_id='R4')"
        ).fetchall()
        self.assertEqual(decisions, [("observe", 0)])
        self.add(4, "4.2.2.2", 10443, src_port=50003)
        self.process()
        self.assertEqual(len(self.events("R4")), 1)
        self.assertEqual(
            self.security.execute(
                "SELECT count(*) FROM event_evidence WHERE event_id IN "
                "(SELECT event_id FROM security_events WHERE rule_id='R4')"
            ).fetchone()[0],
            1,
        )

    def test_nat_fields_do_not_replace_historical_identity(self):
        self.add(1, post_nat_src_ip="10.0.0.100", src_mac="02:11:22:33:44:55")
        self.process()
        subject = self.security.execute(
            "SELECT device_id FROM communication_profile_changes"
        ).fetchone()[0]
        self.assertEqual(subject, "mac:02:11:22:33:44:55")

    def test_inbound_nat_is_directional_but_identity_stays_unknown(self):
        self.add(
            1, dst_ip="10.0.0.100", src_ip="8.8.8.8", src_port=443,
            dst_port=51000, ingress=8, egress=10,
            post_nat_dst_ip="192.168.1.50", post_napt_dst_port=51000,
        )
        self.process()
        self.assertEqual(
            self.security.execute(
                "SELECT device_id,direction FROM canonical_flows"
            ).fetchone(),
            ("unknown", "inbound"),
        )
        self.assertEqual(self.security.execute("SELECT count(*) FROM security_events").fetchone()[0], 0)

    def test_r2_requires_flow_and_time_baseline(self):
        self.config = DetectionConfig(r2_learning_flows=2, r2_learning_seconds=172800)
        self.add(1, "8.8.8.8")
        self.add(2, "9.9.9.9", src_port=50001)
        self.process()
        self.assertEqual(
            self.security.execute(
                "SELECT count(*) FROM communication_profile_changes"
            ).fetchone()[0], 0
        )
        self.add(
            3, "1.1.1.1", src_port=50002,
            timestamp=1_700_000_000_000_000_000 + 172800 * 1_000_000_000,
        )
        self.process()
        self.assertEqual(
            self.security.execute(
                "SELECT count(*) FROM communication_profile_changes"
            ).fetchone()[0], 1
        )
        self.assertEqual(len(self.events("R2")), 0)

    def test_detection_and_checkpoint_rollback_together(self):
        self.add(1)
        self.flows.close()
        self.flows = open_flows_read_only(self.flows_path)

        def fail():
            raise RuntimeError("interrupted")

        with self.assertRaises(RuntimeError):
            process_batch(
                self.flows, self.security, detection_config=self.config,
                before_commit=fail,
            )
        self.assertEqual(self.security.execute("SELECT count(*) FROM security_events").fetchone()[0], 0)
        self.assertEqual(self.security.execute("SELECT count(*) FROM canonical_flows").fetchone()[0], 0)
        self.assertEqual(
            self.security.execute(
                "SELECT count(*) FROM communication_profile_changes"
            ).fetchone()[0], 0
        )
        self.assertIsNone(
            self.security.execute("SELECT last_flow_id FROM detector_checkpoints").fetchone()
        )
        self.assertEqual(self.process(), (1, 1))

    def test_invalid_direction_and_threshold_configuration_fails_closed(self):
        with self.assertRaises(ValueError):
            DetectionConfig(lan_if=8, wan_if=8)
        with self.assertRaises(ValueError):
            DetectionConfig(r4_window_seconds=0)

    def test_production_defaults_match_approved_parameters(self):
        config = DetectionConfig()
        self.assertEqual(config.r2_learning_flows, 1000)
        self.assertEqual(config.r2_learning_seconds, 48 * 60 * 60)
        self.assertEqual(config.r4_window_seconds, 600)
        self.assertEqual(config.r4_destination_threshold, 120)
        self.assertEqual(config.r4_port_threshold, 25)

    def test_cli_uses_approved_r4_destination_default(self):
        with mock.patch("detector.security_reader.process_batch", return_value=(0, 0)) as process:
            self.assertEqual(main([
                str(self.flows_path),
                str(self.security_path),
                "--once",
            ]), 0)
        self.assertEqual(
            process.call_args.kwargs["detection_config"].r4_destination_threshold,
            120,
        )

    def test_r4_default_destination_boundary(self):
        self.config = DetectionConfig(r2_learning_flows=999999)
        for index in range(119):
            self.add(
                index + 1,
                f"23.1.{index // 250}.{index % 250 + 1}",
                src_port=50000 + index,
            )
        self.process(batch_size=200)
        self.assertEqual(len(self.events("R4")), 0)
        self.add(120, "23.1.0.120", src_port=50119)
        self.process(batch_size=200)
        self.assertEqual(len(self.events("R4")), 1)

    def test_r4_default_port_boundary(self):
        self.config = DetectionConfig(r2_learning_flows=999999)
        for index in range(24):
            self.add(index + 1, "8.8.8.8", 10000 + index, src_port=51000 + index)
        self.process(batch_size=100)
        self.assertEqual(len(self.events("R4")), 0)
        self.add(25, "8.8.8.8", 10024, src_port=51024)
        self.process(batch_size=100)
        self.assertEqual(len(self.events("R4")), 1)


if __name__ == "__main__":
    unittest.main()
