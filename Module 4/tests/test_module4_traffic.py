import copy
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from module4.traffic import (canonical_flows, feature_rows, renamed_inputs,
                             selected_features, traffic_features)
from module4.traffic_study import decision, disjoint
from test_module4 import fixture


class TrafficFeatureTests(unittest.TestCase):
    def example(self):
        recording, _ = fixture("traffic", 0)
        flow = copy.deepcopy(recording["flows"][0])
        flow.update(start_time=100.0, duration=2.0, origin_packets=4, response_packets=2,
                    origin_bytes=100, response_bytes=20, missed_bytes=0, transport="tcp")
        recording["flows"] = [copy.deepcopy(flow)]
        return recording, [flow]

    def test_totals_follow_endpoint_direction_and_are_counted_once(self):
        recording, flows = self.example()
        flow = flows[0]
        features = traffic_features(recording, flows)
        source, destination = features[flow["source_ip"]], features[flow["destination_ip"]]
        self.assertEqual(source["payload_bytes_sent"], 100)
        self.assertEqual(source["payload_bytes_received"], 20)
        self.assertEqual(source["packets_sent"], 4)
        self.assertEqual(source["sent_payload_bytes_per_packet"], 25)
        self.assertEqual(source["observed_span_seconds"], 2)
        self.assertEqual(source["packets_per_observed_second"], 3)
        self.assertEqual(destination["payload_bytes_sent"], 20)
        self.assertEqual(destination["payload_bytes_received"], 100)
        self.assertEqual(destination["received_flows"], 1)
        self.assertEqual(source["peer_count"], 1)
        with self.assertRaisesRegex(ValueError, "double-count"):
            traffic_features(recording, flows + flows)

    def test_sparse_missing_counters_and_duration_are_explicit(self):
        recording, flows = self.example()
        flow = flows[0]
        flow.update(duration=None, origin_bytes=None, response_bytes=None,
                    origin_packets=None, response_packets=None)
        features = traffic_features(recording, flows)
        source = features[flow["source_ip"]]
        self.assertEqual(source["missing_duration_flows"], 1)
        self.assertEqual(source["missing_byte_counter_flows"], 1)
        self.assertEqual(source["payload_bytes_per_observed_second"], 0)
        self.assertEqual(source["flow_duration_seconds_mean"], 0)
        self.assertEqual(len({tuple(row.keys()) for row in features.values()}), 1)

    def test_nonfinite_measurements_are_rejected(self):
        for bad in (float("nan"), float("inf"), -1, "42"):
            recording, flows = self.example()
            flows[0]["origin_bytes"] = bad
            with self.assertRaises(ValueError):
                traffic_features(recording, flows)

    def test_identifiers_ports_absolute_time_and_sender_names_cannot_change_features(self):
        recording, flows = self.example()
        before = feature_rows(recording, flows)
        record, renamed = renamed_inputs(recording, flows)
        for flow in renamed:
            flow.update(source_port=45555, destination_port=50000, service="new-service", zeek_uid="new-uid")
        after = feature_rows(record, renamed)
        for family in ("protocol_evidence", "statistics", "combined"):
            self.assertEqual([selected_features(row, family) for row in before],
                             [selected_features(row, family) for row in after])
        self.assertEqual(flows[0]["start_time"], 100.0)

    def test_statistics_model_does_not_secretly_require_hl7_or_dicom(self):
        recording, flows = self.example()
        row = feature_rows(recording, flows)[0]
        row["protocols"] = set()
        row["presence"] = "observed_transmitting"
        self.assertEqual(decision(row, ("ct", .9), .8, "statistics")[0], "ct")
        self.assertEqual(decision(row, ("ct", .9), .8, "protocol_evidence")[0], "unknown")
        self.assertEqual(decision(row, ("other", .99), .8, "statistics")[0], "unknown")
        self.assertEqual(decision(row, ("ct", .7), .8, "statistics")[0], "unknown")

    def test_feature_families_keep_semantic_evidence_out_of_statistics(self):
        recording, flows = self.example()
        row = feature_rows(recording, flows)[0]
        row["features"].update(hl7_heart_rate=1, oru_flows=2, packets_sent=8)
        protocol = selected_features(row, "protocol_evidence")
        self.assertEqual(protocol["hl7_heart_rate"], 1)
        self.assertNotIn("packets_sent", protocol)
        statistics = selected_features(row, "statistics")
        self.assertTrue(all(name.startswith("traffic_") for name in statistics))
        self.assertNotIn("hl7_heart_rate", statistics)

    def test_readonly_canonical_join_rejects_mismatched_recordings(self):
        recording, flows = self.example()
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "monitoring.sqlite3"
            with closing(sqlite3.connect(database)) as db:
                with db:
                    db.execute("CREATE TABLE canonical (id TEXT,start_time REAL,scope TEXT,data TEXT)")
                    db.execute("INSERT INTO canonical VALUES (?,?,?,?)", (
                        flows[0]["flow_id"], flows[0]["start_time"], recording["scope"], json.dumps(flows[0])))
            before = database.read_bytes()
            self.assertEqual(canonical_flows(database, recording), flows)
            self.assertEqual(database.read_bytes(), before)
            recording["flows"][0]["origin_packets"] += 1
            with self.assertRaisesRegex(ValueError, "disagree"):
                canonical_flows(database, recording)

    def test_overlap_checks_cover_sessions_instances_and_digests(self):
        def group(name):
            return {"recordings": {(name, name): {"digest": name}}, "instances": {name}}
        disjoint(group("train"), group("test"))
        for field in ("recordings", "instances"):
            left, right = group("train"), group("test")
            right[field] = left[field]
            with self.assertRaises(ValueError):
                disjoint(left, right)
        left, right = group("train"), group("test")
        right["recordings"][("test", "test")]["digest"] = "train"
        with self.assertRaises(ValueError):
            disjoint(left, right)


if __name__ == "__main__":
    unittest.main()
