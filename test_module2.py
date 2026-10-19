"""Deterministic parser/storage tests. Real Zeek acceptance is verify_module2.py."""
import csv
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import Mock, patch
from http.server import ThreadingHTTPServer
import threading
import urllib.error
import urllib.request

from module2.parsing import hl7_messages, identity, normalize, reassemble
from module2.pcap import complete_pcap, snapshot
from module2.pipeline import Pipeline
from module2.sensor import FIELDS, Sensor
from module2.store import Store
from module2.live import Live, Spool
from module2.retention import enforce_budget, raw_size
from module2.server import handler

HEADER = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
PACKET = struct.pack("<IIII", 100, 0, 4, 4) + b"test"
HL7 = b"\x0bMSH|^~\\&|LAB_PUMP|LAB|EHR|LAB|20261015||ORU^R01|1|P|2.5\rPID|SECRET_PATIENT\rOBX|SECRET_VALUE\r\x1c\x0d"


def flow(capture="one", source="pump", ts=100.0, correlation="syn", scope="test"):
    return {"schema_version": "hiot.monitoring.v1", "observation_id": identity(capture, ts), "capture_id": capture,
            "observation_source": source, "scope": scope, "start_time": ts, "source_ip": "10.77.20.20", "source_port": 40000,
            "destination_ip": "10.77.30.40", "destination_port": 2575, "transport": "tcp", "service": None,
            "connection_state": "SF", "duration": 1, "origin_packets": 4, "response_packets": 3,
            "origin_bytes": 100, "response_bytes": 60, "missed_bytes": 0, "zeek_uid": "random",
            "tcp_stream": "0", "correlation_key": correlation, "correlation_status": "syn_fingerprint" if correlation else "observation_only", "evidence": []}


def capture(identifier="one", source="pump", scope="test"):
    return {"capture_id": identifier, "scope": scope, "observation_source": source}


def fixture(folder, protocol="hl7", flag="True"):
    fields = {f: "" for f in FIELDS}
    fields.update({"frame.number": "1", "frame.time_epoch": "100.0", "ip.src": "10.77.20.20", "ip.dst": "10.77.30.40",
                   "tcp.srcport": "40000", "tcp.dstport": "2575", "tcp.flags.syn": flag, "tcp.flags.ack": "False",
                   "tcp.seq_raw": "123", "tcp.len": "0", "tcp.stream": "0", "frame.cap_len": "60", "frame.len": "60"})
    rows = [fields.copy()]
    fields.update({"frame.number": "2", "frame.time_epoch": "100.1", "tcp.flags.syn": "False", "tcp.flags.ack": "True", "tcp.seq_raw": "124"})
    if protocol == "hl7":
        fields["tcp.payload"] = HL7.hex()
        fields["tcp.len"] = str(len(HL7))
    elif protocol == "dicom":
        fields.update({"dicom.assoc.ae.calling": "LAB_CT", "dicom.assoc.ae.called": "LAB_PACS", "dicom.pctx.abss.syntax": "1.2.840.10008.1.1"})
    rows.append(fields)
    with (folder / "packets.tsv").open("w", newline="") as out:
        writer = csv.writer(out, delimiter="\t", quotechar='"', quoting=csv.QUOTE_ALL)
        writer.writerows([[r[k] for k in FIELDS] for r in rows])
    conn = {"ts": 100.0, "uid": "one", "id.orig_h": "10.77.20.20", "id.orig_p": 40000,
            "id.resp_h": "10.77.30.40", "id.resp_p": 2575, "proto": "tcp", "duration": 1,
            "conn_state": "SF", "orig_pkts": 4, "resp_pkts": 3, "orig_bytes": 100, "resp_bytes": 60}
    (folder / "conn.log").write_text(json.dumps(conn)+"\n")


class Module2Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = Store(self.root / "monitoring.sqlite3")

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def test_pcap_counts_complete_records(self):
        data, info = complete_pcap(HEADER + PACKET*2)
        self.assertEqual(info["frames"], 2)
        self.assertEqual(info["incomplete_tail_bytes"], 0)

    def test_malformed_pcap_refused(self):
        for raw in (b"bad", b"\x0a\x0d\x0d\x0a" + b"0"*30, HEADER+struct.pack("<IIII", 0, 0, 999999, 2)):
            with self.assertRaises(ValueError):
                complete_pcap(raw)

    def test_partial_tail_allowed_only_for_live_snapshot(self):
        raw = HEADER+PACKET+PACKET[:18]
        with self.assertRaisesRegex(ValueError, "Truncated"):
            complete_pcap(raw)
        data, info = complete_pcap(raw, True)
        self.assertEqual(data, HEADER+PACKET)
        self.assertEqual(info["incomplete_tail_bytes"], 18)

    def test_snapshot_limit_not_silent_truncation(self):
        path = self.root / "input.pcap"
        path.write_bytes(HEADER+PACKET)
        with self.assertRaisesRegex(ValueError, "limit"):
            snapshot(path, self.root/"out.pcap", max_bytes=30)

    def test_split_out_of_order_and_retransmitted_hl7(self):
        a, b = HL7[:15], HL7[15:]
        chunks, issues = reassemble([(115, b, 3), (100, a, 2), (100, a, 4)])
        messages, problems = hl7_messages(chunks)
        self.assertFalse(issues+problems)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["metadata"], {"sender": "LAB_PUMP", "message_type": "ORU^R01"})
        self.assertNotIn("SECRET", json.dumps(messages))

    def test_tcp_wraparound(self):
        chunks, issues = reassemble([(2**32-5, b"abcde", 1), (0, b"fgh", 2)])
        self.assertEqual(chunks[0][0], b"abcdefgh")
        self.assertFalse(issues)

    def test_persistent_hl7_messages_keep_actual_supporting_frames(self):
        chunks, _ = reassemble([(100, HL7, 2), (100+len(HL7), HL7[:20], 5),
                                (120+len(HL7), HL7[20:], 6)])
        messages, issues = hl7_messages(chunks)
        self.assertFalse(issues)
        self.assertEqual([m["frame"] for m in messages], [2, 5])
        self.assertEqual(messages[1]["supporting_frames"], [5, 6])
        self.assertEqual(messages[1]["frame_payload_offset"], 0)

    def test_hl7_frame_offset_with_multiple_messages_in_one_packet(self):
        chunks, _ = reassemble([(100, b"padding"+HL7+HL7, 3)])
        messages, _ = hl7_messages(chunks)
        self.assertEqual([m["frame_payload_offset"] for m in messages], [7, 7+len(HL7)])

    def test_gap_never_joins_message_fragments(self):
        chunks, issues = reassemble([(100, HL7[:20], 1), (125, HL7[20:], 2)])
        messages, problems = hl7_messages(chunks)
        self.assertFalse(messages)
        self.assertIn("tcp_gap", [i["kind"] for i in issues])
        self.assertIn("incomplete_mllp_message", [i["kind"] for i in problems])

    def test_conflicting_overlap_not_interpreted(self):
        chunks, issues = reassemble([(10, b"abcdef", 1), (12, b"XX", 2)])
        self.assertFalse(chunks)
        self.assertEqual(issues[0]["kind"], "conflicting_tcp_overlap")

    def test_reassembly_memory_bound(self):
        chunks, issues = reassemble([(10, b"012345", 1)], limit=3)
        self.assertFalse(chunks)
        self.assertEqual(issues[0]["kind"], "reassembly_limit")

    def test_malformed_and_incomplete_hl7_are_visible(self):
        messages, issues = hl7_messages([(b"\x0bMSH|bad\x1c\x0d\x0bMSH|unfinished", 1)])
        self.assertFalse(messages)
        self.assertEqual({i["kind"] for i in issues}, {"malformed_hl7_msh", "incomplete_mllp_message"})

    def test_tshark_boolean_flags_and_hl7_metadata(self):
        fixture(self.root)
        flows, issues, ref = normalize(self.root, "one", "pump", "test")
        self.assertFalse(issues)
        self.assertEqual(ref["independent_unique_syns"], 1)
        self.assertEqual(flows[0]["correlation_status"], "syn_fingerprint")
        self.assertEqual(flows[0]["evidence"][0]["metadata"]["message_type"], "ORU^R01")

    def test_numeric_syn_encoding(self):
        fixture(self.root, flag="1")
        self.assertEqual(normalize(self.root, "one", "pump", "test")[2]["independent_unique_syns"], 1)

    def test_port_alone_does_not_confirm_protocol(self):
        fixture(self.root, protocol="none")
        flows, _, _ = normalize(self.root, "one", "pump", "test")
        self.assertFalse(flows[0]["evidence"])
        self.assertEqual(flows[0]["protocol_status"], "unconfirmed")

    def test_dicom_ae_titles_have_frame_provenance(self):
        fixture(self.root, protocol="dicom")
        event = normalize(self.root, "one", "ct", "test")[0][0]["evidence"][0]
        self.assertEqual(event["metadata"]["calling_ae"], "LAB_CT")
        self.assertEqual(event["frame"], 2)
        self.assertEqual(event["capture_id"], "one")

    def test_tcp_medical_evidence_never_attaches_to_same_tuple_udp(self):
        fixture(self.root)
        path = self.root/"conn.log"
        udp = json.loads(path.read_text())
        udp.update(proto="udp", ts=100.1, uid="udp")
        path.write_text(path.read_text()+json.dumps(udp)+"\n")
        flows, _, _ = normalize(self.root, "one", "pump", "test")
        tcp = next(f for f in flows if f["transport"] == "tcp")
        udp = next(f for f in flows if f["transport"] == "udp")
        self.assertTrue(tcp["evidence"])
        self.assertFalse(udp["evidence"])

    def test_malformed_zeek_record_reported(self):
        fixture(self.root)
        (self.root / "conn.log").write_text('{"ts":1}\n')
        self.assertEqual(normalize(self.root, "one", "pump", "test")[1][0]["kind"], "malformed_zeek_record")

    def test_idempotent_upsert_ignores_zeek_random_uid(self):
        f = flow()
        self.db.ingest(capture(), [f], [])
        f["zeek_uid"] = "different"
        self.db.ingest(capture(), [f], [])
        self.assertEqual(self.db.status()["observations"], 1)

    def test_overlapping_link_counters_are_not_summed(self):
        self.db.ingest(capture(), [flow()], [])
        second = flow("two", "mirror", ts=100.002)
        second["origin_packets"] = 5
        self.db.ingest(capture("two", "mirror"), [second], [])
        self.assertEqual(self.db.status()["canonical_flows"], 1)
        result = self.db.flows()[0]
        self.assertEqual(result["observation_count"], 2)
        self.assertEqual(result["origin_packets"], 5)
        self.assertEqual(result["capture_ids"], ["one", "two"])

    def test_time_guard_prevents_syn_reuse_collision(self):
        self.db.ingest(capture(), [flow()], [])
        self.db.ingest(capture("two"), [flow("two", ts=110)], [])
        self.assertEqual(self.db.status()["canonical_flows"], 2)

    def test_missing_syn_not_guessed_across_links(self):
        self.db.ingest(capture(), [flow(correlation=None)], [])
        self.db.ingest(capture("two"), [flow("two", correlation=None)], [])
        self.assertEqual(self.db.status()["canonical_flows"], 2)

    def test_scopes_do_not_mix_experiments(self):
        self.db.ingest(capture(), [flow()], [])
        other = flow("two", scope="other", correlation="other-syn")
        self.db.ingest(capture("two", scope="other"), [other], [])
        self.assertEqual(len(self.db.flows(scope="test")), 1)
        self.assertEqual(self.db.status("other")["canonical_flows"], 1)

    def test_resolved_parser_warning_replaced(self):
        self.db.ingest(capture(), [flow()], [{"kind": "incomplete"}])
        self.db.ingest(capture(), [flow()], [])
        self.assertFalse(self.db.status()["issues"])

    def test_snapshot_replaces_removed_records_without_removing_other_capture(self):
        self.db.ingest(capture(), [flow(), flow(ts=103)], [])
        self.db.ingest(capture("mirror"), [flow("mirror")], [])
        self.db.ingest(capture(), [flow()], [])
        self.assertEqual(self.db.status()["observations"], 2)
        self.assertEqual(self.db.status()["canonical_flows"], 1)
        self.db.ingest(capture(), [], [])
        self.assertEqual(self.db.status()["observations"], 1)

    def test_collector_health_does_not_hide_dead_readers_or_sensor_errors(self):
        live = Live(self.db, self.root, Mock(), "unused")
        live.running = True
        live.spools = {"pump": Mock()}
        live.threads = [Mock(), Mock()]
        for thread in live.threads:
            thread.is_alive.return_value = True
        self.assertEqual(live.status()["state"], "running")
        live.threads[0].is_alive.return_value = False
        self.assertEqual(live.status()["state"], "degraded")
        live.threads[0].is_alive.return_value = True
        self.db.health("sensor", state="error", error="SSH unavailable")
        self.assertEqual(live.status()["state"], "degraded")
        self.db.health("sensor", state="ready", error=None)
        self.assertEqual(live.status()["state"], "running")

    def test_stop_waits_for_analysis_and_does_not_claim_early_completion(self):
        live = Live(self.db, self.root, Mock(), "unused")
        live.running = True
        finish = threading.Event()
        worker = threading.Thread(target=finish.wait, daemon=True)
        worker.start()
        live.threads = [worker]
        self.db.setting("live", {"enabled": True})
        try:
            with self.assertRaisesRegex(RuntimeError, "still finishing"):
                live.stop(timeout=.01)
            self.assertTrue(live.running)
            self.assertTrue(self.db.setting("live")["enabled"])
        finally:
            finish.set()
            live.stop(timeout=1)
        self.assertFalse(worker.is_alive())
        self.assertFalse(live.running)
        self.assertFalse(self.db.setting("live")["enabled"])

    def test_jsonl_export_and_query(self):
        self.db.ingest(capture(), [flow()], [])
        self.assertEqual(len(self.db.flows(query="2575")), 1)
        self.assertFalse(self.db.flows(query="unrelated"))
        self.db.export(self.root/"out.jsonl")
        record = json.loads((self.root/"out.jsonl").read_text())
        self.assertEqual(record["schema_version"], "hiot.monitoring.v1")

    def test_cached_flows_invalidate_after_another_store_import(self):
        self.db.ingest(capture(), [flow()], [])
        self.assertEqual(len(self.db.flows(scope="test")), 1)
        other = Store(self.db.path)
        other.ingest(capture("two"), [flow("two", ts=110)], [])
        self.assertEqual(len(self.db.flows(scope="test")), 2)

    def test_cached_flow_results_cannot_be_mutated_by_consumers(self):
        self.db.ingest(capture(), [flow()], [])
        result = self.db.flows(scope="test")
        result[0]["source_ip"] = "changed"
        result[0]["evidence"].append({"protocol": "invented"})
        fresh = self.db.flows(scope="test")[0]
        self.assertEqual(fresh["source_ip"], "10.77.20.20")
        self.assertFalse(fresh["evidence"])

    def test_flow_cache_is_bounded_and_preserves_scope_and_summary(self):
        for i in range(4):
            scope = f"scope-{i}"
            self.db.ingest(capture(str(i), scope=scope), [flow(str(i), scope=scope, correlation=None)], [])
        for i in range(4):
            scope = f"scope-{i}"
            self.assertEqual(len(self.db.flows(scope=scope)), 1)
            self.assertEqual(self.db.summary(scope)["endpoints"][0]["connections"], 1)
        self.assertLessEqual(len(self.db._cache), 2)
        self.assertFalse(self.db.flows(limit=0))

    def test_transport_filter_matches_export_query(self):
        self.db.ingest(capture(), [flow()], [])
        self.assertEqual(len(self.db.flows(transport="tcp")), 1)
        self.assertFalse(self.db.flows(transport="udp"))

    def test_icmp_has_no_invented_service_port(self):
        fixture(self.root, protocol="none")
        record = json.loads((self.root/"conn.log").read_text())
        record["proto"] = "icmp"
        (self.root/"conn.log").write_text(json.dumps(record))
        f = normalize(self.root, "one", "source", "test")[0][0]
        self.assertIsNone(f["source_port"])
        self.assertIsNone(f["destination_port"])

    def test_retention_refuses_unowned_file(self):
        raw = self.root/"do-not-remove.pcap"
        raw.write_bytes(HEADER)
        info = {**capture(), "raw_capture": str(raw), "raw_retained": True}
        self.db.ingest(info, [], [])
        with self.assertRaises(ValueError):
            self.db.expire_raw("one")
        self.assertTrue(raw.exists())

    def test_retention_preserves_hash_and_marks_expiry(self):
        folder = self.root/"artifacts"/"one"
        folder.mkdir(parents=True)
        raw = folder/"input.pcap"
        raw.write_bytes(HEADER)
        self.db.ingest({**capture(), "raw_capture": str(raw), "raw_retained": True, "sha256": "known"}, [], [])
        self.db.expire_raw("one")
        c = self.db.status()["captures"][0]
        self.assertFalse(c["raw_retained"])
        self.assertEqual(c["sha256"], "known")
        self.assertFalse(raw.exists())

    def test_global_budget_preserves_offline_evidence(self):
        folder = self.root/"artifacts"/"offline"
        folder.mkdir(parents=True)
        raw = folder/"input.pcap"
        raw.write_bytes(HEADER)
        with self.assertRaises(BufferError):
            enforce_budget(self.db, self.root, "live-current", budget=1)
        self.assertTrue(raw.exists())

    def test_storage_accounting_tolerates_concurrent_segment_retirement(self):
        folder = self.root/"live"
        folder.mkdir()
        gone, retained = folder/"retired.pcap", folder/"retained.pcap"
        gone.write_bytes(HEADER)
        retained.write_bytes(HEADER+PACKET)
        original_stat = Path.stat
        def stat(path, *args, **kwargs):
            if path.name == gone.name:
                raise FileNotFoundError(str(path))
            return original_stat(path, *args, **kwargs)
        with patch.object(Path, "stat", stat):
            self.assertEqual(raw_size(self.root), len(HEADER+PACKET))

    def test_global_budget_expires_only_completed_old_live_scope(self):
        identifier = identity("live-old", "pump", 1)
        raw_dir = self.root/"artifacts"/identifier
        raw_dir.mkdir(parents=True)
        raw = raw_dir/"input.pcap"
        raw.write_bytes(HEADER)
        spool_dir = self.root/"live"/"live-old"/"pump"
        spool_dir.mkdir(parents=True)
        (spool_dir/"segment-000001.pcap").write_bytes(HEADER)
        facts = complete_pcap(HEADER)[1]
        self.db.ingest({**capture(identifier, scope="live-old"), **facts, "raw_capture": str(raw), "raw_retained": True, "processed_at": 1}, [], [])
        self.assertEqual(enforce_budget(self.db, self.root, "live-current", budget=1), 0)
        self.assertFalse(raw.exists())
        self.assertFalse(self.db.status()["captures"][0]["raw_retained"])

    def test_global_budget_preserves_unprocessed_old_scope_spool(self):
        self.test_global_budget_expires_only_completed_old_live_scope()
        folder = self.root/"live"/"live-old"/"pump"
        pending = folder/"segment-000002.pcap"
        pending.write_bytes(HEADER+PACKET)
        with self.assertRaises(BufferError):
            enforce_budget(self.db, self.root, "live-current", budget=1)
        self.assertTrue(pending.exists())

    def test_spool_never_snapshots_partial_record(self):
        spool = Spool(self.root/"live", "pump", "scope", self.db)
        spool.feed((HEADER+PACKET)[:35])
        self.assertEqual(spool.segments[0]["path"].read_bytes(), HEADER)
        spool.feed((HEADER+PACKET)[35:])
        self.assertEqual(complete_pcap(spool.segments[0]["path"].read_bytes())[1]["frames"], 1)

    def test_spool_retention_backpressure_is_visible(self):
        spool = Spool(self.root/"live", "pump", "scope", self.db, limit=50)
        spool.feed(HEADER+PACKET*2)
        with self.assertRaises(BufferError):
            spool.feed(PACKET)

    def test_spool_reconnect_does_not_append_second_pcap_header(self):
        spool = Spool(self.root/"live", "pump", "scope", self.db)
        spool.feed(HEADER+PACKET)
        spool.processed[spool.segments[0]["id"]] = spool.segments[0]["bytes"]
        spool.reconnect()
        spool.feed(HEADER+PACKET)
        self.assertEqual(len(spool.segments), 2)
        for segment in spool.segments:
            self.assertEqual(complete_pcap(segment["path"].read_bytes())[1]["frames"], 1)

    def test_quiet_header_only_reconnects_do_not_permanently_backpressure(self):
        spool = Spool(self.root/"live", "quiet", "scope", self.db)
        for _ in range(5):
            spool.reconnect()
            spool.feed(HEADER)
        self.assertEqual(len(spool.segments), 2)
        self.assertEqual(spool.counter, 5)
        self.assertTrue(all(s["bytes"] == 24 for s in spool.segments))

    def test_rotation_preserves_tail_added_after_last_analysis(self):
        spool = Spool(self.root/"live", "pump", "scope", self.db, limit=70)
        spool.feed(HEADER+PACKET)
        spool.processed[spool.segments[0]["id"]] = spool.segments[0]["bytes"]
        spool.feed(PACKET*3)
        oldest = spool.segments[0]["path"]
        with self.assertRaises(BufferError):
            spool.feed(PACKET)
        self.assertTrue(oldest.exists())
        self.assertEqual(complete_pcap(oldest.read_bytes())[1]["frames"], 2)
        self.assertEqual(spool.buffer, PACKET)

    def test_restart_does_not_mark_unanalyzed_segment_tail_processed(self):
        folder = self.root/"live"
        spool = Spool(folder, "pump", "scope", self.db, limit=70)
        spool.feed(HEADER+PACKET)
        first = spool.segments[0]
        self.db.ingest({**capture(first["id"], scope="scope"), "bytes": first["bytes"]}, [], [])
        spool.feed(PACKET*3)
        resumed = Spool(folder, "pump", "scope", self.db, limit=70)
        resumed.header = HEADER
        with self.assertRaises(BufferError):
            resumed.new_segment()

    def test_pipeline_failure_saved_to_health(self):
        source = self.root / "bad.pcap"
        source.write_bytes(b"bad")
        with self.assertRaises(ValueError):
            Pipeline(self.db, self.root, Mock()).import_file(source, "bad", "test")
        self.assertEqual(self.db.status()["health"][0]["state"], "error")

    def test_pipeline_repeat_import_is_cached(self):
        source = self.root/"valid.pcap"
        source.write_bytes(HEADER+PACKET)
        sensor = Mock()
        def analyze(path, folder):
            fixture(folder)
            return {"analysis_seconds": .1, "versions": {"zeek": "fixture", "tshark": "fixture"}}
        sensor.analyze.side_effect = analyze
        pipeline = Pipeline(self.db, self.root, sensor)
        pipeline.import_file(source, "pump", "test")
        result = pipeline.import_file(source, "pump", "test")
        self.assertTrue(result["cached"])
        self.assertEqual(sensor.analyze.call_count, 1)
        self.assertEqual(self.db.status()["observations"], 1)

    def test_sensor_constructor_closes_failed_ssh_client(self):
        with patch("paramiko.SSHClient") as client:
            client.return_value.connect.side_effect = OSError("VM unavailable")
            with self.assertRaisesRegex(OSError, "unavailable"):
                Sensor("192.168.209.142", self.root)
            client.return_value.close.assert_called_once()

    def test_live_analysis_reconnects_after_sensor_disconnect(self):
        first, second = Mock(), Mock()
        first.analyze.side_effect = ConnectionError("SSH socket closed")
        first.connected.return_value = False
        def recover(path, folder):
            fixture(folder)
            live.stop_event.set()
            return {"analysis_seconds": .1}
        second.analyze.side_effect = recover
        live = Live(self.db, self.root, Mock(side_effect=[first, second]), "unused", interval=.01)
        live.scope = "scope"
        spool = Spool(self.root/"live"/"pump", "pump", live.scope, self.db)
        spool.feed(HEADER+PACKET)
        live.spools = {"pump": spool}
        live.analyze()
        first.close.assert_called_once()
        self.assertEqual(self.db.status()["observations"], 1)
        self.assertEqual(spool.processed[spool.segments[0]["id"]], len(HEADER+PACKET))
        self.assertFalse(next(h for h in self.db.status()["health"] if h["source"] == "sensor")["error"])

    def test_backpressured_reader_retries_instead_of_permanently_exiting(self):
        live = Live(self.db, self.root, Mock(), "unused")
        live.scope = "scope"
        live.adapter = Mock()
        live.adapter.stream.return_value.read1.return_value = HEADER+PACKET
        spool = Mock()
        attempts = []
        def feed(data):
            attempts.append(data)
            if len(attempts) == 1:
                raise BufferError("Pending capture must finish analysis")
            live.stop_event.set()
        spool.feed.side_effect = feed
        live.spools = {"pump": spool}
        with patch.object(live.stop_event, "wait", return_value=False):
            live.read("pump")
        self.assertEqual(live.adapter.stream.call_count, 1)
        self.assertEqual(spool.reconnect.call_count, 1)
        self.assertIsNone(self.db.status()["health"][0]["error"])

    def test_failed_reanalysis_preserves_previous_capture_bytes(self):
        source = self.root/"growing.pcap"
        source.write_bytes(HEADER+PACKET)
        sensor = Mock()
        def analyze(path, folder):
            fixture(folder)
            return {"analysis_seconds": .1, "versions": {"zeek": "fixture", "tshark": "fixture"}}
        sensor.analyze.side_effect = analyze
        pipeline = Pipeline(self.db, self.root, sensor)
        previous = pipeline.import_file(source, "pump", "test", logical_id="growing")
        source.write_bytes(HEADER+PACKET*2)
        sensor.analyze.side_effect = RuntimeError("interrupted analysis")
        with self.assertRaisesRegex(RuntimeError, "interrupted"):
            pipeline.import_file(source, "pump", "test", logical_id="growing")
        retained = Path(previous["raw_capture"]).read_bytes()
        self.assertEqual(complete_pcap(retained)[1]["sha256"], previous["sha256"])
        self.assertEqual(self.db.status()["captures"][0]["sha256"], previous["sha256"])

    def test_successful_reanalysis_replaces_raw_without_accumulating_versions(self):
        source = self.root/"growing.pcap"
        source.write_bytes(HEADER+PACKET)
        sensor = Mock()
        sensor.analyze.side_effect = lambda path, folder: (fixture(folder) or {"analysis_seconds": .1})
        pipeline = Pipeline(self.db, self.root, sensor)
        first = pipeline.import_file(source, "pump", "test", logical_id="growing")
        source.write_bytes(HEADER+PACKET*2)
        last = pipeline.import_file(source, "pump", "test", logical_id="growing")
        self.assertNotEqual(first["sha256"], last["sha256"])
        self.assertEqual(len(list((self.root/"artifacts").rglob("*.pcap"))), 1)
        self.assertEqual(complete_pcap(Path(last["raw_capture"]).read_bytes())[1]["sha256"], last["sha256"])

    def api(self, path, data=None, headers=None):
        live = Mock(running=False, interval=20, scope=None)
        live.status.return_value = {"state": "stopped"}
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler(self.db, live, 8878))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            request = urllib.request.Request(f"http://127.0.0.1:{server.server_port}"+path,
                                             data=json.dumps(data).encode() if data is not None else None,
                                             headers=headers or {})
            try:
                with urllib.request.urlopen(request) as response:
                    return response.status, response.read()
            except urllib.error.HTTPError as error:
                return error.code, error.read()
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_api_rejects_cross_origin_control(self):
        code, body = self.api("/api/live", {"enabled": True}, {"Content-Type": "application/json", "Origin": "http://untrusted.invalid"})
        self.assertEqual(code, 403)

    def test_api_rejects_non_json_and_arbitrary_control(self):
        self.assertEqual(self.api("/api/live", {"enabled": True})[0], 415)
        self.assertEqual(self.api("/api/import", {"path": "private"}, {"Content-Type": "application/json"})[0], 400)

    def test_api_query_and_export_use_same_filters(self):
        self.db.ingest(capture(), [flow()], [])
        code, body = self.api("/api/flows?scope=test&transport=tcp&q=2575&limit=1")
        self.assertEqual(code, 200)
        result = json.loads(body)["records"]
        export = self.api("/api/export.jsonl?scope=test&transport=tcp&q=2575")[1]
        self.assertEqual(json.loads(export)["flow_id"], result[0]["flow_id"])
        self.assertEqual(self.api("/api/export.jsonl?transport=udp")[1], b"")

    def test_summary_uses_capture_time_and_canonical_counters(self):
        self.db.ingest(capture(), [flow()], [])
        self.db.ingest(capture("two", "mirror"), [flow("two", "mirror")], [])
        summary = self.db.summary()
        self.assertEqual(summary["window_end"], 100)
        self.assertEqual(summary["endpoints"][0]["connections"], 1)
        self.assertEqual(summary["endpoints"][0]["payload_bytes"], 160)


if __name__ == "__main__":
    unittest.main()
