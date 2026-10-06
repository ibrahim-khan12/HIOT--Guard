import json
import os
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch, Mock
from agent import Agent, synthetic_image
from config import CAPTURE_ROLES, NORMAL_ROLES, ROLES, address, expected, registry
from gns3 import GNS3, IMAGE, MANIFEST_FILE, private_url, request_json
from monitor import Capture, Engine
from server import Lab
from verify_gns3 import dropped_packets


def packet(src, dst, port, source_port=40000, at=None, payload="", **extra):
    from monitor import FIELDS
    row = dict.fromkeys(FIELDS, "")
    row.update({"frame.time_epoch": str(at or time.time()), "ip.src": src, "ip.dst": dst,
                "tcp.srcport": str(source_port), "tcp.dstport": str(port), "tcp.flags.syn": "True",
                "tcp.flags.ack": "False", "tcp.seq_raw": "1234", "tcp.len": "0", "tcp.payload": payload})
    row.update(extra)
    return row


class EngineTests(unittest.TestCase):
    def test_portable_topology_can_be_attached_without_rebuilding(self):
        archive_path = Path(__file__).with_name("HIoT-Mini-Hospital-Expanded.gns3project")
        with zipfile.ZipFile(archive_path) as archive:
            self.assertIsNone(archive.testzip())
            self.assertFalse(any(name.endswith((".pcap", ".pcapng")) for name in archive.namelist()))
            project = json.loads(archive.read("project.gns3"))
        nodes = project["topology"]["nodes"]
        links = project["topology"]["links"]
        self.assertEqual((len(nodes), len(links)), (19, 18))

        def api(endpoint, data=None):
            if endpoint == "/version":
                return {"version": "2.2.61"}
            if endpoint == f"/projects/{project['project_id']}":
                return project
            if endpoint.endswith("/nodes"):
                return nodes
            if endpoint.endswith("/links"):
                return links
            raise AssertionError(endpoint)

        with tempfile.TemporaryDirectory() as folder:
            adapter = GNS3("http://192.168.209.142", folder)
            with patch.object(adapter, "api", side_effect=api):
                manifest = adapter.attach_imported(project["project_id"])
                with self.assertRaisesRegex(ValueError, "already exists"):
                    adapter.attach_imported(project["project_id"])
            self.assertEqual(set(manifest["nodes"]), set(ROLES))
            self.assertEqual(set(manifest["links"]), set(ROLES) - {"gateway"})
            self.assertEqual(set(manifest["gateway_links"]), {"staff", "medical", "services"})
            self.assertTrue((adapter.folder / MANIFEST_FILE).exists())

    def test_hospital_registry_and_expected_paths(self):
        self.assertEqual(len(ROLES), 16)
        self.assertEqual(len(CAPTURE_ROLES), 13)
        self.assertNotIn(address("unregistered", "gns3"), registry("gns3"))
        for role, service, port in (("modality", "pacs", 11112), ("ultrasound", "pacs", 11112),
                                    ("pump", "ehr", 2575), ("monitor", "ehr", 2575),
                                    ("lab_analyzer", "ehr", 2575), ("mri", "pacs", 11112),
                                    ("xray", "pacs", 11112), ("ventilator", "ehr", 2575),
                                    ("dialysis", "ehr", 2575), ("ecg", "ehr", 2575),
                                    ("vendor", "pump", 8082)):
            self.assertTrue(expected(role, address(service, "gns3"), port, "gns3"))
        self.assertFalse(expected("unregistered", address("ehr", "gns3"), 8081, "gns3"))

    def test_four_synthetic_imaging_modalities_are_distinct(self):
        for role, modality in (("modality", "CT"), ("ultrasound", "US"), ("mri", "MR"), ("xray", "DX")):
            self.assertEqual(synthetic_image(role).Modality, modality)
        self.assertEqual(synthetic_image("modality").PatientID, "LAB_ONLY")

    def test_new_gns3_project_contains_real_actor_links(self):
        with tempfile.TemporaryDirectory() as folder:
            adapter = GNS3("http://192.168.209.142", folder)
            created = []
            def api(endpoint, data=None):
                if endpoint == "/version":
                    return {"version": "2.2.61"}
                if endpoint == "/computes":
                    return [{"compute_id": "vm", "connected": True, "capabilities": {"platform": "linux", "node_types": ["docker"]}}]
                if endpoint == "/projects":
                    return {"project_id": "fresh", "name": data["name"]}
                if endpoint.endswith("/nodes"):
                    created.append(data)
                    return {"node_id": f"node-{len(created)}"}
                if endpoint.endswith("/links"):
                    return {"link_id": f"link-{len(adapter.manifest['links']) + len(adapter.manifest['gateway_links'])}"}
                return {}
            with patch.object(adapter, "api", side_effect=api):
                manifest = adapter.build()
            self.assertEqual(set(manifest["nodes"]), set(ROLES))
            self.assertEqual(set(manifest["links"]), set(ROLES) - {"gateway"})
            self.assertEqual(len(manifest["switches"]), 3)
            medical_switch = next(n for n in created if n["node_type"] == "ethernet_switch" and n["name"] == "medical switch")
            self.assertEqual(len(medical_switch["properties"]["ports_mapping"]), 16)
            self.assertTrue((adapter.folder / MANIFEST_FILE).exists())
            self.assertTrue(all(n["properties"]["image"] == IMAGE for n in created if n["node_type"] == "docker"))

    def test_background_command_retries_do_not_repeat_probes(self):
        agent = Agent("workstation", "local")
        release, entered = threading.Event(), threading.Event()
        def command(_):
            entered.set()
            release.wait(2)
            return {"success": True}
        with patch.object(agent, "action", side_effect=command) as action:
            try:
                accepted = agent.begin_command("recon", "one-command")
                self.assertTrue(entered.wait(2))
                self.assertTrue(accepted["running"])
                self.assertEqual(agent.begin_command("recon", "one-command")["id"], "one-command")
                with self.assertRaisesRegex(ValueError, "Wait for"):
                    agent.begin_command("recon", "another-command")
            finally:
                release.set()
                agent.command_thread.join(timeout=3)
            self.assertFalse(agent.command["running"])
            self.assertEqual(agent.begin_command("recon", "one-command")["result"], {"success": True})
            action.assert_called_once_with("recon")

    def test_stop_cancels_remaining_bounded_probes(self):
        agent = Agent("workstation", "local")
        def interrupted(*_):
            agent.action("stop")
            raise OSError("Stopped")
        with patch.object(agent, "connect", side_effect=interrupted) as connect:
            result = agent.action("recon")
        self.assertEqual(len(result), 1)
        connect.assert_called_once()

    def test_reset_does_not_score_old_syn_retransmissions(self):
        with tempfile.TemporaryDirectory() as folder:
            lab = Lab(folder)
            lab.mode, lab.engine = "gns3", Engine("gns3")
            source = address("workstation", "gns3")
            rows = [packet(source, address(target, "gns3"), port, 40000 + index)
                    for index, (target, port) in enumerate((t, p) for t in ("pacs", "ehr") for p in (445, 3389, 11112))]
            for row in rows:
                lab.engine.consume(row)
            self.assertEqual(lab.engine.assets[source]["peakRisk"], 85)
            with patch.object(lab, "agent", return_value={}):
                lab.action({"action": "reset"})
            for row in rows:
                lab.engine.consume(row)
            self.assertEqual(lab.engine.assets[source]["peakRisk"], 0)
            self.assertEqual(lab.engine.assets[source]["response"], "none")

    def test_pause_and_immediate_resume_does_not_revive_old_generator(self):
        agent = Agent("workstation", "local")
        sent = threading.Event()
        with patch.object(agent, "normal_once", side_effect=lambda: sent.set()) as probe:
            try:
                agent.action("start")
                self.assertTrue(sent.wait(2))
                original = agent.traffic_thread
                agent.action("stop")
                self.assertFalse(original.is_alive())
                sent.clear()
                agent.action("start")
                self.assertTrue(sent.wait(2))
                self.assertIsNot(agent.traffic_thread, original)
                agent.action("stop")
                self.assertEqual(probe.call_count, 2)
            finally:
                agent.action("stop")

    def test_repeated_start_uses_one_generator(self):
        agent = Agent("workstation", "local")
        with patch("agent.threading.Thread") as thread:
            agent.action("start")
            agent.action("start")
        thread.assert_called_once()
        thread.return_value.start.assert_called_once()

    def test_json_control_reads_a_complete_reply_before_closing(self):
        connection = Mock()
        response = connection.getresponse.return_value
        response.status = 200
        response.read.return_value = b'{"observed": true}'
        with patch("gns3.http.client.HTTPConnection", return_value=connection):
            self.assertEqual(request_json("http://127.0.0.1:8877/api/status"), {"observed": True})
        response.read.assert_called_once()
        self.assertNotIn("Connection", connection.request.call_args.kwargs["headers"])
        connection.close.assert_called_once()

    def test_json_control_preserves_http_errors_and_closes(self):
        connection = Mock()
        response = connection.getresponse.return_value
        response.status = 400
        response.read.return_value = b'{"error":"Invalid policy"}'
        with patch("gns3.http.client.HTTPConnection", return_value=connection):
            with self.assertRaisesRegex(RuntimeError, "HTTP 400.*Invalid policy"):
                request_json("http://127.0.0.1:8877/api/action", {"action": "invalid"})
        connection.close.assert_called_once()

    def test_pcap_stream_has_a_connect_deadline_but_no_quiet_network_timeout(self):
        adapter = GNS3("http://192.168.209.142", ".")
        adapter.manifest = {"project_id": "project", "links": {"pump": "link"}}
        connection = Mock()
        response = connection.getresponse.return_value
        response.status = 200
        response.read1.return_value = b"measured-pcap-bytes"
        with patch.object(adapter, "api", return_value={"capturing": True}), patch("gns3.http.client.HTTPConnection", return_value=connection) as factory:
            stream = adapter.stream("pump")
        factory.assert_called_once_with("192.168.209.142", None, timeout=20)
        connection.sock.settimeout.assert_called_once_with(None)
        connection.getresponse.assert_not_called()
        self.assertEqual(stream.read1(1024), b"measured-pcap-bytes")
        stream.close()
        connection.sock.shutdown.assert_called_once()
        response.close.assert_called_once()
        connection.close.assert_called_once()

    def test_failed_pcap_open_closes_its_connection(self):
        adapter = GNS3("http://192.168.209.142", ".")
        adapter.manifest = {"project_id": "project", "links": {"pump": "link"}}
        connection = Mock()
        response = connection.getresponse.return_value
        response.status = 404
        response.read.return_value = b"Missing capture"
        with patch.object(adapter, "api", return_value={"capturing": True}), patch("gns3.http.client.HTTPConnection", return_value=connection):
            stream = adapter.stream("pump")
            with self.assertRaisesRegex(RuntimeError, "GNS3 capture HTTP 404"):
                stream.read1(1024)
            stream.close()
        connection.close.assert_called_once()

    def test_gateway_drop_counter_uses_the_actual_source(self):
        table = """Chain IOMT_LAB (1 references)
 pkts bytes target prot opt in out source destination
  4  240 DROP all -- * * 10.77.10.10 0.0.0.0/0
  2  120 DROP all -- * * 0.0.0.0/0 10.77.10.10
  7  420 DROP all -- * * 10.77.20.20 0.0.0.0/0
"""
        self.assertEqual(dropped_packets(table, "10.77.10.10"), 4)
        self.assertEqual(dropped_packets(table, "10.77.20.20"), 7)

    def test_gateway_drop_counter_does_not_treat_rule_presence_as_blocking(self):
        table = "0 0 DROP all -- * * 10.77.10.10 0.0.0.0/0"
        self.assertEqual(dropped_packets(table, "10.77.10.10"), 0)

    def test_no_traffic_means_no_inventory_or_incident(self):
        engine = Engine("gns3")
        self.assertEqual(engine.snapshot()["assets"], [])
        self.assertEqual(engine.snapshot()["events"], [])

    def test_normal_clinical_connection_does_not_score(self):
        engine = Engine("gns3")
        engine.consume(packet(address("pump", "gns3"), address("ehr", "gns3"), 2575))
        self.assertEqual(engine.assets[address("pump", "gns3")]["risk"], 0)

    def test_recon_requires_correlated_packet_indicators(self):
        responses = []
        engine = Engine("gns3", lambda *value: responses.append(value))
        for index, (target, port) in enumerate((target, port) for target in ("pacs", "ehr") for port in (445, 3389, 11112)):
            engine.consume(packet(address("workstation", "gns3"), address(target, "gns3"), port, 40000 + index))
        self.assertEqual(engine.assets[address("workstation", "gns3")]["risk"], 85)
        self.assertEqual(responses, [(address("workstation", "gns3"), "quarantined")])

    def test_syn_retransmission_not_counted_as_extra_attempt(self):
        responses = []
        engine = Engine("gns3", lambda *value: responses.append(value))
        row = packet(address("pump", "gns3"), address("pacs", "gns3"), 11112)
        for _ in range(5):
            engine.consume(row)
        self.assertFalse(responses)

    def test_port_number_alone_does_not_classify_dicom(self):
        engine = Engine("gns3")
        engine.consume(packet(address("modality", "gns3"), address("pacs", "gns3"), 11112))
        self.assertNotIn("DICOM", engine.assets[address("modality", "gns3")]["protocols"])

    def test_peak_risk_is_retained_after_window_expires(self):
        engine = Engine("gns3")
        now = time.time()
        source = address("workstation", "gns3")
        for index, (target, port) in enumerate((target, port) for target in ("pacs", "ehr") for port in (445, 3389, 11112)):
            engine.consume(packet(source, address(target, "gns3"), port, 40000 + index, at=now))
        engine.consume(packet(source, address("ehr", "gns3"), 8081, 41000, at=now + 65))
        self.assertEqual(engine.assets[source]["risk"], 0)
        self.assertEqual(engine.assets[source]["peakRisk"], 85)

    def test_service_control_requires_approval_for_pump_isolation(self):
        agent = Agent("pacs", "local")
        with self.assertRaises(ValueError):
            agent.apply_policy({"workstation": "normal", "pump": "isolated", "reviewer": "Reviewer"})
        agent.apply_policy({"workstation": "normal", "pump": "restricted"})
        with self.assertRaises(ValueError):
            agent.apply_policy({"workstation": "normal", "pump": "isolated"})
        agent.apply_policy({"workstation": "normal", "pump": "isolated", "reviewer": "Reviewer"})
        self.assertEqual(agent.policy["pump"], "isolated")

    def test_occupied_ports_do_not_take_over_an_existing_lab(self):
        with tempfile.TemporaryDirectory() as folder:
            lab = Lab(folder)
            fake_socket = Mock()
            fake_socket.bind.side_effect = OSError("Port occupied")
            context = Mock()
            context.__enter__ = Mock(return_value=fake_socket)
            context.__exit__ = Mock(return_value=False)
            with patch("server.socket.socket", return_value=context), patch.object(lab, "agent") as agent:
                with self.assertRaises(RuntimeError):
                    lab.start("local")
                agent.assert_not_called()

    def test_medical_device_restricts_not_isolates(self):
        responses = []
        engine = Engine("gns3", lambda *value: responses.append(value))
        for index in range(3):
            engine.consume(packet(address("pump", "gns3"), address("pacs", "gns3"), 11112, 40000 + index))
        self.assertEqual(responses, [(address("pump", "gns3"), "restricted")])

    def test_external_server_urls_rejected(self):
        for url in ("http://8.8.8.8:3080", "file:///etc/passwd", "http://admin:secret@127.0.0.1:3080", "http://0.0.0.0:3080"):
            with self.assertRaises(ValueError):
                private_url(url)

    def test_gateway_firewall_is_scoped_and_preserves_telemetry(self):
        agent = Agent("gateway", "gns3")
        with patch("agent.subprocess.run", return_value=Mock(returncode=0)) as run, patch("agent.subprocess.check_output", return_value="rules"):
            agent.apply_policy({"workstation": "quarantined", "pump": "restricted"})
        restore = [call for call in run.call_args_list if call.args[0][0] == "iptables-restore"][0]
        rules = restore.kwargs["input"]
        self.assertIn("-F IOMT_LAB", rules)
        self.assertNotIn("-F FORWARD", rules)
        self.assertLess(rules.index("--dport 2575 -j ACCEPT"), rules.index("-s 10.77.20.20 -j DROP"))


@unittest.skipUnless(os.environ.get("IOMT_INTEGRATION") == "1", "Set IOMT_INTEGRATION=1 for real sockets and packet capture")
class RealTrafficTests(unittest.TestCase):
    def wait_until(self, check, label, timeout=12):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if check():
                return
            time.sleep(0.2)
        self.fail("Timed out waiting for " + label)

    def test_real_capture_detects_and_changes_actual_service_access(self):
        with tempfile.TemporaryDirectory() as folder:
            lab = Lab(folder)
            try:
                lab.start("local")
                self.assertFalse(lab.engine.assets)
                lab.action({"action": "normal"})
                self.wait_until(lambda: any("DICOM" in a["protocols"] for a in lab.engine.assets.values()), "DICOM packet dissection")
                self.wait_until(lambda: any("HL7/MLLP" in a["protocols"] for a in lab.engine.assets.values()), "HL7 payload evidence")
                baseline = lab.action({"action": "verify"})["result"]
                self.assertTrue(all(r["success"] for r in baseline.values()))
                self.assertEqual(set(baseline), set(NORMAL_ROLES))
                self.assertGreaterEqual(lab.agent("pacs", "/state")["counters"]["dicom_store"], 4)
                self.assertGreaterEqual(lab.agent("ehr", "/state")["counters"]["hl7_received"], 6)
                self.assertGreaterEqual(lab.agent("pump", "/state")["counters"]["maintenance_received"], 1)
                self.assertTrue(lab.action({"action": "unknown"})["result"]["success"])
                self.wait_until(lambda: address("unregistered", "local") in lab.engine.assets, "unknown asset in PCAP")
                self.assertFalse(lab.engine.assets[address("unregistered", "local")]["registered"])
                lab.action({"action": "recon"})
                self.wait_until(lambda: lab.policy["workstation"] == "quarantined", "traffic-driven quarantine")
                after = lab.action({"action": "verify"})["result"]
                self.assertFalse(after["workstation"]["success"])
                self.assertTrue(after["pump"]["success"])
                self.assertEqual(lab.engine.assets[address("workstation", "local")]["risk"], 85)
                lab.action({"action": "anomaly"})
                self.wait_until(lambda: lab.policy["pump"] == "restricted", "pump safety restriction")
                restricted = lab.action({"action": "verify"})["result"]
                self.assertTrue(restricted["pump"]["success"])
                self.assertFalse(restricted["vendor"]["success"])
                with self.assertRaises(ValueError):
                    lab.action({"action": "approve", "reviewer": ""})
                lab.action({"action": "approve", "reviewer": "Test reviewer"})
                isolated = lab.action({"action": "verify"})["result"]
                self.assertFalse(isolated["pump"]["success"])
                self.assertTrue(isolated["modality"]["success"])
                self.assertGreater(lab.engine.frames, 0)
                self.assertTrue(all(c.output.stat().st_size > 0 for c in lab.captures))
                lab.action({"action": "reset"})
                reset = lab.action({"action": "verify"})["result"]
                self.assertTrue(all(r["success"] for r in reset.values()))
                native_file = lab.captures[0].output
                lab.stop()
                streamed_engine = Engine("local")
                with native_file.open("rb") as stream:
                    decoder = Capture(streamed_engine, os.path.join(folder, "stream-copy.pcapng"), stream=stream)
                    try:
                        self.wait_until(lambda: decoder.process.poll() is not None, "stream decoder completion")
                        self.wait_until(lambda: streamed_engine.frames > 0, "streamed PCAP packet parsing")
                        self.assertEqual(decoder.process.returncode, 0)
                        self.assertTrue(any("DICOM" in a["protocols"] for a in streamed_engine.assets.values()))
                    finally:
                        decoder.stop()
            finally:
                lab.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)
