from copy import deepcopy
from pathlib import Path
from contextlib import ExitStack
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from module4.sentinel_full import (AnalyzerBatch, IntegrityError, METHODS, cache_valid,
                                   capture_outcome, identity, inventory, metrics,
                                   object_hash, packet_info, pilot_check, summarize)
from module4.sentinel_full import SCHEMA, evaluate, sha256
from module4.experiment import write_json


def target(ip="10.0.0.1", predicted="unknown", method="statistics"):
    decisions = {name: {"category": "unknown"} for name in METHODS}
    decisions[method]["category"] = predicted
    return {"ip": ip, "presence": "observed_transmitting", "decisions": decisions}


def result(member="one", status="completed", predicted="unknown", mac="00:11:22:33:44:55"):
    return {"member": member, "folder": "Example", "target_mac": mac, "cohort": "expansion",
            "expected": "unknown", "status": status, "targets": [target(predicted=predicted)],
            "missing_target_ips": [] if status == "completed" else ["10.0.0.2"]}


class FullSentinelTests(unittest.TestCase):
    def test_inventory_includes_all_captures_and_excludes_resource_forks(self):
        names = [f"captures_IoT-Sentinel/Example/Setup-A-{i}-STA.pcap" for i in range(1, 21)]
        self.assertEqual(len(inventory(names + ["__MACOSX/._dummy", "captures_IoT-Sentinel/.DS_Store"])), 20)
        for unsafe in ("../outside", "/absolute", "folder\\file", "C:/absolute"):
            with self.assertRaises(IntegrityError):
                inventory(names + [unsafe])
        with self.assertRaises(IntegrityError):
            inventory(names + [names[0]])

    def test_identity_review_and_indirect_visibility(self):
        self.assertEqual(identity("EdimaxCam2")["publisher_identifier"], "EdimaxCam")
        self.assertEqual(identity("HueSwitch")["visibility"], "gateway_mediated")
        self.assertEqual(identity("HomeMaticPlug")["expected"], "unknown")
        self.assertIsNone(identity("UnlistedHospitalDevice")["expected"])

    def test_any_false_alias_fails_even_when_primary_alias_is_unknown(self):
        row = result()
        row["targets"].append(target("192.168.0.20", "infusion_pump"))
        self.assertEqual(capture_outcome(row, "statistics"), "false_medical")
        self.assertEqual(capture_outcome(row, "selected_fallback"), "correct_unknown")

    def test_missing_targets_and_import_failures_never_become_successes(self):
        partial = result(status="partial")
        failed = result(status="unevaluable")
        failed["targets"] = []
        cards = metrics([partial, failed])["methods"]["statistics"]
        self.assertEqual(cards["correct_unknown"], 0)
        self.assertEqual(cards["unevaluable"], 2)
        partial["targets"][0]["decisions"]["statistics"]["category"] = "infusion_pump"
        self.assertEqual(capture_outcome(partial, "statistics"), "false_medical")

    def test_unreviewed_identity_never_enters_target_error_metrics(self):
        row = result(predicted="infusion_pump")
        row["expected"] = None
        self.assertEqual(capture_outcome(row, "statistics"), "unevaluable")
        self.assertEqual(metrics([row])["methods"]["statistics"]["wrong_address_assignments"], 0)

    def test_shared_mac_folders_form_one_group_and_repeats_do_not_dominate_macro(self):
        rows = [result(f"a{i}") for i in range(20)]
        second = result("b", predicted="infusion_pump", mac="11:22:33:44:55:66")
        rows[0]["folder"], rows[1]["folder"] = "HueBridge", "HueSwitch"
        summary = summarize(rows + [second])
        self.assertEqual(len(summary["per_mac"]), 2)
        self.assertEqual(summary["equal_mac_group_average"]["statistics"]["mean_complete_rejection_fraction"], .5)

    def test_resume_requires_same_contract_member_input_and_completed_inference(self):
        entry = {"member": "one", "sha256": "capture-hash"}
        value = {"fingerprint": "contract", "member": "one", "input_sha256": "capture-hash",
                 "status": "completed", "identifier_time_invariance": True}
        self.assertTrue(cache_valid(value, "contract", entry))
        for change in ({"fingerprint": "changed-model"}, {"member": "two"}, {"input_sha256": "modified"},
                       {"status": "unevaluable"}, {"identifier_time_invariance": False}):
            self.assertFalse(cache_valid(value | change, "contract", entry))
        self.assertEqual(object_hash({"a": 1, "b": 2}), object_hash({"b": 2, "a": 1}))

    def test_pilot_reproduction_detects_changed_prediction(self):
        row = result()
        row["cohort"] = "pilot"
        expected = {"targets": [{"member": "one", **row["targets"][0]}]}
        pilot_check([row], expected)
        changed = deepcopy(row)
        changed["targets"][0]["decisions"]["statistics"]["category"] = "ct"
        with self.assertRaises(IntegrityError):
            pilot_check([changed], expected)

    @patch("module4.sentinel_full.subprocess.run")
    def test_packet_audit_validates_all_mac_ip_aliases(self, run):
        from module4.external_pilot import FIELDS
        def packet(ip, frame):
            row = dict.fromkeys(FIELDS, "")
            row.update({"frame.number": frame, "eth.src": "00:11:22:33:44:55", "ip.src": ip,
                        "frame.len": "64", "frame.cap_len": "64", "_ws.col.Protocol": "UDP"})
            return "\t".join(row[key] for key in FIELDS)
        run.return_value = SimpleNamespace(stdout="\n".join((packet("0.0.0.0", "1"), packet("10.0.0.1", "2"),
                                                              packet("192.168.0.20", "3"))), stderr="")
        audit = packet_info("input", "00:11:22:33:44:55", "tshark")
        self.assertEqual(set(audit["source_ip_counts"]), {"10.0.0.1", "192.168.0.20"})
        self.assertEqual(len(audit["bindings"]), 2)

    @patch("module4.local_sensor.docker_zeek")
    @patch("module4.sentinel_full.time.monotonic")
    def test_analyzer_recycles_after_twenty_imports_or_six_hundred_seconds(self, clock, create):
        clock.return_value = 10
        batch = AnalyzerBatch(Path("root"), "tshark")
        for _ in range(20):
            batch.get()
        self.assertEqual(create.call_count, 1)
        batch.get()
        self.assertEqual(create.call_count, 2)
        clock.return_value = 610
        batch.get()
        self.assertEqual(create.call_count, 3)
        batch.close()

    def test_capture_failure_continues_and_resume_skips_only_verified_success(self):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary)
            (root / "archive.zip").write_bytes(b"archive")
            pilot = root / "pilot"
            pilot.mkdir()
            write_json(pilot / "report.json", {"targets": [], "unchanged_model_hashes": {}})
            records = []
            for index in (1, 2):
                pcap = root / f"{index}.pcap"
                pcap.write_bytes(bytes([index]))
                records.append({"id": f"c{index:04d}", "member": f"file-{index}", "folder": "Example",
                                "target_mac": "00:11:22:33:44:55", "cohort": "expansion", "expected": "unknown",
                                "pcap": str(pcap), "sha256": sha256(pcap), "audit_status": "completed",
                                "visibility": "network_endpoint", "shared_mac_folders": ["Example"],
                                "packet_audit": {"source_ip_counts": {"10.0.0.1": 1}}})
            manifest = {"schema_version": SCHEMA, "archive": str(root / "archive.zip"),
                        "archive_sha256": sha256(root / "archive.zip"), "pilot": str(pilot),
                        "pilot_report_sha256": sha256(pilot / "report.json"), "records": records,
                        "folders": {"Example": {"visibility": "network_endpoint"}},
                        "mac_groups": {"00:11:22:33:44:55": ["Example"]}}
            write_json(root / "manifest.json", manifest)
            (root / "manifest.sha256").write_text(sha256(root / "manifest.json"))
            stack.enter_context(patch("module4.sentinel_full.load_models", return_value=({}, {})))
            stack.enter_context(patch("module4.sentinel_full.load_selected", return_value=({}, {})))
            contract = stack.enter_context(patch("module4.sentinel_full.runtime_contract",
                                                 return_value={"sources": {}, "artifacts": {}}))
            stack.enter_context(patch("module4.sentinel_full.AnalyzerBatch"))
            importer = stack.enter_context(patch("module4.sentinel_full.imported_capture",
                                                 side_effect=[OSError("capture failed"), root / "import"]))
            stack.enter_context(patch("module4.sentinel_full.validate_import", return_value=({}, [], [], {}, {})))
            stack.enter_context(patch("module4.sentinel_full.infer", return_value=[target()]))
            first = evaluate(root, root, root, "tshark")
            self.assertEqual(first["summary"]["overall"]["statuses"], {"unevaluable": 1, "completed": 1})
            self.assertEqual(importer.call_count, 2)
            importer.reset_mock(side_effect=True)
            importer.side_effect = OSError("still failed")
            resumed = evaluate(root, root, root, "tshark", resume=True)
            self.assertEqual(resumed["capture_processing"]["verified_cache_hits"], 1)
            self.assertEqual(importer.call_count, 1)
            self.assertTrue((root / "items/c0001/a001.json").is_file())
            self.assertTrue((root / "items/c0001/a002.json").is_file())
            contract.return_value = {"sources": {}, "artifacts": {}, "changed": True}
            with self.assertRaises(IntegrityError):
                evaluate(root, root, root, "tshark", resume=True)


if __name__ == "__main__":
    unittest.main()
