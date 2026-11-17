import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

from module2.parsing import dicom_request_contexts, hl7_messages
from module4 import MEDICAL, OTHER, ROLE_LABELS, UNKNOWN
from module4.classifier import DICOM_CATEGORIES, HL7_CATEGORIES, endpoint_rows, rule
from module4.collect import EVALUATION_SESSIONS, profile
from module4.experiment import decisions, evaluate, train, write_json


def fixture(scope, offset=0):
    ips = [f"10.70.{offset}.{i}" for i in range(1, 13)]
    record = {"schema_version": "hiot.discovery.recording.v1", "source_id": "test", "scope": scope,
              "assets": [{"asset_id": f"{scope}-{i}", "ip": ip, "address_kind": "unicast_address",
                          "presence": "observed_transmitting"} for i, ip in enumerate(ips)],
              "flows": []}
    observations = {category: ("DICOM", {"requested_abstract_syntax_uids": [uid]})
                    for uid, category in DICOM_CATEGORIES.items()}
    observations.update({category: ("HL7/MLLP", {"message_type": "ORU^R01", "measurement_kinds": [kind]})
                         for kind, categories in HL7_CATEGORIES.items() for category in categories})
    for index, category in enumerate(MEDICAL):
        protocol, metadata = observations[category]
        target = ips[10] if protocol == "HL7/MLLP" else ips[11]
        for count in range(3):
            flow_id = f"{scope}-{index}-{count}"
            record["flows"].append({"flow_id": flow_id, "source_ip": ips[index], "destination_ip": target,
                                    "transport": "tcp", "start_time": 3 * count,
                                    "origin_packets": 5, "response_packets": 5, "origin_bytes": 100,
                                    "response_bytes": 20, "evidence": [
                    {"protocol": protocol, "direction": "originator", "parser_status": "confirmed",
                     "metadata": metadata, "capture_id": scope, "frame": count * 2 + 1},
                    {"protocol": protocol, "direction": "responder", "parser_status": "confirmed",
                     "metadata": {"message_type": "ACK"} if protocol == "HL7/MLLP" else {},
                     "capture_id": scope, "frame": count * 2 + 2}]})
    labels = [{"ip": ip, "instance_id": f"{scope}-{index}", "category": category}
              for index, (ip, category) in enumerate(zip(ips, (*MEDICAL, OTHER, OTHER), strict=True))]
    return record, labels


class Module4Tests(unittest.TestCase):
    def test_measurement_normalization_and_payload_minimization(self):
        cases = ((b"HEART_RATE", "heart_rate"), (b"ECG_HEART_RATE", "heart_rate"),
                 (b"LAB_RATE", "flow_rate"), (b"PRIVATE_CODE", None))
        for code, expected in cases:
            with self.subTest(code=code):
                message = (b"\vMSH|^~\\&|SENDER|TEST|LAB|LAB|1||ORU^R01|1|P|2.5\r"
                           b"PID|1||PRIVATE_PATIENT\rOBX|1|NM|" + code + b"||PRIVATE_VALUE|units\r\x1c\r")
                result, issues = hl7_messages([(message, 4)])
                self.assertFalse(issues)
                metadata = result[0]["metadata"]
                self.assertEqual(metadata.get("measurement_kinds"), [expected] if expected else None)
                self.assertNotIn("PRIVATE", str(metadata))

    def test_storage_uid_requires_request_provenance(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "dicom-contexts.tsv"
            path.write_text("4\t0x01\tVerification (1.2.840.10008.1.1)|CT Image Storage (1.2.840.10008.5.1.4.1.1.2)\n"
                            "6\t0x02\tCT Image Storage (1.2.840.10008.5.1.4.1.1.2)\n")
            self.assertEqual(dicom_request_contexts(path), {4: ["1.2.840.10008.1.1", "1.2.840.10008.5.1.4.1.1.2"]})
            self.assertEqual(dicom_request_contexts(Path(temp) / "absent.tsv"), {})

    def test_rules_abstain_on_shared_heart_rate_sparse_and_responders(self):
        record, _ = fixture("rules")
        rows = endpoint_rows(record)
        self.assertEqual([rule(row)[0] for row in rows], [
            "infusion_pump", "ct", "mri", "ultrasound", "portable_xray", UNKNOWN, "lab_analyzer",
            "ventilator", "dialysis_machine", UNKNOWN, UNKNOWN, UNKNOWN])
        record["flows"] = [record["flows"][0]]
        self.assertEqual(rule(endpoint_rows(record)[0]), (UNKNOWN, "fewer_than_two_bidirectional_exchanges"))

    def test_collection_profiles_have_disjoint_medical_addresses(self):
        configured = set()
        for number in range(13):
            settings, _, order, schedule = profile(number, "holdout", 4057 + number)
            self.assertFalse(configured & set(settings["addresses"].values()))
            configured.update(settings["addresses"].values())
            self.assertEqual(len(order), 16)
            self.assertTrue(all(role in {actor for _, actor, _ in schedule} for role in (
                "pump", "modality", "monitor", "ecg")))

    def test_expanded_holdout_preserves_ground_truth_and_varies_ambiguous_cases(self):
        ambiguous = set()
        self.assertEqual(len({number for numbers in EVALUATION_SESSIONS.values() for number in numbers}), 12)
        for family, numbers in EVALUATION_SESSIONS.items():
            for number in numbers:
                settings, _, _, schedule = profile(number, family, 4057 + number)
                self.assertEqual(settings["traffic_profile"], family)
                self.assertEqual(len(set(settings["addresses"].values())), 15)
                self.assertEqual(settings["variants"]["workstation"], "verification")
                self.assertEqual(settings["variants"]["unregistered"], "generic_hl7")
                actors = {actor for _, actor, _ in schedule}
                self.assertTrue(set(ROLE_LABELS) <= actors)
                self.assertTrue(set(settings["variants"]) <= actors)
                if family == "eval-ambiguous":
                    masked = set(settings["variants"]) - {"workstation", "unregistered"}
                    self.assertEqual(len(masked), 2)
                    self.assertFalse(ambiguous & masked)
                    ambiguous.update(masked)
        self.assertEqual(len(ambiguous), 6)

    @unittest.skipUnless(importlib.util.find_spec("sklearn"), "Install requirements-module4.txt")
    def test_forest_comparison_holdout_and_identifier_invariance(self):
        with tempfile.TemporaryDirectory() as temp:
            from joblib import load

            folder = Path(temp)
            for index, split in enumerate(("train", "validate", "holdout")):
                record, labels = fixture(split, index)
                write_json(folder / f"{split}-data.json", record)
                write_json(folder / f"{split}.json", {"recordings": [
                    {"recording": f"{split}-data.json", "endpoints": labels}]})
            train(folder / "train.json", folder / "validate.json", folder / "fit")
            model = load(folder / "fit/model.joblib")
            report, rows = evaluate(folder / "holdout.json", model)
            self.assertEqual(report["methods"]["rules"]["correct"], 8)
            self.assertEqual(report["methods"]["protocol"]["abstained"], 12)
            self.assertEqual(report["methods"]["rules"]["classes"]["bedside_monitor"]["recall"], 0)
            self.assertEqual(sum(report["fallback_increment"].values()), 4)
            renamed = copy.deepcopy(record)
            renamed["scope"] = "renamed"
            for asset in renamed["assets"]:
                asset["ip"] = asset["ip"].replace("10.70.", "10.90.")
                asset["asset_id"] += "-changed"
                asset["configured"] = {"role": "changed"}
            for flow in renamed["flows"]:
                flow["source_ip"] = flow["source_ip"].replace("10.70.", "10.90.")
                flow["destination_ip"] = flow["destination_ip"].replace("10.70.", "10.90.")
                for item in flow["evidence"]:
                    item["metadata"].update(sender="renamed", calling_ae="renamed")
            self.assertEqual([row["decisions"] for row in rows],
                             [row["decisions"] for row in decisions(renamed, model)])
            with self.assertRaisesRegex(ValueError, "overlaps"):
                evaluate(folder / "validate.json", model)
