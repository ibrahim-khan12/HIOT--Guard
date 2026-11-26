"""Read existing recordings and reproduce Stage 1 evidence limitations.

No training, packet generation, network access, or production-code changes.
Fixtures are in-memory parser/export diagnostics, not captured-device results.
"""
import argparse
from collections import Counter, defaultdict
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from statistics import median
import sys

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from module2.parsing import hl7_messages
from module2.pcap import complete_pcap
from module4 import MEDICAL
from module4.classifier import DICOM_CATEGORIES, RECORDING_SCHEMA, endpoint_rows, rule


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def hl7(code="LAB_RATE^Rate^99LAB", ack="AA", control="CASE", ack_control=None):
    request = (f"MSH|^~\\&|SOURCE|LAB|RECEIVER|LAB|20261123000000||ORU^R01|{control}|P|2.5\r"
               f"OBX|1|NM|{code}||1|1\r")
    response = (f"MSH|^~\\&|RECEIVER|LAB|SOURCE|LAB|20261123000000||ACK|ACK{control}|P|2.5\r"
                f"MSA|{ack}|{ack_control or control}\r")
    result = []
    for index, (direction, message) in enumerate((("originator", request), ("responder", response))):
        parsed, issues = hl7_messages([(b"\x0b" + message.encode("ascii") + b"\x1c\r", index + 1)])
        if issues or len(parsed) != 1:
            raise ValueError(f"Unexpected fixture parsing failure: {issues}")
        result.append({**parsed[0], "direction": direction, "evidence_id": f"fixture-{index}"})
    return result


def fixture(evidence, flows=2, repetitions=1):
    origin, peer = "192.0.2.1", "192.0.2.2"
    recording = {"schema_version": RECORDING_SCHEMA, "source_id": "in-memory-fixture",
                 "scope": "stage1-diagnostic", "assets": [{"ip": origin, "asset_id": "sender",
                 "address_kind": "unicast_address", "presence": "observed_transmitting"}], "flows": []}
    for number in range(flows):
        events = []
        for repetition in range(repetitions):
            for item in evidence:
                events.append({**deepcopy(item), "evidence_id": f"f{number}-r{repetition}-{item['direction']}"})
        recording["flows"].append({"flow_id": f"flow-{number}", "source_ip": origin,
                                  "destination_ip": peer, "transport": "tcp", "start_time": number * 10,
                                  "origin_packets": 10, "response_packets": 8, "evidence": events})
    row = endpoint_rows(recording)[0]
    label, reason = rule(row)
    return {"category": label, "reason": reason, "features": dict(row["features"]),
            "supported": dict(row["supported"])}


def diagnostics():
    cases = {}
    for name, kwargs, expected in [
        ("local_rate_two_flows", {}, "infusion_pump"),
        ("application_reject_ack", {"ack": "AR"}, "infusion_pump"),
        ("mismatched_ack_control_id", {"ack_control": "UNRELATED"}, "infusion_pump"),
        ("local_code_wrong_namespace", {"code": "LAB_RATE^Rate^LN"}, "infusion_pump"),
        ("loinc_heart_rate", {"code": "8867-4^Heart rate^LN"}, "unknown"),
        ("loinc_respiratory_rate", {"code": "9279-1^Respiratory rate^LN"}, "unknown"),
        ("shared_heart_rate", {"code": "HEART_RATE^Heart rate^99LAB"}, "unknown"),
        ("relay_forwarding_rate", {}, "infusion_pump"),
    ]:
        result = fixture(hl7(**kwargs))
        if result["category"] != expected:
            raise ValueError(f"Current behavior changed for {name}: {result}")
        cases[name] = result
    cases["three_exchanges_one_connection"] = fixture(hl7(), flows=1, repetitions=3)
    if cases["three_exchanges_one_connection"]["category"] != "unknown":
        raise ValueError("Persistent-connection diagnostic changed")
    for uid, category in DICOM_CATEGORIES.items():
        evidence = [{"protocol": "DICOM", "parser_status": "confirmed", "direction": "originator",
                     "metadata": {"requested_abstract_syntax_uids": [uid]}},
                    {"protocol": "DICOM", "parser_status": "confirmed", "direction": "responder", "metadata": {}}]
        result = fixture(evidence)
        if result["category"] != category:
            raise ValueError(f"DICOM diagnostic changed: {category}")
        cases[f"{category}_proposal_without_transfer_evidence"] = result
    return {"kind": "in_memory_parser_and_recording_diagnostics_not_live_captures",
            "interpretation": "These reproduce current behavior, including limitations; they are not correctness passes.",
            "cases": cases}


def summarize_study(study):
    splits = {}
    recording_hashes, capture_hashes = {}, {}
    identities = set()
    scopes = set()
    spans, collector_times = [], []
    semantic_pairs_equal = 0
    counts = Counter()
    for split in ("training", "validation", "test"):
        manifest = read(study / f"{split}.json")
        categories = defaultdict(lambda: {"rows": 0, "rule_decisions": Counter(), "protocols": Counter(),
                                          "measurement_kinds": Counter(), "requested_uids": Counter(),
                                          "example": None})
        for entry in manifest["recordings"]:
            path = study / entry["recording"]
            recording = read(path)
            recording_hashes[str(path.relative_to(REPO))] = digest(path)
            key = recording["source_id"], recording["scope"]
            if key in scopes:
                raise ValueError("Repeated recording scope across manifests")
            scopes.add(key)
            rows = {row["ip"]: row for row in endpoint_rows(recording)}
            heart = {}
            for endpoint in entry["endpoints"]:
                instance = endpoint["instance_id"]
                if instance in identities:
                    raise ValueError("Repeated endpoint instance across manifests")
                identities.add(instance)
                row = rows[endpoint["ip"]]
                category = endpoint["category"]
                aggregate = categories[category]
                aggregate["rows"] += 1
                aggregate["rule_decisions"][rule(row)[0]] += 1
                aggregate["protocols"].update(row["protocols"])
                kinds, uids = set(), set()
                for flow in recording["flows"]:
                    if flow["source_ip"] != endpoint["ip"]:
                        continue
                    for event in flow["evidence"]:
                        if event.get("parser_status") != "confirmed" or event.get("direction") != "originator":
                            continue
                        kinds.update(event.get("metadata", {}).get("measurement_kinds", []))
                        uids.update(event.get("metadata", {}).get("requested_abstract_syntax_uids", []))
                aggregate["measurement_kinds"].update(kinds)
                aggregate["requested_uids"].update(uids)
                if aggregate["example"] is None:
                    aggregate["example"] = {"recording": str(path.relative_to(REPO)), "asset_id": row["asset_id"],
                                            "rule_decision": rule(row), "features": dict(row["features"]),
                                            "evidence_references": row["references"][:2]}
                if category in ("bedside_monitor", "ecg_monitor"):
                    heart[category] = (sorted(row["protocols"]), sorted(kinds), sorted(uids), sorted(row["candidates"]))
            if len(heart) == 2 and heart["bedside_monitor"] == heart["ecg_monitor"]:
                semantic_pairs_equal += 1
            capture_report = read(path.parent / "capture-report.json")
            starts, ends = [], []
            for role, recorded in capture_report["captures"].items():
                capture = path.parent / "pcaps" / f"{role}.pcap"
                _, info = complete_pcap(capture.read_bytes(), allow_partial=False)
                for field in ("sha256", "frames", "bytes", "incomplete_tail_bytes", "first_packet_time", "last_packet_time"):
                    if info[field] != recorded[field]:
                        raise ValueError(f"Capture metadata mismatch: {capture}: {field}")
                capture_hashes[str(capture.relative_to(REPO))] = info["sha256"]
                counts["captures"] += 1
                counts["capture_bytes"] += info["bytes"]
                if info["first_packet_time"] is not None:
                    starts.append(info["first_packet_time"])
                    ends.append(info["last_packet_time"])
            spans.append(max(ends) - min(starts))
            collector_times.append(capture_report["capture_seconds"])
        splits[split] = {"sessions": len(manifest["recordings"]), "categories": dict(categories),
                         "endpoint_rows": sum(item["rows"] for item in categories.values())}
    return {"splits": splits, "totals": dict(counts), "distinct_instances": len(identities),
            "distinct_recordings": len(scopes), "equal_heart_pair_semantic_sets": semantic_pairs_equal,
            "heart_pair_comparison_excludes_counts_timing_and_packet_statistics": True,
            "observed_packet_span_seconds": {"min": min(spans), "median": median(spans), "max": max(spans)},
            "collector_elapsed_seconds": {"min": min(collector_times), "median": median(collector_times), "max": max(collector_times)},
            "note": "Observed packet span is not capture wall-clock duration or proof of network completeness.",
            "recording_sha256": recording_hashes, "capture_sha256": capture_hashes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study", type=Path, default=REPO / "runs/module4-learning-study-20261116")
    parser.add_argument("--output", type=Path, required=True, help="New JSON path; existing files are never overwritten")
    args = parser.parse_args()
    study = args.study.resolve()
    sources = [REPO / item for item in ("module2/parsing.py", "Module 3/module3/store.py",
               "Module 4/module4/__init__.py", "Module 4/module4/classifier.py", "Module 4/module4/experiment.py",
               "Module 4/module4/study.py", "Module 4/module4/lab_actor.py", "Module 4/module4/traffic.py",
               "Module 4/tools/audit_stage1.py")]
    artifacts = [study / "model/model.joblib", study / "model/selection.json"]
    comparison = REPO / "runs/module4-traffic-comparison-20261116/models"
    artifacts += [comparison / name for name in ("combined.joblib", "protocol_evidence.joblib",
                                                 "statistics.joblib", "selection.json")]
    protected = sources + artifacts
    before = {str(path.relative_to(REPO)): digest(path) for path in protected}
    result = {"schema_version": "hiot.module4.stage1-audit.v1", "medical_categories": list(MEDICAL),
              "study": summarize_study(study), "diagnostics": diagnostics(), "protected_sha256": before}
    after = {str(path.relative_to(REPO)): digest(path) for path in protected}
    if before != after:
        raise ValueError("Audited source or frozen artifact changed during audit")
    result["protected_sources_and_artifacts_unchanged"] = True
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as out:
        json.dump(result, out, indent=2, sort_keys=True, allow_nan=False)
        out.write("\n")
    print(json.dumps({"output": str(args.output), "sessions": result["study"]["distinct_recordings"],
                      "endpoint_rows": result["study"]["distinct_instances"], **result["study"]["totals"],
                      "diagnostic_cases": len(result["diagnostics"]["cases"]),
                      "protected_sources_and_artifacts_unchanged": True}))


if __name__ == "__main__":
    main()
