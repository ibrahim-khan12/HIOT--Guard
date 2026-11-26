"""Evaluate reviewed out-of-scope targets without labelling background hosts.

The manifest supplies independently reviewed publisher identities. MAC/IP values
join the PCAP evidence and evaluation labels; they never enter model features.
The recording must first be imported with module4.traffic_study import-pcap.
"""
import argparse
from collections import Counter
import csv
import ipaddress
from pathlib import Path
import subprocess

from . import MEDICAL, UNKNOWN
from .experiment import load_json, row_key, write_json
from .study import load_selected, selected_predictions
from .traffic import feature_rows, load_rows, renamed_inputs, selected_features
from .traffic_study import FAMILIES, decision, digest, load_models, scores

SCHEMA = "hiot.module4.external-pilot.v1"
FIELDS = ("frame.number", "eth.src", "eth.dst", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
          "frame.len", "frame.cap_len", "tcp.analysis.retransmission", "tcp.analysis.lost_segment",
          "_ws.col.Protocol")


def verify_binding(packets, mac, ip):
    """Require the reviewed address to be sent by the reviewed device MAC."""
    address = ipaddress.ip_address(ip)
    if address.is_multicast or address.is_unspecified or ip == "255.255.255.255":
        raise ValueError("A target must have an observed individual IP address")
    mac = mac.lower()
    sources, sent, received, ether_frames = set(), [], [], 0
    for packet in packets:
        source, destination = packet["eth.src"].lower(), packet["eth.dst"].lower()
        ether_frames += mac in (source, destination)
        if ip in (packet["ip.src"], packet["ipv6.src"]):
            sources.add(source)
            sent.append(int(packet["frame.number"]))
        if ip in (packet["ip.dst"], packet["ipv6.dst"]) and destination == mac:
            received.append(int(packet["frame.number"]))
    if not sent or sources != {mac}:
        raise ValueError("Reviewed device MAC does not uniquely match the target IP in this PCAP")
    return {"device_mac": mac, "ip": ip, "source_ip_mac_packets": len(sent),
            "destination_ip_mac_packets": len(received), "device_ethernet_frames": ether_frames,
            "supporting_source_frames": sent[:8], "supporting_reply_frames": received[:8],
            "status": "publisher_MAC_matched_to_observed_IP"}


def packet_audit(path, tshark, mac, ip):
    command = [tshark, "-n", "-r", str(path), "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"]
    for field in FIELDS:
        command.extend(("-e", field))
    result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=120)
    packets = [dict(zip(FIELDS, row, strict=True)) for row in csv.reader(result.stdout.splitlines(), delimiter="\t")]
    binding = verify_binding(packets, mac, ip)
    return binding | {"frames": len(packets),
                      "truncated_frames": sum(int(row["frame.cap_len"]) < int(row["frame.len"]) for row in packets),
                      "tshark_retransmission_markers": sum(bool(row["tcp.analysis.retransmission"]) for row in packets),
                      "tshark_lost_segment_markers": sum(bool(row["tcp.analysis.lost_segment"]) for row in packets),
                      "protocol_columns": dict(Counter(row["_ws.col.Protocol"] for row in packets)),
                      "tshark_stderr": result.stderr.strip()}


def rejection_metrics(results):
    if not results:
        raise ValueError("At least one independently reviewed target is required")
    methods = set(results[0]["decisions"])
    if any(set(row["decisions"]) != methods or row["expected"] != UNKNOWN for row in results):
        raise ValueError("This pilot scores only consistently reviewed out-of-scope targets")
    cards = {}
    for method in sorted(methods):
        predictions = [row["decisions"][method]["category"] for row in results]
        if any(category not in (*MEDICAL, UNKNOWN) for category in predictions):
            raise ValueError("Unexpected public prediction category")
        rejected = predictions.count(UNKNOWN)
        cards[method] = {"targets": len(results), "correct_unknown_rejections": rejected,
                         "incorrect_medical_assignments": len(results) - rejected,
                         "correct_rejection_fraction": rejected / len(results)}
    return cards


def evaluate(manifest_path, model_dir, study, output, tshark):
    if output.exists():
        raise ValueError("Use a fresh evaluation output directory")
    manifest = load_json(manifest_path)
    if manifest.get("schema_version") != SCHEMA:
        raise ValueError("Expected a reviewed external-pilot manifest")
    selection, candidates = load_models(model_dir)
    model, policy = load_selected(study)
    artifacts = [*(model_dir / f"{family}.joblib" for family in FAMILIES),
                 study / "model/model.joblib", study / "model/selection.json"]
    hashes = {str(path.resolve()): digest(path) for path in artifacts}
    used_sessions, targets, predictions, audits, invariance = set(), [], [], [], []
    for entry in manifest["recordings"]:
        if (entry.get("expected") != UNKNOWN or entry.get("review_status") != "out_of_scope_reviewed"
                or not entry.get("identity_source") or not entry.get("mapping_rationale")):
            raise ValueError("Each target needs a reviewed out-of-scope label and publisher identity source")
        pcap = Path(entry["pcap"])
        if digest(pcap) != entry["sha256"]:
            raise ValueError("Public capture differs from the reviewed manifest")
        if entry["original_session"] in used_sessions:
            raise ValueError("Do not count windows/chunks of one original recording as independent sessions")
        used_sessions.add(entry["original_session"])
        binding = packet_audit(pcap, tshark, entry["target_mac"], entry["target_ip"])
        path = (Path(manifest_path).parent / entry["recording"]).resolve()
        imported = load_json(path.with_name("sample-audit.json"))
        if len(imported["inputs"]) != 1 or imported["inputs"][0]["sha256"] != entry["sha256"]:
            raise ValueError("Imported recording does not match the reviewed original PCAP")
        record, flows, rows = load_rows(path)
        if not any(row["ip"] == entry["target_ip"] for row in rows):
            raise ValueError("Reviewed target is absent from the passive recording")
        fitted = {family: scores(candidate, rows) for family, candidate in candidates.items()}
        current = {row_key(row): row for row in selected_predictions(record, model, policy)}
        changed_record, changed_flows = renamed_inputs(record, flows)
        changed_rows = feature_rows(changed_record, changed_flows)
        checks = {family: [selected_features(row, family) for row in rows] ==
                  [selected_features(row, family) for row in changed_rows] and
                  fitted[family] == scores(candidate, changed_rows)
                  for family, candidate in candidates.items()}
        checks["current_policy"] = [row["decisions"] for row in current.values()] == [
            row["decisions"] for row in selected_predictions(changed_record, model, policy)]
        if not all(checks.values()):
            raise ValueError("Public prediction changed after identifier/time renaming")
        invariance.append({"original_session": entry["original_session"], "passed": True, "methods": checks})
        for index, row in enumerate(rows):
            outputs = dict(current[row_key(row)]["decisions"])
            for family, candidate in candidates.items():
                prediction, reason = decision(row, fitted[family][index], candidate["threshold"], family)
                outputs[family] = {"category": prediction, "score": fitted[family][index][1], "reason": reason,
                                   "raw_top_class": fitted[family][index][0]}
            item = {"original_session": entry["original_session"], "ip": row["ip"], "presence": row["presence"],
                    "is_reviewed_target": row["ip"] == entry["target_ip"], "decisions": outputs}
            predictions.append(item)
            if item["is_reviewed_target"]:
                if row["presence"] != "observed_transmitting":
                    raise ValueError("Reviewed target must be observed transmitting")
                targets.append(item | {"device": entry["device"], "expected": UNKNOWN,
                                       "medical_protocols": sorted(row["protocols"]),
                                       "traffic_features": row["traffic_features"], "evidence": row["references"]})
        audits.append({"original_session": entry["original_session"], "device": entry["device"],
                       "binding": binding, "canonical_flows": len(flows),
                       "exported_endpoints": len(rows), "input": imported["inputs"][0],
                       "sensor_versions": imported["sensor_versions"]})
    if any(digest(Path(path)) != expected for path, expected in hashes.items()):
        raise ValueError("A frozen model artifact changed during public evaluation")
    metrics = rejection_metrics(targets)
    excluded_calls = [{"original_session": row["original_session"], "ip": row["ip"],
                       "method": method, "category": result["category"], "score": result.get("score")}
                      for row in predictions if not row["is_reviewed_target"]
                      for method, result in row["decisions"].items() if result["category"] != UNKNOWN]
    report = {"schema_version": SCHEMA, "dataset": manifest["dataset"], "evaluated_targets": len(targets),
              "independent_recordings": len(used_sessions), "metrics": metrics, "targets": targets,
              "capture_audits": audits, "excluded_background_endpoints": len(predictions) - len(targets),
              "background_medical_assignments_not_in_target_metrics": excluded_calls,
              "identifier_and_time_invariance": invariance, "unchanged_model_sha256": hashes,
              "comparison_source_sha256": selection["source_sha256"],
              "manifest_sha256": digest(manifest_path),
              "trained_on_public_data": False, "thresholds_changed": False,
              "ten_category_macro_f1_computed": False,
              "limitations": ["A small set of device identities and profiling recordings is only a pilot",
                              "Protocol-gated methods reject these targets because no HL7/DICOM is present",
                              "Background endpoints are not independently labelled and are excluded from target metrics",
                              "Public samples are retained as evaluation data; no fitting or threshold tuning"]}
    output.mkdir(parents=True)
    write_json(output / "report.json", report)
    write_json(output / "predictions.json", {"predictions": predictions})
    write_json(output / "ground-truth.json", manifest)
    render(output / "REPORT.md", report, manifest)
    print(f"Evaluated {len(targets)} reviewed targets in {len(used_sessions)} public recordings", flush=True)
    for method, card in metrics.items():
        print(f"{method}: correct unknown {card['correct_unknown_rejections']}/{card['targets']}, "
              f"wrong medical category {card['incorrect_medical_assignments']}", flush=True)


def render(path, report, manifest):
    current = report["metrics"]["selected_fallback"]
    lines = ["# CICIoMT2024 first external pilot", "",
             f"Imported {report['independent_recordings']} profiling recordings with "
             f"{report['evaluated_targets']} publisher-verified targets. The current selected policy "
             f"returned unknown for {current['correct_unknown_rejections']}/{current['targets']} targets. "
             "This is an out-of-scope rejection pilot, with no ten-category classification score.", "",
             "## Reviewed targets", "",
             "The device MAC addresses match Table 3 of the "
             "[authors' preprint](https://www.preprints.org/manuscript/202402.0898/v1/download). "
             "TShark independently links each MAC to its observed source IP. Device identity and IP/MAC "
             "bindings are evaluation metadata and do not enter model features.", "",
             "| Device | Verified MAC | Observed target IP | Frames | Canonical flows | Current policy |",
             "| --- | --- | --- | ---: | ---: | --- |"]
    for entry, audit, target in zip(manifest["recordings"], report["capture_audits"], report["targets"], strict=True):
        lines.append(f"| {entry['device']} | {entry['target_mac']} | {entry['target_ip']} | "
                     f"{audit['binding']['frames']} | {audit['canonical_flows']} | "
                     f"{target['decisions']['selected_fallback']['category']} |")
    lines += ["", "Only the reviewed profiled devices are labelled. The remaining "
              f"{report['excluded_background_endpoints']} exported endpoint "
              "entries, including cloud servers, a local network endpoint and broadcast destinations, are "
              "excluded from formal metrics. They are not additional labelled test devices.", "",
              "## Results on reviewed targets", "",
              "| Method | Correct unknown | Wrong hospital category |",
              "| --- | ---: | ---: |"]
    for method, card in report["metrics"].items():
        lines.append(f"| {method} | {card['correct_unknown_rejections']}/{card['targets']} | {card['incorrect_medical_assignments']} |")
    lines += ["", "The current forest, rules and protocol evidence candidate require confirmed outgoing "
              "HL7/DICOM. Where that evidence is absent, their guards return unknown. This does not demonstrate "
              "that those methods learned real camera or SOS behaviour. The statistics and combined "
              "candidates do not require that protocol guard. A forest score is the winning training-class "
              "score, not a calibrated unknown probability. This pilot cannot establish broad external accuracy.", ""]
    for target in report["targets"]:
        decisions = target["decisions"]
        lines.append(f"- {target['device']}: statistics top class {decisions['statistics']['raw_top_class']} "
                     f"(score {decisions['statistics']['score']:.3f}); combined top class "
                     f"{decisions['combined']['raw_top_class']} (score {decisions['combined']['score']:.3f}).")
    lines += ["",
              "## Background observation", ""]
    for call in report["background_medical_assignments_not_in_target_metrics"]:
        lines.append(f"- In {call['original_session']}, {call['method']} assigned {call['category']} "
                     f"to background endpoint {call['ip']} (score {call['score']:.3f}).")
    lines += ["", "A hospital assignment to an unreviewed background endpoint is a generalization concern. "
              "Such endpoints are outside the independently reviewed target labels, so calls are preserved as observations "
              "rather than silently added to or removed from labelled target metrics.", "",
              "## Capture and integrity checks", ""]
    for audit, target in zip(report["capture_audits"], report["targets"], strict=True):
        packet = audit["binding"]
        lines.append(f"- {audit['device']}: {packet['truncated_frames']} truncated frames, "
                     f"{packet['tshark_retransmission_markers']} TShark retransmission markers, "
                     f"{packet['tshark_lost_segment_markers']} lost-segment markers, "
                     f"{int(target['traffic_features']['missed_payload_bytes'])} canonical Zeek missed payload bytes; "
                     f"confirmed medical protocols {target['medical_protocols']}.")
    lines += ["", "Differing analyzer signals are retained. No zero-loss claim is made.", "",
              "All model files and thresholds stayed unchanged. Identifier/time renaming checks passed "
              "for all recordings. Inputs, ground truth, model hashes, software versions and cited "
              "evidence are saved in ground-truth.json, report.json and predictions.json. Public captures "
              "were not used for fitting or threshold selection.", "",
              "## Next data", "",
              "For potential overlap with a hospital category, inspect the Active subset and its MQTT "
              "metadata next. The authors' Table 2 includes a simulated infusion pump (10.0.0.13), and "
              "Section 4.4.3 says Active recordings include simulated MQTT traffic. Its actual presence "
              "and device mapping in a downloaded Active capture remain unverified. These two Power "
              "files provide no public CT/MRI/etc. evaluation and do not increase the GNS3 training size.", "",
              "The remaining five Power captures are an optional bounded expansion of out-of-scope "
              "rejection tests. Add interaction/active recordings to check behaviour beyond startup. "
              "Keep all recordings from a physical device instance grouped when constructing future splits.", ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def main():
    from config import tshark_path

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--models", type=Path, required=True)
    parser.add_argument("--study", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tshark", default=tshark_path())
    args = parser.parse_args()
    evaluate(args.manifest, args.models, args.study, args.output, args.tshark)


if __name__ == "__main__":
    main()
