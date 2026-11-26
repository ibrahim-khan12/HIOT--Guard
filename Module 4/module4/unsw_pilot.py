"""Prepare bounded UNSW-IoTraffic PCAP prefixes and evaluate reviewed targets.

No download, training, label inference from an IP, or threshold selection occurs.
"""
import argparse
import hashlib
import re
import struct
from pathlib import Path

from module2.pcap import MAGICS, complete_pcap
from . import UNKNOWN
from .experiment import load_json, row_key, write_json
from .external_pilot import packet_audit, rejection_metrics
from .study import load_selected, selected_predictions
from .traffic import feature_rows, load_rows, renamed_inputs, selected_features
from .traffic_study import FAMILIES, decision, digest, load_models, scores

SOURCE = "https://iotanalytics.unsw.edu.au/unsw-iotraffic.html"
DOI = "https://doi.org/10.5061/dryad.w0vt4b94b"
SCHEMA = "hiot.module4.unsw-pilot.v1"
MAX_BYTES = 16 * 1024 * 1024


def sha256(path):
    checksum = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def prefix(stream, max_frames=50000, max_bytes=MAX_BYTES):
    """Select the first complete records, before examining any predictions."""
    if not 1 <= max_frames or not 40 <= max_bytes <= MAX_BYTES:
        raise ValueError("Invalid prefix limit")
    header = stream.read(24)
    complete_pcap(header)
    endian = MAGICS[header[:4]]
    snaplen = struct.unpack_from(endian + "I", header, 16)[0]
    output, frames, stop = bytearray(header), 0, "frame_limit"
    while frames < max_frames:
        packet = stream.read(16)
        if not packet:
            stop = "end_of_file"
            break
        if len(packet) != 16:
            raise ValueError("Truncated PCAP packet header")
        captured, original = struct.unpack_from(endian + "II", packet, 8)
        if captured > snaplen or captured > original:
            raise ValueError("Invalid PCAP record length")
        if len(output) + 16 + captured > max_bytes:
            stop = "byte_limit"
            break
        payload = stream.read(captured)
        if len(payload) != captured:
            raise ValueError("Truncated PCAP packet payload")
        output.extend(packet + payload)
        frames += 1
    if not frames:
        raise ValueError("No complete packets fit in this sample")
    data, audit = complete_pcap(bytes(output))
    return data, audit | {"stop_reason": stop, "max_frames": max_frames, "max_bytes": max_bytes,
                          "selection": "first complete packet records in original file order"}


def prepare(pcap, output, max_frames=50000):
    pcap, output = Path(pcap).resolve(strict=True), Path(output)
    match = re.fullmatch(r"(.+)_([0-9a-fA-F]{12})\.pcap", pcap.name)
    if not match:
        raise ValueError("Keep the publisher DeviceName_DeviceMAC.pcap filename")
    if output.exists():
        raise ValueError("Use a fresh sample directory")
    with pcap.open("rb") as stream:
        data, audit = prefix(stream, max_frames)
    source_hash = sha256(pcap)
    output.mkdir(parents=True)
    (output / "sample.pcap").write_bytes(data)
    write_json(output / "source-audit.json", {
        "dataset": "UNSW-IoTraffic", "publisher": SOURCE, "doi": DOI,
        "original_file": str(pcap), "original_bytes": pcap.stat().st_size,
        "original_sha256": source_hash, "sample": audit,
        "original_session": pcap.name,
        "device_name_from_filename": match[1],
        "device_mac_from_filename": ":".join(match[2][i:i+2].lower() for i in range(0, 12, 2)),
        "label_reviewed": False, "accuracy_computed": False,
        "limitation": "A bounded prefix is not the full 203-day trace or an independent new session",
    })
    print(f"Prepared {audit['frames']} frames / {audit['bytes']} bytes; labels still require review")


def validate_entry(entry, audit):
    if (entry.get("expected") != UNKNOWN or entry.get("review_status") != "out_of_scope_reviewed"
            or not entry.get("identity_source") or not entry.get("mapping_rationale")):
        raise ValueError("Require a publisher-verified identity and reviewed out-of-scope rationale")
    if (entry.get("target_mac", "").lower() != audit["device_mac_from_filename"]
            or entry.get("original_session") != audit["original_session"]
            or entry.get("device") != audit["device_name_from_filename"]):
        raise ValueError("Reviewed identity differs from the publisher filename provenance")


def evaluate(manifest_path, models, study, output, tshark):
    manifest_path, output = Path(manifest_path), Path(output)
    if output.exists():
        raise ValueError("Use a fresh evaluation directory")
    manifest = load_json(manifest_path)
    if manifest.get("schema_version") != SCHEMA or not manifest.get("recordings"):
        raise ValueError("Expected a nonempty reviewed UNSW pilot manifest")
    selection, candidates = load_models(models)
    model, policy = load_selected(study)
    artifacts = [*(models / f"{family}.joblib" for family in FAMILIES),
                 models / "selection.json", study / "model/model.joblib", study / "model/selection.json"]
    hashes = {str(path.resolve()): sha256(path) for path in artifacts}
    sessions, original_hashes, targets, background, audits = set(), set(), [], [], []
    for entry in manifest["recordings"]:
        sample_dir = (manifest_path.parent / entry["sample_directory"]).resolve()
        provenance = load_json(sample_dir / "source-audit.json")
        validate_entry(entry, provenance)
        if entry["original_session"] in sessions or provenance["original_sha256"] in original_hashes:
            raise ValueError("Do not count multiple prefixes of one recording as independent samples")
        sessions.add(entry["original_session"])
        original_hashes.add(provenance["original_sha256"])
        pcap = sample_dir / "sample.pcap"
        if sha256(pcap) != provenance["sample"]["sha256"]:
            raise ValueError("Sample PCAP changed after preparation")
        binding = packet_audit(pcap, tshark, entry["target_mac"], entry["target_ip"])
        imported_dir = (manifest_path.parent / entry["import_directory"]).resolve()
        imported = load_json(imported_dir / "sample-audit.json")
        if len(imported["inputs"]) != 1 or imported["inputs"][0]["sha256"] != provenance["sample"]["sha256"]:
            raise ValueError("Imported canonical recording differs from the reviewed sample")
        record, flows, rows = load_rows(imported_dir / "recording.json")
        fitted = {family: scores(candidate, rows) for family, candidate in candidates.items()}
        current = selected_predictions(record, model, policy)
        changed_record, changed_flows = renamed_inputs(record, flows)
        changed_rows = feature_rows(changed_record, changed_flows)
        invariant = all([selected_features(row, family) for row in rows] ==
                        [selected_features(row, family) for row in changed_rows] and
                        fitted[family] == scores(candidate, changed_rows)
                        for family, candidate in candidates.items())
        invariant = invariant and [row["decisions"] for row in current] == [
            row["decisions"] for row in selected_predictions(changed_record, model, policy)]
        if not invariant:
            raise ValueError("Identifier/time renaming changed predictions")
        current = {row_key(row): row for row in current}
        found = 0
        for index, row in enumerate(rows):
            outputs = dict(current[row_key(row)]["decisions"])
            for family, candidate in candidates.items():
                category, reason = decision(row, fitted[family][index], candidate["threshold"], family)
                outputs[family] = {"category": category, "score": fitted[family][index][1],
                                   "raw_top_class": fitted[family][index][0], "reason": reason}
            item = {"original_session": entry["original_session"], "ip": row["ip"],
                    "decisions": outputs, "evidence": row["references"]}
            if row["ip"] == entry["target_ip"]:
                if row["presence"] != "observed_transmitting":
                    raise ValueError("Reviewed target must be observed transmitting")
                found += 1
                targets.append(item | {"device": entry["device"], "expected": UNKNOWN,
                                       "medical_protocols": sorted(row["protocols"])})
            else:
                background.append(item)
        if found != 1:
            raise ValueError("Expected exactly one row for the reviewed target")
        audits.append({"source": provenance, "binding": binding, "canonical_flows": len(flows),
                       "sensor_versions": imported["sensor_versions"], "identifier_time_invariance": invariant})
    if any(sha256(path) != expected for path, expected in hashes.items()):
        raise ValueError("A frozen model artifact changed during evaluation")
    report = {"schema_version": SCHEMA, "dataset": "UNSW-IoTraffic", "doi": DOI,
              "metrics": rejection_metrics(targets), "targets": targets, "capture_audits": audits,
              "original_recordings": len(sessions), "excluded_background_endpoints": len(background),
              "unchanged_model_hashes": hashes, "comparison_source_sha256": selection["source_sha256"],
              "manifest_sha256": digest(manifest_path), "trained_on_public_data": False,
              "thresholds_changed": False, "ten_category_macro_f1_computed": False,
              "limitations": ["Consumer IoT rejection does not validate ten hospital device categories",
                              "Protocol guards may trivially reject samples without confirmed HL7/DICOM",
                              "Prefixes may contain partial flows and emphasize startup behaviour",
                              "Multiple devices in the same lab are not independent hospital deployments",
                              "Unreviewed background endpoints are preserved and excluded from target metrics"]}
    output.mkdir(parents=True)
    write_json(output / "report.json", report)
    write_json(output / "predictions.json", {"targets": targets, "unreviewed_background": background})
    write_json(output / "reviewed-manifest.json", manifest)
    lines = ["# UNSW-IoTraffic external pilot", "", "| Method | Correct unknown | Wrong medical assignments |",
             "| --- | ---: | ---: |"]
    for name, card in report["metrics"].items():
        lines.append(f"| {name} | {card['correct_unknown_rejections']}/{card['targets']} | {card['incorrect_medical_assignments']} |")
    lines += ["", *report["limitations"], "", "No fitting or threshold changes occurred."]
    (output / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Evaluated {len(targets)} reviewed out-of-scope targets; no ten-class accuracy claimed")


def main():
    from config import tshark_path
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    sample = commands.add_parser("prepare")
    sample.add_argument("--pcap", type=Path, required=True)
    sample.add_argument("--output", type=Path, required=True)
    sample.add_argument("--max-frames", type=int, default=50000)
    score = commands.add_parser("evaluate")
    score.add_argument("--manifest", type=Path, required=True)
    score.add_argument("--models", type=Path, required=True)
    score.add_argument("--study", type=Path, required=True)
    score.add_argument("--output", type=Path, required=True)
    score.add_argument("--tshark", default=tshark_path())
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args.pcap, args.output, args.max_frames)
    else:
        evaluate(args.manifest, args.models, args.study, args.output, args.tshark)


if __name__ == "__main__":
    main()
