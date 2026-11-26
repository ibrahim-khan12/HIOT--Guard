"""Bounded, evaluation-only IoT Sentinel pilot using frozen Module 4 models."""
import argparse
from collections import Counter, defaultdict
import hashlib
import ipaddress
from pathlib import Path
import re
import subprocess
import zipfile

from module2.pcap import complete_pcap
from . import UNKNOWN
from .experiment import load_json, row_key, write_json
from .external_pilot import packet_audit, rejection_metrics
from .study import load_selected, selected_predictions
from .traffic import feature_rows, load_rows, renamed_inputs, selected_features
from .traffic_study import FAMILIES, decision, import_pcap, load_models, scores

SOURCE = "https://research.aalto.fi/en/datasets/iot-devices-captures/"
DEVICES = ("D-LinkCam", "TP-LinkPlugHS100", "SmarterCoffee")
SCHEMA = "hiot.module4.sentinel-pilot.v1"


def sha256(path):
    checksum = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


def select_members(names, device):
    """First capture per setup person, then fill to three in filename order."""
    pattern = rf"captures_IoT-Sentinel/{re.escape(device)}/Setup-[A-Z]-[0-9]+-STA\.pcap"
    candidates = sorted(name for name in names if re.fullmatch(pattern, name))
    if len(candidates) != len(set(candidates)):
        raise ValueError("Duplicate archive members")
    people, selected = set(), []
    for name in candidates:
        person = Path(name).name.split("-")[1]
        if person not in people:
            selected.append(name)
            people.add(person)
    selected = selected[:3]
    for name in candidates:
        if len(selected) >= 3:
            break
        if name not in selected:
            selected.append(name)
    if len(selected) != 3:
        raise ValueError("Need three setup captures per selected device")
    return selected


def source_addresses(path, tshark, mac):
    fields = ("eth.src", "ip.src", "ipv6.src")
    command = [tshark, "-n", "-r", str(path), "-T", "fields", "-E", "occurrence=f"]
    for field in fields:
        command.extend(("-e", field))
    result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=120)
    counts, owners = Counter(), defaultdict(set)
    for line in result.stdout.splitlines():
        source, *addresses = line.split("\t")
        for address in addresses:
            if not address:
                continue
            ip = ipaddress.ip_address(address)
            if ip.is_unspecified or ip.is_multicast or address == "255.255.255.255":
                continue
            owners[address].add(source.lower())
            if source.lower() == mac:
                counts[address] += 1
    if not counts or any(owners[ip] != {mac} for ip in counts):
        raise ValueError("Target needs uniquely MAC-attributed transmitting IP evidence")
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def prepare(archive, root, tshark):
    archive, root = Path(archive).resolve(strict=True), Path(root)
    if root.exists():
        raise ValueError("Use a fresh preparation directory")
    records = []
    with zipfile.ZipFile(archive) as zipped:
        names = zipped.namelist()
        # Exact allowlisted members only; no extractall or archive paths as destinations.
        for device in DEVICES:
            mac_member = f"captures_IoT-Sentinel/{device}/_iotdevice-mac.txt"
            if names.count(mac_member) != 1:
                raise ValueError("Missing or duplicate publisher MAC file")
            mac = zipped.read(mac_member).decode("ascii").strip().lower()
            if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
                raise ValueError("Invalid publisher MAC")
            for member in select_members(names, device):
                if zipped.getinfo(member).file_size > 32 * 1024 * 1024:
                    raise ValueError("Selected capture exceeds the regular import limit")
                raw, audit = complete_pcap(zipped.read(member))
                path = root / "captures" / device / Path(member).name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
                records.append({"device": device, "member": member, "pcap": str(path.resolve()),
                                "bytes": len(raw), "sha256": audit["sha256"], "frames": audit["frames"],
                                "target_mac": mac, "mac_member": mac_member,
                                "source_ip_counts": source_addresses(path, tshark, mac)})
    write_json(root / "archive-audit.json", {
        "schema_version": SCHEMA, "publisher": SOURCE, "archive": str(archive),
        "archive_bytes": archive.stat().st_size, "archive_sha256": sha256(archive),
        "selection": "Three predeclared consumer devices; first setup per person, fill to three in filename order",
        "records": records, "trained_on_public_data": False})
    print(f"Prepared {len(records)} complete setup recordings for {len(DEVICES)} device identities", flush=True)


def capture_metrics(targets):
    """A setup fails rejection if ANY reviewed address receives a medical class."""
    grouped = defaultdict(list)
    for target in targets:
        grouped[target["member"]].append(target)
    results = []
    for member, rows in grouped.items():
        decisions = {}
        for method in rows[0]["decisions"]:
            predictions = [row["decisions"][method]["category"] for row in rows]
            decisions[method] = {"category": next((p for p in predictions if p != UNKNOWN), UNKNOWN)}
        results.append({"member": member, "expected": UNKNOWN, "decisions": decisions})
    return rejection_metrics(results)


def run(root, model_dir, study, output, tshark):
    root, model_dir, study, output = map(Path, (root, model_dir, study, output))
    if output.exists():
        raise ValueError("Use a fresh evaluation directory")
    audit = load_json(root / "archive-audit.json")
    archive = Path(audit["archive"])
    if sha256(archive) != audit["archive_sha256"]:
        raise ValueError("Input ZIP changed")
    selection, candidates = load_models(model_dir)
    model, policy = load_selected(study)
    artifacts = [*(model_dir / f"{family}.joblib" for family in FAMILIES), model_dir / "selection.json",
                 study / "model/model.joblib", study / "model/selection.json"]
    hashes = {str(path.resolve()): sha256(path) for path in artifacts}
    targets, background, bindings, captures = [], [], [], []
    members, digests = set(), set()
    with zipfile.ZipFile(archive) as zipped:
        expected_members = {name for device in DEVICES for name in select_members(zipped.namelist(), device)}
        if {entry["member"] for entry in audit["records"]} != expected_members:
            raise ValueError("Selection differs from the predeclared nine captures")
        for entry in audit["records"]:
            member = entry["member"]
            if member in members or entry["sha256"] in digests:
                raise ValueError("Repeated capture or exact duplicate packet file")
            members.add(member)
            digests.add(entry["sha256"])
            path = Path(entry["pcap"])
            if (sha256(path) != entry["sha256"] or hashlib.sha256(zipped.read(member)).hexdigest() != entry["sha256"]
                    or zipped.read(entry["mac_member"]).decode("ascii").strip().lower() != entry["target_mac"]):
                raise ValueError("Capture or publisher MAC differs from archive provenance")
            addresses = source_addresses(path, tshark, entry["target_mac"])
            if addresses != {ip: count for ip, count in entry["source_ip_counts"].items()
                              if ip != "0.0.0.0"}:
                raise ValueError("Reviewed IP evidence changed")
            for ip in addresses:
                bindings.append({"member": member, **packet_audit(path, tshark, entry["target_mac"], ip)})
            # Keep artifact paths below legacy Windows MAX_PATH despite two SHA directories.
            imported = output / f"i{len(captures)+1:02d}"
            print(f"Importing {entry['device']}/{path.name}", flush=True)
            import_pcap([path], imported, tshark)
            record, flows, rows = load_rows(imported / "recording.json")
            fitted = {family: scores(candidate, rows) for family, candidate in candidates.items()} if rows else {}
            current_rows = selected_predictions(record, model, policy)
            current = {row_key(row): row for row in current_rows}
            changed_record, changed_flows = renamed_inputs(record, flows)
            changed_rows = feature_rows(changed_record, changed_flows)
            invariant = all([selected_features(row, family) for row in rows] ==
                            [selected_features(row, family) for row in changed_rows] and
                            fitted.get(family, []) == (scores(candidate, changed_rows) if changed_rows else [])
                            for family, candidate in candidates.items())
            invariant = invariant and [row["decisions"] for row in current_rows] == [
                row["decisions"] for row in selected_predictions(changed_record, model, policy)]
            if not invariant:
                raise ValueError("Identifier/time invariance failed")
            found = set()
            for index, row in enumerate(rows):
                outputs = dict(current[row_key(row)]["decisions"])
                for family, candidate in candidates.items():
                    category, reason = decision(row, fitted[family][index], candidate["threshold"], family)
                    outputs[family] = {"category": category, "reason": reason,
                                       "score": fitted[family][index][1], "raw_top_class": fitted[family][index][0]}
                item = {"member": member, "device": entry["device"], "target_mac": entry["target_mac"],
                        "ip": row["ip"], "presence": row["presence"], "decisions": outputs,
                        "medical_protocols": sorted(row["protocols"]), "evidence": row["references"],
                        "traffic_features": row["traffic_features"]}
                if row["ip"] in addresses:
                    found.add(row["ip"])
                    targets.append(item | {"expected": UNKNOWN})
                else:
                    background.append(item)
            if found != set(addresses):
                raise ValueError(f"Some MAC-attributed target addresses were not discovered: {set(addresses)-found}")
            imported_audit = load_json(imported / "sample-audit.json")
            if len(imported_audit["inputs"]) != 1 or imported_audit["inputs"][0]["sha256"] != entry["sha256"]:
                raise ValueError("Imported recording differs from reviewed PCAP")
            captures.append({"member": member, "import_directory": str(imported.resolve()),
                             "frames": imported_audit["inputs"][0]["frames"],
                             "canonical_flows": len(flows), "endpoints": len(rows),
                             "sensor_versions": imported_audit["sensor_versions"], "identifier_time_invariance": True})
    if any(sha256(path) != expected for path, expected in hashes.items()):
        raise ValueError("Frozen model or policy artifact changed during evaluation")
    transmitting = [row for row in targets if row["presence"] == "observed_transmitting"]
    report = {"schema_version": SCHEMA, "dataset": "Aalto IoT Sentinel", "publisher": SOURCE,
              "archive_sha256": audit["archive_sha256"], "archive_bytes": audit["archive_bytes"],
              "preparation_manifest_sha256": sha256(root / "archive-audit.json"),
              "evaluator_source_sha256": sha256(Path(__file__)),
              "selected_pcap_bytes": sum(entry["bytes"] for entry in audit["records"]),
              "setup_recordings": len(members), "unique_publisher_macs": len({entry["target_mac"] for entry in audit["records"]}),
              "device_categories": list(DEVICES), "reviewed_endpoint_address_rows": len(targets),
              "observed_transmitting_target_rows": len(transmitting),
              "address_metrics": rejection_metrics(targets), "setup_metrics": capture_metrics(targets),
              "transmitting_address_metrics": rejection_metrics(transmitting) if transmitting else {},
              "per_device_setup_metrics": {device: capture_metrics([row for row in targets if row["device"] == device]) for device in DEVICES},
              "targets": targets, "packet_bindings": bindings, "capture_audits": captures,
              "background_endpoint_rows_excluded": len(background),
              "background_medical_assignments": [{"member": row["member"], "ip": row["ip"], "method": method, **prediction}
                   for row in background for method, prediction in row["decisions"].items() if prediction["category"] != UNKNOWN],
              "unchanged_model_hashes": hashes, "comparison_source_sha256": selection["source_sha256"],
              "thresholds_changed": False, "trained_on_public_data": False, "ten_class_macro_f1_computed": False,
              "limitations": ["Three physical identities with repeated setups; nine recordings are not nine independent devices",
                              "Only setup traffic is represented, not normal long-running operation or attacks",
                              "Consumer devices are outside the ten hospital categories; this measures unknown rejection only",
                              "Protocol guards can trivially reject traffic without confirmed HL7/DICOM",
                              "Learned-peer rows with no canonical attributed transmission are reported separately",
                              "Every observed target IP alias is included; a setup fails if any alias receives a medical category",
                              "Unreviewed background hosts are preserved and excluded from target metrics"]}
    write_json(output / "report.json", report)
    write_json(output / "predictions.json", {"targets": targets, "unreviewed_background": background})
    write_json(output / "ground-truth.json", audit | {"expected_for_selected_devices": UNKNOWN,
               "mapping_rationale": "Publisher-labelled consumer camera, smart plug and coffee maker are outside all ten hospital categories"})
    render(output / "REPORT.md", report)
    print(f"Finished {len(members)} setup recordings / {report['unique_publisher_macs']} device identities", flush=True)
    for method, card in report["setup_metrics"].items():
        print(f"{method}: {card['correct_unknown_rejections']}/{card['targets']} setups fully rejected; {card['incorrect_medical_assignments']} with medical assignments", flush=True)


def render(path, report):
    lines = ["# IoT Sentinel external rejection pilot", "",
             f"{report['setup_recordings']} setup recordings, {report['unique_publisher_macs']} publisher MAC identities, "
             f"{report['reviewed_endpoint_address_rows']} target address rows; "
             f"{report['observed_transmitting_target_rows']} rows have attributed transmission in the canonical pipeline.", "",
             "A setup passes only when every MAC-attributed target IP is unknown.", "",
             "| Method | Correct unknown setups | Setups with medical assignments |",
             "| --- | ---: | ---: |"]
    for method, card in report["setup_metrics"].items():
        lines.append(f"| {method} | {card['correct_unknown_rejections']}/{card['targets']} | {card['incorrect_medical_assignments']} |")
    lines += ["", "## Limitations", "", *("- " + limitation for limitation in report["limitations"]), "",
              "## Integrity", "", "Model and selection artifact hashes stayed unchanged. Identifier/time invariance passed for all imports.",
              "No training, threshold tuning or ten-category macro F1 calculation was performed.", "",
              "## Target predictions", "", "| Device / setup | Target IP | Presence | Selected fallback | Statistics | Combined |",
              "| --- | --- | --- | --- | --- | --- |"]
    for row in report["targets"]:
        outputs = row["decisions"]
        lines.append(f"| {row['device']} / {Path(row['member']).name} | {row['ip']} | {row['presence']} | "
                     f"{outputs['selected_fallback']['category']} | {outputs['statistics']['category']} | {outputs['combined']['category']} |")
    lines += ["", f"Excluded background endpoint rows: {report['background_endpoint_rows_excluded']}. "
              f"Background medical assignments: {len(report['background_medical_assignments'])}; details remain in report.json.", ""]
    lines += ["## Incorrect target assignments", ""]
    for row in report["targets"]:
        for method, prediction in row["decisions"].items():
            if prediction["category"] != UNKNOWN:
                lines.append(f"- {method}: {row['device']} / {Path(row['member']).name}, {row['ip']} "
                             f"was assigned {prediction['category']} (score {prediction.get('score')}).")
    lines += ["", "The current selected policy rejects these captures because no HL7/DICOM is confirmed. "
              "This is not evidence of learned camera, plug or coffee-maker classification. "
              "A forest score is not a calibrated unknown probability.", ""]
    Path(path).write_text("\n".join(lines), encoding="utf-8")


def main():
    from config import tshark_path
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--archive", type=Path, required=True)
    prepare_parser.add_argument("--root", type=Path, required=True)
    prepare_parser.add_argument("--tshark", default=tshark_path())
    evaluate = commands.add_parser("evaluate")
    evaluate.add_argument("--root", type=Path, required=True)
    evaluate.add_argument("--models", type=Path, required=True)
    evaluate.add_argument("--study", type=Path, required=True)
    evaluate.add_argument("--output", type=Path, required=True)
    evaluate.add_argument("--tshark", default=tshark_path())
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args.archive, args.root, args.tshark)
    else:
        run(args.root, args.models, args.study, args.output, args.tshark)


if __name__ == "__main__":
    main()
