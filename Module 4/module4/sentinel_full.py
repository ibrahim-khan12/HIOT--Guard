"""Audit and evaluate the complete IoT Sentinel archive without fitting models."""
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import importlib
import ipaddress
import json
from pathlib import Path, PurePosixPath
import re
import sqlite3
import struct
import subprocess
import sys
import time
import zipfile

from module2.pcap import MAGICS, complete_pcap
from . import MEDICAL, UNKNOWN
from .experiment import load_json, row_key, write_json
from .external_pilot import FIELDS, verify_binding
from .sentinel_pilot import sha256
from .study import load_selected, selected_predictions
from .traffic import feature_rows, load_rows, renamed_inputs, selected_features
from .traffic_study import FAMILIES, IMAGE, decision, load_models, scores

SCHEMA = "hiot.module4.sentinel-full.v1"
PUBLISHER = "https://research.aalto.fi/en/datasets/iot-devices-captures/"
PAPER = "https://arxiv.org/abs/1611.04880"
METHODS = ("protocol", "rules", "forest", "fallback", "selected_forest", "selected_fallback", *FAMILIES)
# Concise identity review of the original paper, Table II; numbered folders are
# separate publisher instances of the same listed model, not new device types.
IDENTITIES = {
    "Aria": "consumer weight scale", "Withings": "consumer weight scale",
    "HomeMaticPlug": "home power switch", "MAXGateway": "home automation gateway",
    "HueBridge": "lighting bridge", "HueSwitch": "lighting switch",
    "EdnetGateway": "home automation gateway", "EdnetCam": "home camera",
    "EdimaxCam": "home camera", "Lightify": "lighting gateway",
    "WeMoInsightSwitch": "home power switch", "WeMoLink": "lighting bridge",
    "WeMoSwitch": "home power switch", "D-LinkHomeHub": "home automation hub",
    "D-LinkDoorSensor": "door sensor", "D-LinkDayCam": "home camera",
    "D-LinkCam": "home camera", "D-LinkSwitch": "home power switch",
    "D-LinkWaterSensor": "water sensor", "D-LinkSiren": "home siren",
    "D-LinkSensor": "motion sensor", "TP-LinkPlugHS110": "home power plug",
    "TP-LinkPlugHS100": "home power plug", "EdimaxPlug1101W": "home power plug",
    "EdimaxPlug2101W": "home power plug", "SmarterCoffee": "coffee maker",
    "iKettle2": "kettle",
}
INSTANCE_NAMES = {"EdimaxCam1": "EdimaxCam", "EdimaxCam2": "EdimaxCam",
                  "EdnetCam1": "EdnetCam", "EdnetCam2": "EdnetCam",
                  "WeMoInsightSwitch2": "WeMoInsightSwitch", "WeMoSwitch2": "WeMoSwitch"}
GATEWAY_MEDIATED = {"HomeMaticPlug", "HueSwitch", "D-LinkDoorSensor"}
SOURCE_MODULES = ("module4.sentinel_full", "module4.sentinel_pilot", "module4.external_pilot",
                  "module4.classifier", "module4.experiment", "module4.traffic", "module4.traffic_study",
                  "module4.study", "module4.local_sensor", "module4.replay", "module2.pipeline",
                  "module2.parsing", "module2.sensor", "module2.discovery", "module2.pcap",
                  "module2.store", "module2.retention", "module2", "module3", "module3.input", "module3.store")


class IntegrityError(ValueError):
    """A run must stop rather than mix incompatible inputs or inference code."""


def object_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, allow_nan=False).encode()).hexdigest()


def inventory(names):
    """List every capture exactly once; reject unsafe paths before extracting."""
    if len(names) != len(set(names)):
        raise IntegrityError("Duplicate ZIP member names")
    captures = []
    for name in names:
        if name.startswith("__MACOSX/"):
            continue
        parts = PurePosixPath(name).parts
        if "\\" in name or ":" in name or name.startswith("/") or any(part in (".", "..") for part in parts):
            raise IntegrityError(f"Unsafe archive member: {name}")
        if name.startswith("captures_IoT-Sentinel/") and name.endswith(".pcap"):
            if not re.fullmatch(r"captures_IoT-Sentinel/[A-Za-z0-9-]+/Setup-[A-Z]-[0-9]+-STA\.pcap", name):
                raise IntegrityError(f"Unrecognized capture member: {name}")
            captures.append(name)
    if not captures:
        raise IntegrityError("Archive has no recognized captures")
    return sorted(captures)


def identity(folder):
    base = INSTANCE_NAMES.get(folder, folder)
    description = IDENTITIES.get(base)
    return {"publisher_identifier": base, "description": description,
            "identity_source": PAPER + " (Table II), publisher folder and MAC file",
            "review_status": "out_of_scope_reviewed" if description else "unresolved_identity",
            "expected": UNKNOWN if description else None,
            "mapping_rationale": "Reviewed consumer/home device is outside all ten hospital categories" if description else None,
            "visibility": "gateway_mediated" if base in GATEWAY_MEDIATED else "network_endpoint"}


def packet_info(path, mac, tshark):
    command = [tshark, "-n", "-r", str(path), "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"]
    for field in FIELDS:
        command.extend(("-e", field))
    result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=120)
    packets = [dict(zip(FIELDS, row, strict=True)) for row in csv.reader(result.stdout.splitlines(), delimiter="\t")]
    addresses = Counter()
    for packet in packets:
        if packet["eth.src"].lower() != mac:
            continue
        for value in (packet["ip.src"], packet["ipv6.src"]):
            if not value:
                continue
            address = ipaddress.ip_address(value)
            if not address.is_unspecified and not address.is_multicast and value != "255.255.255.255":
                addresses[value] += 1
    if not addresses:
        raise ValueError("no_attributed_source_ip")
    bindings = [verify_binding(packets, mac, ip) for ip in sorted(addresses)]
    return {"source_ip_counts": dict(sorted(addresses.items())), "bindings": bindings,
            "frames": len(packets),
            "truncated_frames": sum(int(p["frame.cap_len"]) < int(p["frame.len"]) for p in packets),
            "retransmission_markers": sum(bool(p["tcp.analysis.retransmission"]) for p in packets),
            "lost_segment_markers": sum(bool(p["tcp.analysis.lost_segment"]) for p in packets),
            "protocol_columns": dict(Counter(p["_ws.col.Protocol"] for p in packets)),
            "tshark_stderr": result.stderr.strip()}


def audit(archive, root, pilot, tshark):
    archive, root, pilot = Path(archive).resolve(strict=True), Path(root).resolve(), Path(pilot).resolve(strict=True)
    if root.exists():
        raise ValueError("Use a fresh audit root")
    pilot_report = load_json(pilot / "report.json")
    archive_hash = sha256(archive)
    if pilot_report["archive_sha256"] != archive_hash:
        raise IntegrityError("ZIP differs from pilot ZIP")
    pilot_imports = {entry["member"]: entry["import_directory"] for entry in pilot_report["capture_audits"]}
    records, folder_reviews, duplicates = [], {}, defaultdict(list)
    with zipfile.ZipFile(archive) as zipped:
        names = zipped.namelist()
        captures = inventory(names)
        folders = sorted({name.split("/")[1] for name in captures})
        mac_groups = defaultdict(list)
        for folder in folders:
            member = f"captures_IoT-Sentinel/{folder}/_iotdevice-mac.txt"
            mac = zipped.read(member).decode("ascii").strip().lower() if member in names else None
            if mac is not None and not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
                mac = None
            review = identity(folder) | {"folder": folder, "mac_member": member, "target_mac": mac,
                                         "mac_file_sha256": hashlib.sha256(zipped.read(member)).hexdigest() if member in names else None}
            folder_reviews[folder] = review
            if mac:
                mac_groups[mac].append(folder)
        root.mkdir(parents=True)
        for index, member in enumerate(captures, 1):
            folder = member.split("/")[1]
            entry = {"id": f"c{index:04d}", "member": member, **folder_reviews[folder],
                     "cohort": "pilot" if member in pilot_imports else "expansion",
                     "pilot_import": pilot_imports.get(member), "shared_mac_folders": mac_groups.get(folder_reviews[folder]["target_mac"], []),
                     "audit_status": "unevaluable", "audit_error": None}
            try:
                if zipped.getinfo(member).file_size > 32 * 1024 * 1024:
                    raise ValueError("capture_exceeds_32_MiB")
                raw = zipped.read(member)
                data, facts = complete_pcap(raw)
                entry.update(facts)
                duplicates[facts["sha256"]].append(member)
                if struct.unpack_from(MAGICS[data[:4]] + "I", data, 20)[0] != 1:
                    raise ValueError("unsupported_non_ethernet_linktype")
                path = root / "p" / (entry["id"] + ".pcap")
                path.parent.mkdir(exist_ok=True)
                path.write_bytes(data)
                entry["pcap"] = str(path)
                if not entry["target_mac"]:
                    raise ValueError("missing_or_invalid_publisher_mac")
                entry["packet_audit"] = packet_info(path, entry["target_mac"], tshark)
                entry["audit_status"] = "completed" if entry["expected"] == UNKNOWN else "unresolved_identity"
            except (ValueError, OSError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
                entry["audit_error"] = f"{type(error).__name__}: {error}"
            records.append(entry)
            if index % 20 == 0 or index == len(captures):
                print(f"Audited {index}/{len(captures)} captures", flush=True)
    manifest = {"schema_version": SCHEMA, "publisher": PUBLISHER, "paper": PAPER,
                "archive": str(archive), "archive_sha256": archive_hash, "archive_bytes": archive.stat().st_size,
                "pilot": str(pilot), "pilot_report_sha256": sha256(pilot / "report.json"),
                "folders": folder_reviews, "mac_groups": dict(mac_groups), "records": records,
                "duplicate_packet_files": [members for members in duplicates.values() if len(members) > 1],
                "selection": "all original capture members; nine pilot members tagged separately; frozen before scoring",
                "trained_on_public_data": False}
    write_json(root / "manifest.json", manifest)
    (root / "manifest.sha256").write_text(sha256(root / "manifest.json") + "\n", encoding="ascii")
    print(f"Frozen {len(records)} captures / {len(folders)} folders / {len(mac_groups)} observed MAC groups", flush=True)
    return manifest


def file_hashes(paths):
    return {str(Path(path).resolve()): sha256(path) for path in paths}


def verify_files(expected):
    for path, expected_hash in expected.items():
        if not Path(path).is_file() or sha256(path) != expected_hash:
            raise IntegrityError(f"Frozen file changed: {path}")


def runtime_contract(root, models, study, tshark):
    import sklearn
    artifacts = [*(models / f"{family}.joblib" for family in FAMILIES), models / "selection.json",
                 study / "model/model.joblib", study / "model/selection.json"]
    sources = [Path(importlib.import_module(name).__file__) for name in SOURCE_MODULES]
    sources.extend((Path(__file__).with_name("__init__.py"), Path(__file__).parents[2] / "module4/__init__.py"))
    # __file__ lives in Module 4/module4; include the repository's compatibility shim.
    sources = [path for path in sources if path.is_file()]
    version = subprocess.check_output([tshark, "--version"], text=True, timeout=30).splitlines()[0]
    return {"schema_version": SCHEMA, "manifest_sha256": sha256(root / "manifest.json"),
            "artifacts": file_hashes(artifacts), "sources": file_hashes(sources),
            "tshark_sha256": sha256(tshark), "tshark_version": version,
            "image": IMAGE, "python": sys.version, "sklearn": sklearn.__version__}


def cache_valid(value, fingerprint, entry):
    return (value.get("fingerprint") == fingerprint and value.get("member") == entry["member"]
            and value.get("input_sha256") == entry.get("sha256")
            and value.get("status") in ("completed", "partial")
            and value.get("identifier_time_invariance") is True)


class AnalyzerBatch:
    def __init__(self, root, tshark):
        self.root, self.tshark, self.sensor, self.count, self.started = root, tshark, None, 0, 0

    def get(self):
        from .local_sensor import docker_zeek
        if self.sensor is not None and (self.count >= 20 or time.monotonic() - self.started >= 600):
            self.close()
        if self.sensor is None:
            self.sensor = docker_zeek(IMAGE, self.tshark, self.root)
            self.started, self.count = time.monotonic(), 0
        self.count += 1
        return self.sensor

    def close(self):
        if self.sensor is not None:
            sensor, self.sensor = self.sensor, None
            sensor.close()


def imported_capture(path, attempt, sensor):
    from module2.pipeline import Pipeline
    from module2.store import Store
    from .replay import project
    analysis = attempt / "analysis"
    analysis.mkdir(parents=True)
    store = Store(analysis / "monitoring.sqlite3")
    try:
        imported = Pipeline(store, analysis, sensor).import_file(path, "capture-0", "public-profiling-sample")
        record = project(store, "public-profiling-sample", analysis)
        write_json(attempt / "recording.json", record)
        write_json(attempt / "import-audit.json", {"inputs": [imported], "sensor_versions": sensor.versions})
    finally:
        store.close()
    return attempt


def validate_import(directory, entry):
    directory = Path(directory)
    audit_path = directory / ("sample-audit.json" if (directory / "sample-audit.json").exists() else "import-audit.json")
    imported = load_json(audit_path)
    if len(imported["inputs"]) != 1 or imported["inputs"][0]["sha256"] != entry["sha256"]:
        raise IntegrityError("Canonical import differs from original capture")
    raw_path = directory / "analysis/artifacts" / imported["inputs"][0]["capture_id"] / entry["sha256"] / "input.pcap"
    if sha256(raw_path) != entry["sha256"]:
        raise IntegrityError("Retained canonical input PCAP differs")
    record, flows, rows = load_rows(directory / "recording.json")
    hashes = file_hashes((audit_path, directory / "recording.json", directory / "analysis/monitoring.sqlite3", raw_path))
    return record, flows, rows, hashes, imported["sensor_versions"]


def infer(record, flows, rows, model, policy, candidates):
    fitted = {family: scores(candidate, rows) if rows else [] for family, candidate in candidates.items()}
    selected = selected_predictions(record, model, policy)
    selected_by_key = {row_key(row): row for row in selected}
    changed_record, changed_flows = renamed_inputs(record, flows)
    changed_rows = feature_rows(changed_record, changed_flows)
    invariant = all([selected_features(row, family) for row in rows] ==
                    [selected_features(row, family) for row in changed_rows] and
                    fitted[family] == (scores(candidate, changed_rows) if changed_rows else [])
                    for family, candidate in candidates.items())
    invariant = invariant and [row["decisions"] for row in selected] == [
        row["decisions"] for row in selected_predictions(changed_record, model, policy)]
    if not invariant:
        raise IntegrityError("Identifier/time invariance failed")
    output = []
    for index, row in enumerate(rows):
        predictions = dict(selected_by_key[row_key(row)]["decisions"])
        for family, candidate in candidates.items():
            category, reason = decision(row, fitted[family][index], candidate["threshold"], family)
            predictions[family] = {"category": category, "reason": reason,
                                   "score": fitted[family][index][1], "raw_top_class": fitted[family][index][0]}
        if any(p["category"] not in (*MEDICAL, UNKNOWN) for p in predictions.values()):
            raise IntegrityError("Unexpected prediction category")
        output.append({"ip": row["ip"], "presence": row["presence"], "medical_protocols": sorted(row["protocols"]),
                       "traffic_features": row["traffic_features"], "evidence": row["references"], "decisions": predictions})
    return output


def capture_outcome(result, method):
    if result.get("expected") != UNKNOWN:
        return "unevaluable"
    if any(row["decisions"][method]["category"] != UNKNOWN for row in result.get("targets", [])):
        return "false_medical"
    if result["status"] == "completed" and result.get("targets") and not result.get("missing_target_ips"):
        return "correct_unknown"
    return "unevaluable"


def metrics(results):
    cards = {}
    for method in METHODS:
        counts = Counter(capture_outcome(result, method) for result in results)
        complete = [r for r in results if r["status"] == "completed" and r.get("expected") == UNKNOWN]
        correct_complete = sum(capture_outcome(r, method) == "correct_unknown" for r in complete)
        addresses = [row for result in results if result.get("expected") == UNKNOWN for row in result.get("targets", [])]
        cards[method] = {"captures": len(results), "correct_unknown": counts["correct_unknown"],
                         "false_medical": counts["false_medical"], "unevaluable": counts["unevaluable"],
                         "complete_captures": len(complete),
                         "complete_capture_rejection_fraction": correct_complete / len(complete) if complete else None,
                         "reviewed_address_rows": len(addresses),
                         "wrong_address_assignments": sum(row["decisions"][method]["category"] != UNKNOWN for row in addresses)}
    return {"captures": len(results), "statuses": dict(Counter(row["status"] for row in results)),
            "complete_capture_coverage": sum(r["status"] == "completed" for r in results) / len(results) if results else None,
            "methods": cards}


def summarize(results):
    folders, macs, cohorts = defaultdict(list), defaultdict(list), defaultdict(list)
    for result in results:
        folders[result["folder"]].append(result)
        macs[result["target_mac"] or "unresolved"].append(result)
        cohorts[result["cohort"]].append(result)
    grouped = {mac: metrics(rows) for mac, rows in macs.items()}
    macro = {}
    for method in METHODS:
        values = [card["methods"][method]["complete_capture_rejection_fraction"] for card in grouped.values()
                  if card["methods"][method]["complete_capture_rejection_fraction"] is not None]
        macro[method] = {"evaluable_mac_groups": len(values), "mean_complete_rejection_fraction": sum(values) / len(values) if values else None}
    additions = {}
    for method in ("fallback", "selected_fallback"):
        rows = [row for result in results if result.get("expected") == UNKNOWN for row in result.get("targets", [])
                if row["decisions"]["rules"]["category"] == UNKNOWN]
        additions[method] = {"rules_abstained_address_rows": len(rows),
                             "added_medical_assignments": sum(row["decisions"][method]["category"] != UNKNOWN for row in rows),
                             "correct_medical_resolutions": 0}
    return {"overall": metrics(results), "per_folder": {key: metrics(rows) for key, rows in folders.items()},
            "per_mac": grouped, "per_cohort": {key: metrics(rows) for key, rows in cohorts.items()},
            "equal_mac_group_average": macro, "fallback_after_rules_abstain": additions}


def pilot_check(results, pilot_report):
    expected = {(row["member"], row["ip"]): row["decisions"] for row in pilot_report["targets"]}
    actual = {(result["member"], row["ip"]): row["decisions"] for result in results if result["cohort"] == "pilot"
              for row in result.get("targets", [])}
    if expected != actual:
        raise IntegrityError("Rescored pilot predictions differ from the original frozen pilot")


def evaluate(root, models, study, tshark, resume=False):
    root, models, study = Path(root).resolve(), Path(models).resolve(), Path(study).resolve()
    if sha256(root / "manifest.json") != (root / "manifest.sha256").read_text().strip():
        raise IntegrityError("Frozen audit manifest changed")
    manifest = load_json(root / "manifest.json")
    if manifest.get("schema_version") != SCHEMA:
        raise IntegrityError("Unsupported manifest")
    if sha256(manifest["archive"]) != manifest["archive_sha256"]:
        raise IntegrityError("Input ZIP changed")
    if sha256(Path(manifest["pilot"]) / "report.json") != manifest["pilot_report_sha256"]:
        raise IntegrityError("Pilot report changed")
    _, candidates = load_models(models)
    model, policy = load_selected(study)
    contract = runtime_contract(root, models, study, tshark)
    fingerprint = object_hash(contract)
    run_path = root / "run.json"
    if run_path.exists():
        if not resume:
            raise ValueError("Evaluation exists; use --resume")
        if load_json(run_path) != contract:
            raise IntegrityError("Resume inputs, evaluator, models, policy or toolchain changed")
    else:
        write_json(run_path, contract)
    pilot_report = load_json(Path(manifest["pilot"]) / "report.json")
    for path, checksum in pilot_report["unchanged_model_hashes"].items():
        if contract["artifacts"].get(path) != checksum:
            raise IntegrityError("Model/policy artifact differs from pilot")
    batch, results = AnalyzerBatch(root, tshark), []
    cache_hits, import_attempts = 0, 0
    started = time.monotonic()
    try:
        for index, entry in enumerate(manifest["records"], 1):
            verify_files(contract["artifacts"])
            verify_files(contract["sources"])
            if entry.get("pcap") and sha256(entry["pcap"]) != entry["sha256"]:
                raise IntegrityError("Extracted capture changed")
            record_dir = root / "items" / entry["id"]
            attempts = sorted(record_dir.glob("a*.json")) if record_dir.exists() else []
            if attempts:
                latest = attempts[-1]
                if sha256(latest) != latest.with_suffix(".sha256").read_text().strip():
                    raise IntegrityError("Cached result changed")
                cached = load_json(latest)
                if cache_valid(cached, fingerprint, entry):
                    verify_files(cached["import_files"])
                    results.append(cached)
                    cache_hits += 1
                    if index % 20 == 0 or index == len(manifest["records"]):
                        print(f"Evaluated {index}/{len(manifest['records'])} (verified cache)", flush=True)
                    continue
            attempt_index = len(attempts) + 1
            attempt = root / entry["id"] / f"a{attempt_index:03d}"
            while attempt.exists():
                attempt_index += 1
                attempt = root / entry["id"] / f"a{attempt_index:03d}"
            result = {key: entry.get(key) for key in ("id", "member", "folder", "target_mac", "cohort", "expected", "visibility", "shared_mac_folders")}
            result.update(fingerprint=fingerprint, input_sha256=entry.get("sha256"), status="unevaluable",
                          targets=[], background=[], missing_target_ips=[], error=None, attempt=attempt_index)
            phase = "audit"
            try:
                if entry["audit_status"] != "completed":
                    raise ValueError(entry["audit_error"] or entry["audit_status"])
                phase = "import"
                if entry.get("pilot_import"):
                    imported = Path(entry["pilot_import"])
                else:
                    import_attempts += 1
                    imported = imported_capture(Path(entry["pcap"]), attempt, batch.get())
                phase = "provenance"
                record, flows, rows, hashes, versions = validate_import(imported, entry)
                phase = "inference"
                predictions = infer(record, flows, rows, model, policy, candidates)
                expected_ips = set(entry["packet_audit"]["source_ip_counts"])
                result["targets"] = [row for row in predictions if row["ip"] in expected_ips]
                result["background"] = [row for row in predictions if row["ip"] not in expected_ips]
                attributed = {row["ip"] for row in result["targets"] if row["presence"] == "observed_transmitting"}
                result.update(missing_target_ips=sorted(expected_ips - attributed), import_files=hashes,
                              import_directory=str(imported), sensor_versions=versions,
                              identifier_time_invariance=True, canonical_flows=len(flows),
                              reused_pilot_import=bool(entry.get("pilot_import")))
                result["status"] = "partial" if result["missing_target_ips"] else "completed"
            except IntegrityError:
                raise
            except (OSError, ValueError, subprocess.SubprocessError, sqlite3.Error) as error:
                if phase == "provenance":
                    raise IntegrityError(f"{entry['member']} / {phase}: {error}") from error
                result["error"] = {"phase": phase, "type": type(error).__name__, "detail": str(error)}
                batch.close()
            result["elapsed_seconds"] = round(time.monotonic() - started, 3)
            record_dir.mkdir(parents=True, exist_ok=True)
            result_path = record_dir / f"a{attempt_index:03d}.json"
            write_json(result_path, result)
            result_path.with_suffix(".sha256").write_text(sha256(result_path) + "\n", encoding="ascii")
            results.append(result)
            if index % 20 == 0 or index == len(manifest["records"]):
                print(f"Evaluated {index}/{len(manifest['records'])}; statuses {dict(Counter(r['status'] for r in results))}", flush=True)
    finally:
        batch.close()
    verify_files(contract["artifacts"])
    verify_files(contract["sources"])
    pilot_check(results, pilot_report)
    report = {"schema_version": SCHEMA, "dataset": "Aalto IoT Sentinel", "publisher": PUBLISHER,
              "fingerprint": fingerprint, "contract": contract, "summary": summarize(results),
              "folders": manifest["folders"], "mac_groups": manifest["mac_groups"],
              "pilot_reproduced": True, "accounted_captures": len(results),
              "capture_processing": {"verified_cache_hits": cache_hits, "new_import_attempts": import_attempts,
                                     "reused_pilot_imports": sum(bool(r.get("reused_pilot_import")) for r in results)},
              "unchanged_model_hashes": contract["artifacts"], "trained_on_public_data": False,
              "thresholds_changed": False, "ten_class_macro_f1_computed": False,
              "elapsed_seconds_this_invocation": round(time.monotonic() - started, 3)}
    if len({result["member"] for result in results}) != len(manifest["records"]):
        raise IntegrityError("Capture accounting is incomplete")
    report_dir = root / "reports"
    report_dir.mkdir(exist_ok=True)
    edition = 1
    while (report_dir / f"v{edition:03d}").exists():
        edition += 1
    destination = report_dir / f"v{edition:03d}"
    destination.mkdir()
    write_json(destination / "report.json", report)
    write_json(destination / "predictions.json", {"captures": results})
    write_json(destination / "failures.json", {"captures": [r for r in results if r["status"] != "completed"]})
    render(destination / "REPORT.md", report, results)
    print(f"Completed {len(results)} captures. Report: {destination / 'REPORT.md'}", flush=True)
    return report


def render(path, report, results):
    summary = report["summary"]
    overall = summary["overall"]
    lines = ["# Complete IoT Sentinel external rejection evaluation", "",
             f"Accounted for {report['accounted_captures']} captures across {len(report['folders'])} folders "
             f"and {len(report['mac_groups'])} observed publisher MAC groups.", "",
             "Repeated setups and shared-MAC folders are correlated observations, not independent devices. "
             "This is an external unknown-rejection evaluation; no medical ten-class F1 is computed.", "",
             f"Processing statuses: {overall['statuses']}. Complete-capture coverage: {overall['complete_capture_coverage']:.1%}.", "",
             "| Method | Correct unknown setups | Setups with medical assignments | Unevaluable | Equal-MAC rejection mean |",
             "| --- | ---: | ---: | ---: | ---: |"]
    for method, card in overall["methods"].items():
        mean = summary["equal_mac_group_average"][method]["mean_complete_rejection_fraction"]
        lines.append(f"| {method} | {card['correct_unknown']} | {card['false_medical']} | {card['unevaluable']} | "
                     f"{format(mean, '.1%') if mean is not None else 'unavailable'} |")
    lines += ["", "## Pilot and expansion", "", "| Cohort | Captures | Completed | Selected fallback wrong | Statistics wrong |",
              "| --- | ---: | ---: | ---: | ---: |"]
    for cohort, card in summary["per_cohort"].items():
        lines.append(f"| {cohort} | {card['captures']} | {card['statuses'].get('completed', 0)} | "
                     f"{card['methods']['selected_fallback']['false_medical']} | {card['methods']['statistics']['false_medical']} |")
    lines += ["", "Pilot predictions were reproduced exactly from verified original imports.", "",
              "## Per publisher folder", "", "| Folder | Captures | Completed | Selected fallback wrong | Statistics wrong | Combined wrong |",
              "| --- | ---: | ---: | ---: | ---: | ---: |"]
    for folder, card in summary["per_folder"].items():
        lines.append(f"| {folder} | {card['captures']} | {card['statuses'].get('completed', 0)} | "
                     f"{card['methods']['selected_fallback']['false_medical']} | {card['methods']['statistics']['false_medical']} | "
                     f"{card['methods']['combined']['false_medical']} |")
    lines += ["", "## Shared identities and indirect visibility", ""]
    for mac, folders in report["mac_groups"].items():
        if len(folders) > 1:
            lines.append(f"- {mac}: {', '.join(folders)}; one observed endpoint group.")
    for folder, entry in report["folders"].items():
        if entry["visibility"] == "gateway_mediated":
            lines.append(f"- {folder}: gateway-mediated evidence, not direct IP identification of the logical device.")
    wrong = [{"member": result["member"], "ip": row["ip"], "method": method, **prediction}
             for result in results for row in result.get("targets", []) for method, prediction in row["decisions"].items()
             if prediction["category"] != UNKNOWN]
    lines += ["", "## Errors and background observations", "",
              f"Reviewed target address-level medical assignments across methods: {len(wrong)}. "
              "All decisions, including failures and background hosts, are retained in predictions.json.", ""]
    for call in wrong[:30]:
        lines.append(f"- {call['member']}: {call['method']} assigned {call['category']} to {call['ip']} (score {call.get('score')}).")
    background = sum(p["category"] != UNKNOWN for result in results for row in result.get("background", []) for p in row["decisions"].values())
    lines += ["", f"Unreviewed background medical assignments across methods: {background}; excluded from target metrics.", "",
              "## Fallback after rules abstain", "", "```json", json.dumps(summary["fallback_after_rules_abstain"], indent=2), "```", "",
              "## Limits and integrity", "",
              "- No retraining, tuning or model promotion. Model and source hashes stayed fixed; completed imports passed identifier/time invariance.",
              "- Any medical assignment on a reviewed alias fails that setup's rejection. Missing targets are never counted as successful unknown decisions.",
              "- Protocol guards can reject these devices simply because confirmed HL7/DICOM is absent. This does not show learned consumer-device identification.",
              "- Startup traffic, laboratory conditions and repeated device instances limit generalization. Equal-MAC averaging does not make groups independent.",
              "- Forest scores are not calibrated unknown probabilities. No capture-completeness or zero-loss claim is made.",
              "- GNS3 medical classification and its fallback contribution remain a separate evaluation; see runs/module4-learning-study-20261116/REPORT.md.", ""]
    Path(path).write_text("\n".join(lines), encoding="utf-8")


def main():
    from config import tshark_path
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    audit_parser = commands.add_parser("audit")
    audit_parser.add_argument("--archive", type=Path, required=True)
    audit_parser.add_argument("--root", type=Path, required=True)
    audit_parser.add_argument("--pilot", type=Path, default=Path("runs/module4-sentinel-pilot-20261117/results"))
    audit_parser.add_argument("--tshark", default=tshark_path())
    evaluate_parser = commands.add_parser("evaluate")
    evaluate_parser.add_argument("--root", type=Path, required=True)
    evaluate_parser.add_argument("--models", type=Path, default=Path("runs/module4-traffic-comparison-20261116/models"))
    evaluate_parser.add_argument("--study", type=Path, default=Path("runs/module4-learning-study-20261116"))
    evaluate_parser.add_argument("--tshark", default=tshark_path())
    evaluate_parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if args.command == "audit":
        audit(args.archive, args.root, args.pilot, args.tshark)
    else:
        evaluate(args.root, args.models, args.study, args.tshark, args.resume)


if __name__ == "__main__":
    main()
