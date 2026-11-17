"""Replay the retained 12 November pump and CT captures through Modules 2 and 3."""
import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

from config import tshark_path
from module2.discovery import snapshot
from module2.parsing import normalize
from module2.pipeline import Pipeline
from module2.sensor import DICOM_CONTEXT_FIELDS, Sensor, tshark_fields
from module2.store import Store as MonitoringStore
from module3.input import stage
from module3.store import Store, recording

from .experiment import write_json
from .local_sensor import docker_zeek
SOURCE = Path("runs/module3-live-20261112-233505")
CT_UID = "1.2.840.10008.5.1.4.1.1.2"


def project(monitor, scope, output):
    inventory = Store(output / "inventory.sqlite3")
    with stage(snapshot(monitor, scope)) as (staged, header):
        inventory.apply(staged, header)
    return recording(inventory.path, header["source_id"], scope)


def local_replay(tshark, record, raw, monitor, scope, output):
    capture = output / record["observation_source"]
    capture.mkdir()
    retained = capture / "input.pcap"
    shutil.copyfile(raw, retained)
    shutil.copyfile(raw.with_name("conn.log"), capture / "conn.log")
    try:
        for name, fields in (("packets.tsv", None), ("dicom-contexts.tsv", DICOM_CONTEXT_FIELDS)):
            args = tshark_fields(retained) if fields is None else tshark_fields(
                retained, fields, True, "dicom.pdu.type == 1 && dicom.pctx.abss.syntax")
            with (capture / name).open("wb") as stream:
                subprocess.run([tshark, *args], stdout=stream, stderr=subprocess.PIPE, check=True)
        flows, issues, facts = normalize(capture, record["capture_id"], record["observation_source"], scope)
        monitor.ingest({**record, "scope": scope, "raw_capture": str(retained.resolve()),
                        "raw_retained": True, "reference": facts}, flows, issues)
    finally:
        for name in ("packets.tsv", "dicom-contexts.tsv"):
            (capture / name).unlink(missing_ok=True)


def packet_reference(tshark, path, role):
    """Independently decode cited frames without exporting clinical payload."""
    dicom = role == "modality"
    args = [tshark, "-n", "-2", "-r", str(path), "-d", "tcp.port==11112,dicom",
            "-T", "fields", "-E", "occurrence=a", "-E", "aggregator=|"]
    fields = ("frame.number", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
              "dicom.pctx.abss.syntax" if dicom else "tcp.payload")
    for field in fields:
        args.extend(("-e", field))
    raw = subprocess.check_output(args, stderr=subprocess.PIPE, text=True)
    frames = {}
    for frame, source, destination, sport, dport, payload in csv.reader(raw.splitlines(), delimiter="\t"):
        if dicom:
            present = CT_UID in re.findall(r"[0-9]+(?:\.[0-9]+)+", payload)
        else:
            wire = bytes.fromhex(payload.split("|")[0].replace(":", ""))
            present = any(segment.startswith(b"OBX|") and segment.split(b"|")[3:4] == [b"LAB_RATE"]
                          for segment in wire.split(b"\r"))
        if present:
            frames[int(frame)] = (source, destination, int(sport), int(dport))
    return frames


def replay(source, output, tshark, sensor_host=None, sensor_state=None, zeek_image=None):
    output.mkdir(parents=True)
    captures = {}
    for manifest in sorted((source / "module2" / "artifacts").glob("*/*/capture.json")):
        record = json.loads(manifest.read_text())
        role = record["observation_source"]
        raw = manifest.with_name("input.pcap")
        if role in ("pump", "modality") and raw.exists():
            # Use the newest retained revision, leaving the acceptance directory untouched.
            if role not in captures or record["processed_at"] > captures[role][0]["processed_at"]:
                captures[role] = record, raw
    if set(captures) != {"pump", "modality"}:
        raise ValueError("Both verified pump and modality captures must be present")
    scope = "module4-pump-ct-replay"
    monitor = MonitoringStore(output / "monitoring.sqlite3")
    references = {}
    if sensor_host:
        for name in ("known_hosts", "sensor-lock.json"):
            shutil.copyfile(sensor_state / name, output / name)
    if sensor_host:
        sensor = Sensor(sensor_host, output, persistent=True)
    else:
        sensor = docker_zeek(zeek_image, tshark, output) if zeek_image else None
    try:
        for role, (record, raw) in captures.items():
            if hashlib.sha256(raw.read_bytes()).hexdigest() != record["sha256"]:
                raise ValueError(f"Capture hash mismatch for {role}")
            if sensor:
                target = Pipeline(monitor, output, sensor).import_file(raw, role, scope)
            else:
                local_replay(tshark, record, raw, monitor, scope, output)
                target = record
            references[target["capture_id"]] = (role, packet_reference(tshark, raw, role))
        export = project(monitor, scope, output)
        write_json(output / "recording.json", export)
        canonical = {flow["flow_id"]: flow for flow in monitor.iter_flows(scope=scope)}
    finally:
        if sensor:
            sensor.close()
        monitor.close()
    matches = []
    expected = {(capture_id, frame) for capture_id, (_, frames) in references.items() for frame in frames}
    for flow in export["flows"]:
        original = canonical[flow["flow_id"]]
        for evidence in flow["evidence"]:
            capture_id = evidence["capture_id"]
            role, frames = references[capture_id]
            metadata = evidence["metadata"]
            feature = "flow_rate" in metadata.get("measurement_kinds", []) if role == "pump" else (
                CT_UID in metadata.get("requested_abstract_syntax_uids", []))
            if not feature:
                continue
            direction_matches = frames.get(evidence["frame"]) == (
                original["source_ip"], original["destination_ip"], original["source_port"], original["destination_port"])
            matches.append({"role": role, "flow_id": flow["flow_id"], "capture_id": capture_id,
                            "frame": evidence["frame"], "direction": evidence.get("direction"),
                            "packet_matches": direction_matches})
    counts = Counter(item["role"] for item in matches)
    observed = {(item["capture_id"], item["frame"]) for item in matches}
    passed = all(counts[role] >= 2 for role in captures) and observed == expected and all(
        item["packet_matches"] and item["direction"] == "originator" for item in matches)
    mode = "pinned_sensor" if sensor_host else "docker_zeek_local_tshark" if zeek_image else "saved_zeek_local_tshark"
    report = {"passed": passed, "mode": mode,
              "sensor_versions": sensor.versions if sensor else None,
              "reference_tshark": subprocess.check_output([tshark, "--version"], stderr=subprocess.PIPE,
                                                           text=True).splitlines()[0],
              "matches": matches, "expected_frames": len(expected)}
    write_json(output / "report.json", report)
    print(json.dumps(report, indent=2))
    return passed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tshark", default=tshark_path())
    backend = parser.add_mutually_exclusive_group()
    backend.add_argument("--sensor-host")
    backend.add_argument("--zeek-image")
    parser.add_argument("--sensor-state", type=Path)
    args = parser.parse_args()
    if bool(args.sensor_host) != bool(args.sensor_state):
        parser.error("--sensor-host and --sensor-state must be supplied together")
    sys.exit(0 if replay(args.source, args.output, args.tshark, args.sensor_host, args.sensor_state,
                         args.zeek_image) else 1)


if __name__ == "__main__":
    main()
