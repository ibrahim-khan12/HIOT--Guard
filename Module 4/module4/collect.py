"""Record isolated GNS3 hospital sessions and build label-free Module 3 exports."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import random
import shlex
import shutil
import time
from urllib.parse import urlsplit
import uuid

from config import CAPTURE_ROLES, ROLES, tshark_path
from gns3 import GNS3
from module2.pcap import complete_pcap
from module2.pipeline import Pipeline
from module2.sensor import Sensor
from module2.store import Store

from . import MEDICAL, OTHER, ROLE_LABELS
from .classifier import endpoint_rows, rule
from .experiment import load_json, write_json
from .local_sensor import LocalSensor, docker_zeek
from .replay import project

SUPPORT = ("workstation", "vendor", "unregistered", "pacs", "ehr")
EVALUATION_SESSIONS = {
    "eval-alternate": range(13, 16), "eval-fragmented": range(16, 19),
    "eval-burst": range(19, 22), "eval-ambiguous": range(22, 25),
}
SESSIONS = {"pilot": (0,), "training": range(1, 7), "validation": range(7, 10),
            "holdout": range(10, 13), **EVALUATION_SESSIONS}


def profile(number, split, seed):
    rng = random.Random(seed)
    roles = list(CAPTURE_ROLES)
    expanded = split in EVALUATION_SESSIONS
    if expanded:
        addresses = rng.sample(range(10, 245), len(ROLES) - 1)
    else:
        addresses = [10 + number * 15 + offset for offset in range(len(ROLES) - 1)]
    rng.shuffle(addresses)
    settings = {"addresses": dict(zip((r for r in ROLES if r != "gateway"), addresses)), "variants": {}}
    actor = Path(__file__).with_name("lab_actor.py").read_bytes()
    command = "python -c " + shlex.quote("import base64; exec(base64.b64decode(" +
                                        repr(base64.b64encode(actor).decode()) + "))")
    startup, schedule = list(ROLES), []
    rng.shuffle(startup)
    if expanded:
        settings["traffic_profile"] = split
        settings["seed"] = seed
        settings["variants"].update(workstation="verification", unregistered="generic_hl7")
        if split == "eval-ambiguous":
            # Each recording suppresses one HL7 kind and one DICOM storage class.
            index = number - EVALUATION_SESSIONS[split].start
            settings["variants"][("pump", "lab_analyzer", "dialysis")[index]] = "generic_hl7"
            settings["variants"][("modality", "mri", "ultrasound")[index]] = "verification"
        sparse_role = None
    elif split in ("validation", "holdout"):
        if number % 2 == 0:
            settings["variants"]["unregistered"] = "generic_hl7"
        else:
            settings["variants"]["workstation"] = "verification"
        sparse_role = "pump" if number % 2 == 0 else "modality"
    else:
        sparse_role = None
    for round_index in range(3 + number % 3):
        rng.shuffle(roles)
        for role in roles:
            if role == sparse_role and round_index > 0:
                continue
            delay = rng.uniform(.01, .55) if expanded else rng.uniform(.01, .22)
            schedule.append((round_index, role, delay))
    properties = {role: {"start_command": command,
                         "environment": f"LAB_ROLE={role}\nLAB_MODE=gns3\nMODULE4_SETTINGS=" +
                                        json.dumps(settings, separators=(",", ":"))} for role in ROLES}
    return settings, properties, startup, schedule


def get_capture(lab, role, path):
    # Read the completed file from the project rather than the live link stream.
    import urllib.request

    manifest = lab.manifest
    target = f"/v2/projects/{manifest['project_id']}/files/project-files/captures/module4-{role}.pcap"
    request = urllib.request.Request(lab.url + target, headers=lab.headers)
    with urllib.request.urlopen(request, timeout=20) as response:
        data = response.read(32 * 1024 * 1024 + 1)
    if len(data) > 32 * 1024 * 1024:
        raise ValueError(f"Capture for {role} exceeded the import bound")
    _, info = complete_pcap(data)
    if not info["frames"]:
        raise ValueError(f"No packets captured for {role}")
    path.write_bytes(data)
    return info


def capture(server, output, number, split, configured_profile=None):
    settings, properties, startup, schedule = configured_profile or profile(number, split, 4057 + number)
    began = time.time()
    out = output / "pcaps"
    out.mkdir(parents=True)
    lab = GNS3(server, output)
    manifest = lab.build(name=f"HIoT Module 4 {split} {number:02d}", docker_properties=properties)
    project = f"/projects/{manifest['project_id']}"
    started_captures = []
    actions = []
    try:
        lab.start(startup)
        roles = (*CAPTURE_ROLES, "pacs", "ehr")
        for role in roles:
            lab.api(f"{project}/links/{manifest['links'][role]}/start_capture",
                    {"capture_file_name": f"module4-{role}.pcap", "data_link_type": "DLT_EN10MB"})
            started_captures.append(role)
        def exercise(task):
            _, role, delay = task
            time.sleep(delay)
            return role, lab.agent(role, "/action", {"action": "probe"})

        with ThreadPoolExecutor(max_workers=6) as workers:
            for round_index in sorted({task[0] for task in schedule}):
                tasks = [task for task in schedule if task[0] == round_index]
                actions.extend(workers.map(exercise, tasks))
                time.sleep(.25 + .15 * (number % 4))
        failed = [role for role, result in actions if not result.get("success")]
        if failed:
            raise ValueError(f"Failed lab exchanges: {failed}")
        for role in tuple(started_captures):
            lab.api(f"{project}/links/{manifest['links'][role]}/stop_capture", {})
            started_captures.remove(role)
        facts = {role: get_capture(lab, role, out / f"{role}.pcap") for role in roles}
        entries = []
        for role in (*ROLE_LABELS, *SUPPORT):
            subnet = ROLES[role]["suffix"].rsplit(".", 1)[0]
            entries.append({"ip": f"10.77.{subnet}.{settings['addresses'][role]}",
                            "category": ROLE_LABELS.get(role, OTHER),
                            "instance_id": manifest["nodes"][role]})
        write_json(output / "capture-report.json", {"split": split, "session": number,
                   "scope": f"module4-{split}-{number:02d}-{manifest['project_id']}",
                   "captures": facts, "actions": actions, "endpoints": entries,
                   "settings": settings, "capture_seconds": time.time() - began})
    finally:
        for role in started_captures:
            try:
                lab.api(f"{project}/links/{manifest['links'][role]}/stop_capture", {})
            except (OSError, RuntimeError):
                pass
        lab.api(f"{project}/close", {}, timeout=90)


def analyze(folder, server, sensor_state, local_zeek=None, tshark=None, zeek_image=None):
    source = load_json(folder / "capture-report.json")
    output = folder / "analysis"
    output.mkdir(exist_ok=True)
    monitor = Store(output / "monitoring.sqlite3")
    if zeek_image:
        sensor = docker_zeek(zeek_image, tshark, output)
    elif local_zeek:
        sensor = LocalSensor(local_zeek, tshark)
    else:
        for name in ("known_hosts", "sensor-lock.json"):
            shutil.copyfile(sensor_state / name, output / name)
        sensor = Sensor(urlsplit(server).hostname, output, persistent=True)
    try:
        pipeline = Pipeline(monitor, output, sensor)
        for role, facts in source["captures"].items():
            record = pipeline.import_file(folder / "pcaps" / f"{role}.pcap", role, source["scope"])
            if record["sha256"] != facts["sha256"]:
                raise ValueError(f"Invalid capture digest for {role}")
        export = project(monitor, source["scope"], output)
    finally:
        sensor.close()
        monitor.close()
    save_evidence_report(folder, source, export, sensor.versions)
    write_json(folder / "recording.json", export)
    return {"recording": "recording.json", "endpoints": source["endpoints"]}


def save_evidence_report(folder, source, export, versions):
    rows = {row["ip"]: row for row in endpoint_rows(export)}
    facts = []
    for endpoint in source["endpoints"]:
        row = rows.get(endpoint["ip"])
        facts.append({"ip": endpoint["ip"], "expected": endpoint["category"], "observed": row is not None,
                      "candidates": dict(row["candidates"]) if row else {},
                      "supported_flows": dict(row["supported"]) if row else {},
                      "rule": rule(row)[0] if row else "unknown",
                      "features": dict(row["features"]) if row else {},
                      "evidence": row["references"] if row else []})
    if missing := [row["expected"] for row in facts if not row["observed"]]:
        raise ValueError(f"Labeled endpoints missing from the recording: {missing}")
    if source["split"] == "pilot":
        medical = {row["expected"]: row for row in facts if row["expected"] in MEDICAL}
        gaps = [category for category, row in medical.items() if not row["supported_flows"].get(category)]
        bedside = medical["bedside_monitor"]["features"]
        ecg = medical["ecg_monitor"]["features"]
        differences = {key: [bedside.get(key, 0), ecg.get(key, 0)] for key in sorted(bedside.keys() | ecg.keys())
                       if bedside.get(key, 0) != ecg.get(key, 0)}
        write_json(folder / "pilot-report.json", {
            "passed": not gaps, "medical_endpoints": len(medical), "evidence_gaps": gaps,
            "sensor_versions": versions,
            "heart_rate_pair": {"both_share_measurement_kind": bedside.get("hl7_heart_rate", 0) > 0 and
                                ecg.get("hl7_heart_rate", 0) > 0, "feature_differences": differences,
                                "rule_decisions": [medical[key]["rule"] for key in ("bedside_monitor", "ecg_monitor")]}})
        if gaps:
            raise ValueError(f"Pilot is missing supported clinical evidence for: {gaps}")
    write_json(folder / "evidence-report.json", facts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sensor-state", type=Path)
    parser.add_argument("--split", choices=tuple(SESSIONS), required=True)
    local = parser.add_mutually_exclusive_group()
    local.add_argument("--local-zeek", nargs="+", help="Explicit local offline Zeek executable and arguments")
    local.add_argument("--zeek-image", help="Offline Zeek Docker image, preferably pinned by digest")
    parser.add_argument("--tshark", default=tshark_path())
    parser.add_argument("--capture-only", action="store_true")
    parser.add_argument("--analyze-existing", action="store_true")
    args = parser.parse_args()
    if args.capture_only and args.analyze_existing:
        parser.error("--capture-only and --analyze-existing are mutually exclusive")
    if not args.capture_only and not (args.sensor_state or args.local_zeek or args.zeek_image):
        parser.error("Analysis needs --sensor-state, --local-zeek, or --zeek-image")
    sessions = []
    for number in SESSIONS[args.split]:
        folder = args.output / f"session-{number:02d}"
        print(f"Module 4 {args.split}: session {number:02d}", flush=True)
        if not args.analyze_existing and not (folder / "capture-report.json").exists():
            capture(args.server, folder, number, args.split)
        if not args.capture_only:
            if (folder / "recording.json").exists() and (folder / "evidence-report.json").exists():
                session = {"recording": "recording.json", "endpoints": load_json(folder / "capture-report.json")["endpoints"]}
            else:
                session = analyze(folder, args.server, args.sensor_state, args.local_zeek, args.tshark, args.zeek_image)
            session["recording"] = f"{folder.name}/{session['recording']}"
            sessions.append(session)
    if sessions:
        target = args.output / f"{args.split}.json"
        manifest = {"recordings": sessions}
        if target.exists():
            if load_json(target) != manifest:
                raise ValueError(f"Existing split manifest differs from processed recordings: {target}")
        else:
            write_json(target, manifest)


if __name__ == "__main__":
    main()
