"""Extract packet-level experiment evidence from a Module 2 recording scope."""
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
import math
from pathlib import Path
import shutil
import sqlite3
import subprocess
from tempfile import NamedTemporaryFile, TemporaryDirectory

from config import address, tshark_path
from scenario_profile import MQTT_PORT, MQTT_RATE, MQTT_TOPIC, ROLE_IPS, UDP_PORT, UDP_RATE, parse_payload
from .pcap import packet_fingerprints, snapshot


FIELDS = (
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
    "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.reset", "tcp.payload", "udp.srcport", "udp.dstport", "udp.payload",
    "mqtt.msgtype", "mqtt.topic", "mqtt.msg", "arp.opcode", "arp.src.hw_mac",
    "arp.src.proto_ipv4", "arp.dst.proto_ipv4",
)


def retained_captures(state, scope, sources, begin, end):
    database = (Path(state) / "monitoring.sqlite3").resolve()
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
        return [record for (raw,) in db.execute("SELECT data FROM captures WHERE scope=? ORDER BY updated", (scope,))
                if (record := json.loads(raw))["observation_source"] in sources
                and record["raw_retained"] and record.get("last_packet_time") is not None
                and record["last_packet_time"] >= begin
                and record["first_packet_time"] <= end]


def iter_packets(captures, begin, end, evidence_folder=None):
    seen = set()
    with TemporaryDirectory(prefix="hiot-scenario-evidence-") as directory:
        local = Path(directory) / "input.pcap"
        for capture in captures:
            source, path = capture["observation_source"], Path(capture["raw_capture"])
            if not path.exists():
                continue
            facts = snapshot(path, local)
            if capture.get("sha256") and facts["sha256"] != capture["sha256"]:
                raise ValueError(f"Capture revision changed or failed its digest check: {capture['capture_id']}")
            evidence_path = path
            if evidence_folder is not None:
                evidence_folder = Path(evidence_folder).resolve()
                evidence_folder.mkdir(parents=True, exist_ok=True)
                evidence_path = evidence_folder / (facts["sha256"] + ".pcap")
                if evidence_path.exists():
                    with evidence_path.open("rb") as archived:
                        if hashlib.file_digest(archived, "sha256").hexdigest() != facts["sha256"]:
                            raise ValueError(f"Saved evidence hash mismatch: {evidence_path}")
                else:
                    # Copy the validated snapshot before the live collector can replace it.
                    with NamedTemporaryFile(dir=evidence_folder, suffix=".tmp", delete=False) as target:
                        temporary = Path(target.name)
                        try:
                            with local.open("rb") as input_file:
                                shutil.copyfileobj(input_file, target)
                            target.close()
                            temporary.replace(evidence_path)
                        finally:
                            target.close()
                            temporary.unlink(missing_ok=True)
            exact = packet_fingerprints(local)
            fields = [arg for field in FIELDS for arg in ("-e", field)]
            result = subprocess.run([tshark_path(), "-n", "-r", str(local), "-d", f"tcp.port=={MQTT_PORT},mqtt",
                                     "-Y", f"frame.time_epoch >= {begin:.6f} && frame.time_epoch <= {end:.6f}",
                                     "-T", "fields", "-E", "separator=/t", "-E", "quote=d",
                                     "-E", "occurrence=f", *fields], capture_output=True, text=True,
                                    encoding="utf-8", errors="replace", check=True, timeout=60)
            for values in csv.reader(result.stdout.splitlines(), delimiter="\t"):
                row = dict(zip(FIELDS, values, strict=True))
                frame = int(row["frame.number"])
                if frame not in exact:
                    continue
                identity = source, exact[frame]
                if identity in seen:
                    continue
                seen.add(identity)
                yield {**row, "capture_id": capture["capture_id"], "source": source,
                       "sha256": facts["sha256"], "path": str(evidence_path), "frame": frame,
                       "timestamp": float(row["frame.time_epoch"])}


def reference(row):
    return {key: row[key] for key in ("capture_id", "source", "sha256", "path", "frame", "timestamp")}


def flag(row, field):
    return row[field].lower() in ("true", "1")


def tcp_evidence(run, rows):
    role = next(iter(run["expected_sources"]))
    src = run["expected_sources"][role]
    attempts = []
    for attempt in run["agents"].get(role, {}).get("result", {}).get("attempts", []):
        target, port, local = attempt["destination_ip"], str(attempt["destination_port"]), str(attempt["source_port"])
        outgoing = [p for p in rows if p["source"] == role and p["ip.src"] == src and p["ip.dst"] == target
                    and p["tcp.srcport"] == local and p["tcp.dstport"] == port and flag(p, "tcp.flags.syn")
                    and not flag(p, "tcp.flags.ack")]
        incoming = [p for p in rows if p["source"] == role and p["ip.src"] == target and p["ip.dst"] == src
                    and p["tcp.srcport"] == port and p["tcp.dstport"] == local]
        attempts.append({"source_port": local, "destination": target, "port": int(port), "sender_connected": attempt["success"],
                         "syn": [reference(p) for p in outgoing],
                         "syn_ack": [reference(p) for p in incoming if flag(p, "tcp.flags.syn") and flag(p, "tcp.flags.ack")],
                         "reset": [reference(p) for p in incoming if flag(p, "tcp.flags.reset")]})
    allowed = {(target["ip"], port) for target in run["expected_destinations"].values() for port in target["ports"]}
    complete = (len(attempts) == (8 if role == "workstation" else 4) and
                {(item["destination"], item["port"]) for item in attempts} == allowed and
                all(item["syn"] and bool(item["syn_ack"]) == item["sender_connected"] for item in attempts))
    matched_ack = []
    if role == "pump":
        # Correlate the application ACK to the request's control ID on the same TCP connection.
        pending = set()
        for row in sorted(rows, key=lambda item: item["timestamp"]):
            if row["source"] != "pump" or not row["tcp.payload"]:
                continue
            raw = bytes.fromhex(row["tcp.payload"].replace(":", ""))
            if row["ip.src"] == src and row["tcp.dstport"] == "2575" and raw.startswith(b"\x0bMSH|"):
                header = raw.split(b"\r", 1)[0].split(b"|")
                if len(header) > 9 and header[8] == b"ORU^R01":
                    pending.add((row["tcp.srcport"], header[9]))
            if (row["ip.dst"] == src and row["tcp.srcport"] == "2575"
                    and run["active_epoch"] <= row["timestamp"] <= run["active_end_epoch"]):
                for segment in raw.split(b"\r"):
                    parts = segment.split(b"|")
                    if len(parts) > 2 and parts[:2] == [b"MSA", b"AA"] and (row["tcp.dstport"], parts[2]) in pending:
                        matched_ack.append(reference(row))
        complete = complete and bool(matched_ack)
    return {"passed": complete, "tcp_attempts": attempts, "matching_pump_ack_frames": matched_ack}


def burst_evidence(run, rows):
    mqtt = run["scenario_id"] == "mqtt-burst"
    chosen = "arp_observer" if mqtt else "scenario_service"
    destination = ROLE_IPS[chosen]
    frames, buckets = [], defaultdict(Counter)
    totals = defaultdict(Counter)
    for row in rows:
        if row["source"] != chosen or row["ip.dst"] != destination:
            continue
        if mqtt:
            if row["ip.src"] != ROLE_IPS["scenario_service"] or row["mqtt.msgtype"] != "3" or row["mqtt.topic"] != MQTT_TOPIC:
                continue
            encoded, source = row["mqtt.msg"], MQTT_TOPIC
        else:
            if row["ip.src"] not in run["expected_sources"].values() or row["udp.dstport"] != str(UDP_PORT):
                continue
            encoded, source = row["udp.payload"], row["ip.src"]
        tag = parse_payload(bytes.fromhex(encoded.replace(":", "")))
        if not tag or tag[0] != run["run_id"]:
            continue
        _, phase, index = tag
        second = math.floor(row["timestamp"] - run["active_epoch"])
        buckets[source][second] += 1
        totals[source][phase] += 1
        frames.append({**reference(row), "source_ip": row["ip.src"], "destination_ip": row["ip.dst"],
                       "destination_port": int(row["tcp.dstport"]) if mqtt else UDP_PORT,
                       "topic": MQTT_TOPIC if mqtt else None,
                       "phase": phase, "sequence": index, "second_from_burst_start": second,
                       "protocol": "MQTT PUBLISH" if mqtt else "UDP"})
    rate = MQTT_RATE if mqtt else UDP_RATE
    checks = {}
    for role, ip in run["expected_sources"].items():
        source = MQTT_TOPIC if mqtt else ip
        observed = totals[source]
        sent = run["agents"].get(role, {}).get("result", {}).get("sent", {})
        received = run.get("receiver", {}).get(source, {})
        checks[source] = {"sender": sent, "receiver": received, "captured": dict(observed),
                          "baseline_per_second": observed["baseline"] / 5, "burst_per_second": observed["burst"] / 5,
                          "passed": (1 <= observed["baseline"] <= 5 and observed["baseline"] * 4 <= observed["burst"] <= rate * 5
                                     and all(observed[phase] == sent.get(phase) == received.get(phase)
                                             for phase in ("baseline", "burst")))}
    if run["scenario_id"] == "udp-dual":
        first, second = (buckets[ip] for ip in run["expected_sources"].values())
        overlap = sorted(index for index in first.keys() & second.keys() if 0 <= index < 5)
    else:
        overlap = None
    return {"passed": bool(checks) and all(v["passed"] for v in checks.values()) and (overlap is None or bool(overlap)),
            "counts": checks, "overlapping_burst_seconds": overlap, "packet_time_buckets": dict(buckets), "frames": frames}


def arp_evidence(run, rows):
    frames = [{**reference(row), "claimed_ip": row["arp.src.proto_ipv4"], "claimed_mac": row["arp.src.hw_mac"]}
              for row in rows if row["source"] == "arp_observer" and row["arp.opcode"] == "2"
              and row["arp.src.proto_ipv4"] == ROLE_IPS["scenario_service"]
              and row["arp.dst.proto_ipv4"] == ROLE_IPS["arp_observer"]]
    legitimate = [p for p in frames if p["claimed_mac"] == run["expected_service_mac"]
                  and p["timestamp"] < run["active_epoch"]]
    conflicting = [p for p in frames if p["claimed_mac"] == run["expected_conflict_mac"]
                   and run["active_epoch"] <= p["timestamp"] <= run["active_end_epoch"]]
    retained = (run.get("neighbor_before") == run.get("neighbor_after") and
                run["expected_service_mac"] in run.get("neighbor_after", "") and "PERMANENT" in run.get("neighbor_after", ""))
    return {"passed": bool(legitimate) and len(conflicting) == 3 and retained,
            "legitimate_frames": legitimate, "conflicting_frames": conflicting, "neighbor_retained": retained}


def evaluate(run, state=None, evidence_folder=None):
    if run.get("status") != "completed":
        return {"passed": False, "run_id": run["run_id"], "scenario_id": run["scenario_id"],
                "reason": f"Run status is {run['status']}"}
    begin, end = run["start_epoch"] - 0.25, run["end_epoch"]
    if state is None:
        captures = [{"observation_source": source, "capture_id": None,
                     "raw_capture": str(Path(run["module1_session"]) / (source + ".pcap"))}
                    for source in run["capture_links"]]
    else:
        captures = retained_captures(state, run["capture_scope"], run["capture_links"], begin, end)
    rows = list(iter_packets(captures, begin, end, evidence_folder))
    key = run["scenario_id"]
    if key in ("workstation-recon", "pump-to-pacs"):
        evidence = tcp_evidence(run, rows)
    elif key == "arp-conflict":
        evidence = arp_evidence(run, rows)
    else:
        evidence = burst_evidence(run, rows)
    return {"schema_version": 1, "run_id": run["run_id"], "scenario_id": key, "capture_scope": run["capture_scope"],
            "capture_links": run["capture_links"],
            "capture_origin": "module2_retained" if state else "module1_raw", **evidence}


def packet_observations(state, scope, source, begin, end):
    """Emit one link's packet observations without scenario labels or payload data."""
    captures = retained_captures(state, scope, [source], begin, end)
    if not captures:
        raise ValueError("No retained capture covers that source and time range")
    for row in iter_packets(captures, begin, end):
        record = {"schema_version": 1, "scope": scope, **reference(row)}
        if row["arp.opcode"]:
            yield {**record, "protocol": "ARP", "opcode": int(row["arp.opcode"]), "sender_ip": row["arp.src.proto_ipv4"],
                   "sender_mac": row["arp.src.hw_mac"], "target_ip": row["arp.dst.proto_ipv4"]}
        elif row["mqtt.msgtype"]:
            yield {**record, "protocol": "MQTT", "message_type": int(row["mqtt.msgtype"]), "topic": row["mqtt.topic"] or None,
                   "source_ip": row["ip.src"], "destination_ip": row["ip.dst"],
                   "source_port": int(row["tcp.srcport"]), "destination_port": int(row["tcp.dstport"])}
        elif row["udp.dstport"]:
            yield {**record, "protocol": "UDP", "source_ip": row["ip.src"], "destination_ip": row["ip.dst"],
                   "source_port": int(row["udp.srcport"]), "destination_port": int(row["udp.dstport"]),
                   "payload_bytes": len(row["udp.payload"].replace(":", "")) // 2}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_log", type=Path)
    origin = parser.add_mutually_exclusive_group(required=True)
    origin.add_argument("--state", type=Path, help="Module 2 recording state directory")
    origin.add_argument("--module1", action="store_true", help="Cross-check the separate Module 1 raw captures")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--evidence-folder", type=Path, help="Keep the verified PCAP revisions alongside the report")
    args = parser.parse_args()
    report = evaluate(json.loads(args.run_log.read_text(encoding="utf-8")), args.state, args.evidence_folder)
    raw = json.dumps(report, indent=2)
    if args.output:
        args.output.write_text(raw, encoding="utf-8")
    else:
        print(raw)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
