"""Packet-prefix evidence contract for the development pilot.

This does not alter the frozen v1 model or assert physical device identity from
workflow evidence. Identifiers are used transiently for transaction matching;
only allowlisted semantic groups, counts, quality and packet statistics escape.
"""
from collections import defaultdict
import csv
import hashlib
import io
import json
from pathlib import Path
import statistics
import struct
import subprocess

VERSION = "hiot.workflow-evidence.v2.0"
KINDS = {("LAB_RATE", "99HIOT"): "flow_rate", ("HEART_RATE", "99HIOT"): "heart_rate",
         ("ECG_HEART_RATE", "99HIOT"): "heart_rate", ("GLUCOSE", "99HIOT"): "glucose",
         ("RESPIRATORY_RATE", "99HIOT"): "respiratory_rate", ("BLOOD_FLOW", "99HIOT"): "blood_flow",
         ("8867-4", "LN"): "heart_rate", ("9279-1", "LN"): "respiratory_rate"}
STORAGE = {"1.2.840.10008.5.1.4.1.1.2": "ct_storage", "1.2.840.10008.5.1.4.1.1.4": "mr_storage",
           "1.2.840.10008.5.1.4.1.1.6.1": "ultrasound_storage", "1.2.840.10008.5.1.4.1.1.1.1": "dx_storage"}
MPPS_UID = "1.2.840.10008.3.1.2.3.3"
FIELDS = ("frame.number", "frame.time_epoch", "frame.len", "frame.cap_len", "ip.src", "ip.dst",
          "tcp.srcport", "tcp.dstport", "tcp.stream", "tcp.seq_raw", "tcp.flags.syn", "tcp.flags.ack", "tcp.payload")


def packets(path, tshark):
    args = [str(tshark), "-n", "-r", str(path), "-T", "fields", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=f"]
    for field in FIELDS:
        args.extend(["-e", field])
    result = subprocess.run(args, capture_output=True, text=True, check=True, timeout=180)
    output = []
    for values in csv.reader(io.StringIO(result.stdout), delimiter="\t"):
        row = dict(zip(FIELDS, values))
        if not row["ip.src"] or not row["ip.dst"]:
            continue
        output.append({"frame": int(row["frame.number"]), "time": float(row["frame.time_epoch"]),
                       "length": int(row["frame.len"]), "captured": int(row["frame.cap_len"]),
                       "src": row["ip.src"], "dst": row["ip.dst"], "sport": row["tcp.srcport"], "dport": row["tcp.dstport"],
                       "stream": row["tcp.stream"], "seq": int(row["tcp.seq_raw"] or 0),
                       "syn": row["tcp.flags.syn"].lower() in ("1", "true"), "ack": row["tcp.flags.ack"].lower() in ("1", "true"),
                       "payload": bytes.fromhex(row["tcp.payload"].replace(":", ""))})
    return output


def contiguous(items):
    """Bounded TCP assembly. Conflicting overlap fails closed, gaps stop parsing.

    Prefix filtering happens before this function. Retransmissions are not new
    transactions. A missing SYN is exposed and cannot produce accepted evidence.
    """
    syns = [p for p in items if p["syn"]]
    body = [p for p in items if p["payload"]]
    if not body:
        return b"", [], {"missing_syn": int(not syns), "gap": 0, "conflicting_overlap": 0}
    base = ((syns[0]["seq"] + 1) & 0xFFFFFFFF) if syns else body[0]["seq"]
    slots = {}
    conflict = False
    for packet in body:
        offset = (packet["seq"] - base) & 0xFFFFFFFF
        if offset > 2 * 1024 * 1024 or offset + len(packet["payload"]) > 2 * 1024 * 1024:
            return b"", [], {"missing_syn": int(not syns), "gap": 1, "conflicting_overlap": 0}
        for index, value in enumerate(packet["payload"], offset):
            if index in slots and slots[index][0] != value:
                conflict = True
            slots.setdefault(index, (value, packet["frame"], packet["time"]))
    end = 0
    while end in slots:
        end += 1
    quality = {"missing_syn": int(not syns), "gap": int(end < len(slots)), "conflicting_overlap": int(conflict)}
    if conflict:
        return b"", [], quality
    return bytes(slots[i][0] for i in range(end)), [slots[i][1:] for i in range(end)], quality


def reference(marks, start, end):
    selected = marks[start:end]
    return {"frames": sorted({m[0] for m in selected}), "completed_at": max(m[1] for m in selected)}


def hl7_messages(data, marks, *, linkage=False):
    out = []
    cursor = 0
    while True:
        start = data.find(b"\x0bMSH", cursor)
        if start < 0:
            break
        end = data.find(b"\x1c\r", start)
        if end < 0:
            break
        cursor = end + 2
        try:
            segments = [part.split("|") for part in data[start+1:end].decode("ascii").split("\r") if part]
        except UnicodeDecodeError:
            continue
        msh = segments[0]
        if len(msh) < 12 or msh[1] != "^~\\&":
            continue
        item = {"type": msh[8].split("^")[0], "control": msh[9], "kinds": [], "unmapped_codes": 0,
                "reference": reference(marks, start, cursor)}
        waveform = defaultdict(set)
        for segment in segments[1:]:
            if segment[0] == "OBX" and len(segment) > 3:
                parts = segment[3].split("^")
                key = (parts[0], parts[2] if len(parts) > 2 else "")
                kind = KINDS.get(key)
                if kind:
                    item["kinds"].append(kind)
                else:
                    item["unmapped_codes"] += 1
                if linkage and msh[8].split("^")[:2] == ["ORU", "W01"] and len(segment) > 5 and key[1] == "99HIOT":
                    base, _, suffix = key[0].partition("&")
                    valid_types = {"CHN": ("CD",), "TIM": ("TS",), "WAV": ("NA", "MA")}
                    if base == "ECG" and segment[4] and segment[5] and segment[2] in valid_types.get(suffix, ()):
                        waveform[segment[4]].add(suffix)
            elif segment[0] == "MSA" and len(segment) > 2:
                item["ack_status"], item["ack_for"] = segment[1:3]
        if any(parts == {"CHN", "TIM", "WAV"} for parts in waveform.values()):
            item["kinds"].append("ecg_waveform_reporting")
        item["kinds"] = sorted(set(item["kinds"]))
        if linkage and item["type"] == "ORU":
            item["message_digest"] = hashlib.sha256(data[start:cursor]).digest()
        out.append(item)
    return out


def dicom_messages(data, marks, *, linkage=False):
    out, pending = [], {}
    offset = 0
    while offset + 6 <= len(data):
        typ, reserved, size = struct.unpack_from(">BBI", data, offset)
        if reserved or typ not in range(1, 8) or size > 2 * 1024 * 1024:
            break
        end = offset + 6 + size
        if end > len(data):
            break
        body = data[offset+6:end]
        ref = reference(marks, offset, end)
        if typ in (1, 2) and len(body) >= 68:
            pos = 68
            while pos + 4 <= len(body):
                kind, _, length = struct.unpack_from(">BBH", body, pos)
                value = body[pos+4:pos+4+length]
                if len(value) != length:
                    break
                if kind == 0x20 and len(value) >= 4:
                    at = 4
                    while at + 4 <= len(value):
                        sub, _, amount = struct.unpack_from(">BBH", value, at)
                        raw = value[at+4:at+4+amount]
                        if sub == 0x30:
                            uid = raw.decode("ascii", errors="replace").strip("\0 ")
                            workflow = "mpps" if linkage and uid == MPPS_UID else STORAGE.get(uid)
                            out.append({"type": "proposal", "context": value[0], "workflow": workflow, "reference": ref})
                        at += 4 + amount
                elif kind == 0x21 and len(value) >= 4:
                    out.append({"type": "context_result", "context": value[0], "status": value[2], "reference": ref})
                pos += 4 + length
        elif typ == 4:
            at = 0
            while at + 6 <= len(body):
                amount = struct.unpack_from(">I", body, at)[0]
                if amount < 2 or at + 4 + amount > len(body):
                    break
                context, control = body[at+4:at+6]
                if control & 1:
                    accumulator, refs = pending.setdefault(context, (bytearray(), []))
                    accumulator.extend(body[at+6:at+4+amount])
                    refs.append(ref)
                    if control & 2:
                        tags, position = {}, 0
                        while position + 8 <= len(accumulator):
                            group, element, length = struct.unpack_from("<HHI", accumulator, position)
                            raw = accumulator[position+8:position+8+length]
                            if group != 0 or len(raw) != length:
                                break
                            tags[element] = bytes(raw)
                            position += 8 + length
                        def number(tag):
                            raw = tags.get(tag, b"")
                            return struct.unpack("<H", raw)[0] if len(raw) == 2 else None
                        cmd = number(0x100)
                        operations = {1: "store_request", 0x8001: "store_response"}
                        if linkage:
                            operations.update({0x0140: "create_request", 0x8140: "create_response",
                                               0x0120: "set_request", 0x8120: "set_response"})
                        if cmd in operations:
                            uid = tags.get(3 if cmd == 0x0120 else 2, b"").decode("ascii", errors="replace").strip("\0 ")
                            workflow = "mpps" if linkage and uid == MPPS_UID else STORAGE.get(uid)
                            out.append({"type": operations[cmd], "context": context,
                                        "id": number(0x120 if cmd & 0x8000 else 0x110), "status": number(0x900),
                                        "workflow": workflow,
                                        "reference": {"frames": sorted({f for r in refs for f in r["frames"]}),
                                                      "completed_at": max(r["completed_at"] for r in refs)}})
                            if linkage and not (cmd & 0x8000):
                                instance = tags.get(0x1001 if cmd == 0x0120 else 0x1000, b"").strip(b"\0 ")
                                if 0 < len(instance) <= 64 and all(part.isdigit() for part in instance.split(b".")):
                                    out[-1]["instance_digest"] = hashlib.sha256(instance).digest()
                        pending.pop(context)
                at += 4 + amount
        offset = end
    return out


def summary(values):
    if not values:
        return {"count": 0, "mean": 0, "std": 0, "min": 0, "max": 0}
    return {"count": len(values), "mean": statistics.mean(values), "std": statistics.pstdev(values), "min": min(values), "max": max(values)}


def analyze(items, endpoint, seconds, capture_end, capture_sha256=""):
    observed = [p for p in items if endpoint in (p["src"], p["dst"])]
    if not observed:
        return {"endpoint": endpoint, "category": "unknown", "reason": "endpoint_unseen", "window_seconds": seconds, "features": {}, "evidence": []}
    start = min(p["time"] for p in observed)
    cutoff = start + seconds
    # Critical: no complete-flow or future-packet information enters assembly.
    prefix = [p for p in observed if p["time"] <= cutoff]
    features, evidence, workflows = {}, [], set()
    for side, key in (("sent", "src"), ("received", "dst")):
        selected = sorted([p for p in prefix if p[key] == endpoint], key=lambda p: (p["time"], p["frame"]))
        for name, value in summary([p["length"] for p in selected]).items():
            features[f"packet_length_{side}_{name}"] = value
        intervals = [b["time"]-a["time"] for a,b in zip(selected, selected[1:])]
        for name, value in summary(intervals).items():
            features[f"iat_{side}_{name}"] = value
        features[f"idle_intervals_{side}"] = sum(t > 1 for t in intervals)
    features["coverage_sufficient"] = int(capture_end >= cutoff)
    features["truncated_packets"] = sum(p["captured"] < p["length"] for p in prefix)
    groups = defaultdict(list)
    for packet in prefix:
        if packet["stream"] != "":
            groups[(packet["stream"], packet["src"], packet["dst"])].append(packet)
    parsed = {}
    for key, group in groups.items():
        data, marks, quality = contiguous(group)
        for name, value in quality.items():
            features[name] = features.get(name, 0) + value
        clean = not any(quality.values())
        parsed[key] = (hl7_messages(data, marks), dicom_messages(data, marks), clean)
    features["connections"] = len({k[0] for k in groups})
    def count(name, value=1):
        features[name] = features.get(name, 0) + value
    def retain(protocol, event, refs, workflow=None):
        evidence.append({"protocol": protocol, "event": event, "workflow": workflow,
                         "capture_sha256": capture_sha256, "frames": sorted({f for r in refs for f in r["frames"]}),
                         "completed_at": max(r["completed_at"] for r in refs)})
    for (stream, src, dst), (hl7, dicom, clean) in parsed.items():
        if src != endpoint:
            continue
        replies_h, replies_d, reply_clean = parsed.get((stream, dst, src), ([], [], False))
        used = set()
        for request in hl7:
            if request["type"] != "ORU":
                continue
            count("oru_messages")
            count("unmapped_observations", request["unmapped_codes"])
            for kind in request["kinds"]:
                count("observed_" + kind)
                workflows.add(kind + "_reporting")
            matches = [(i,r) for i,r in enumerate(replies_h) if i not in used and r.get("ack_for") == request["control"]
                       and r["type"] == "ACK" and r["reference"]["completed_at"] >= request["reference"]["completed_at"]]
            event = "unacknowledged"
            refs = [request["reference"]]
            if matches:
                index, reply = matches[0]
                used.add(index)
                event = {"AA": "accepted", "AR": "rejected", "AE": "error"}.get(reply.get("ack_status"), "unrecognized_ack")
                refs.append(reply["reference"])
            if not clean or not reply_clean:
                event = "limited_capture"
            count("oru_" + event)
            retain("HL7/MLLP", event, refs)
        proposals = {d["context"]: d for d in dicom if d["type"] == "proposal"}
        for proposal in proposals.values():
            count("dicom_proposals")
            retain("DICOM", "proposed_context", [proposal["reference"]], proposal["workflow"])
        accepted = {d["context"] for d in replies_d if d["type"] == "context_result" and d["status"] == 0}
        used_d = set()
        for request in dicom:
            if request["type"] != "store_request":
                continue
            proposal = proposals.get(request["context"])
            workflow = request["workflow"] or (proposal or {}).get("workflow")
            count("store_requests")
            matches = [(i,r) for i,r in enumerate(replies_d) if i not in used_d and r["type"] == "store_response"
                       and r["id"] == request["id"] and r["context"] == request["context"]
                       and r["reference"]["completed_at"] >= request["reference"]["completed_at"]]
            event, refs = "store_unconfirmed", [request["reference"]]
            if matches:
                index, reply = matches[0]
                used_d.add(index)
                refs.append(reply["reference"])
                event = "store_success" if reply["status"] == 0 else "store_non_success"
            if not clean or not reply_clean or request["context"] not in accepted:
                event = "limited_capture"
            count(event)
            if workflow and event == "store_success":
                workflows.add(workflow)
                count(workflow + "_success")
            retain("DICOM", event, refs, workflow)
    # Workflow metadata does not authenticate its physical origin. No registry,
    # ground-truth label or endpoint identifier participates in this decision.
    reason = "workflow_does_not_establish_physical_device" if workflows else "insufficient_workflow_evidence"
    if not features["coverage_sufficient"]:
        reason = "insufficient_observation_coverage"
    return {"schema_version": VERSION, "endpoint": endpoint, "category": "unknown", "reason": reason,
            "method": "conservative_workflow_rules", "model_score": None, "window_seconds": seconds,
            "observed_seconds": min(seconds, max(0, capture_end-start)), "workflows": sorted(workflows),
            "features": features, "evidence": evidence}


def export_capture(pcap, manifest, tshark, windows=(10,30,60,120)):
    path = Path(pcap)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != manifest["sha256"]:
        raise ValueError("Capture hash differs from manifest")
    items = packets(path, tshark)
    # Packet timestamps provide a conservative observation horizon even when
    # host and VM clocks differ. Do not invent a quiet tail from host wall time.
    observed_end = max((p["time"] for p in items), default=0)
    return {"schema_version": VERSION, "capture_sha256": digest, "purpose": "development_only",
            "observation_end_basis": "last_observed_ip_packet; no assumed quiet tail",
            "rows": [analyze(items, endpoint, seconds, observed_end, digest)
                     for seconds in windows for endpoint in manifest["endpoints"]]}
