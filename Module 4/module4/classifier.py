"""Endpoint features and evidence rules shared by all evaluation methods."""
from collections import Counter, defaultdict
from statistics import median

from . import UNKNOWN

DICOM_CATEGORIES = {
    "1.2.840.10008.5.1.4.1.1.2": "ct",
    "1.2.840.10008.5.1.4.1.1.4": "mri",
    "1.2.840.10008.5.1.4.1.1.6.1": "ultrasound",
    "1.2.840.10008.5.1.4.1.1.1.1": "portable_xray",
}
HL7_CATEGORIES = {
    "flow_rate": ("infusion_pump",),
    "heart_rate": ("bedside_monitor", "ecg_monitor"),
    "glucose": ("lab_analyzer",),
    "respiratory_rate": ("ventilator",),
    "blood_flow": ("dialysis_machine",),
}
RECORDING_SCHEMA = "hiot.discovery.recording.v1"
MIN_EXCHANGES = 2


def references(flow, items):
    return [{"flow_id": flow["flow_id"], **{key: item[key] for key in (
        "evidence_id", "capture_id", "frame", "supporting_frames") if key in item}} for item in items]


def endpoint_rows(recording):
    if recording.get("schema_version") != RECORDING_SCHEMA:
        raise ValueError("Expected a Module 3 classification recording")
    active = {asset["ip"]: asset for asset in recording["assets"] if asset["address_kind"] == "unicast_address"}
    rows = {ip: {"scope": recording["scope"], "source_id": recording["source_id"], "asset_id": asset["asset_id"],
                 "ip": ip, "presence": asset["presence"], "features": Counter(), "candidates": Counter(),
                 "supported": Counter(), "protocols": set(), "times": [], "peers": set(), "references": []}
            for ip, asset in active.items()}
    seen = set()
    for flow in recording["flows"]:
        flow_id = flow["flow_id"]
        if flow_id in seen:
            raise ValueError("Duplicate canonical flow ID")
        seen.add(flow_id)
        if flow["source_ip"] == flow["destination_ip"]:
            continue
        confirmed = defaultdict(list)
        for item in flow["evidence"]:
            if item.get("parser_status") == "confirmed" and item.get("direction") in ("originator", "responder"):
                confirmed[item["direction"]].append(item)
        for own, peer, direction in (("source_ip", "destination_ip", "originator"),
                                     ("destination_ip", "source_ip", "responder")):
            if flow[own] not in rows:
                continue
            row = rows[flow[own]]
            measurements = row["features"]
            outbound = direction == "originator"
            side = "initiated" if outbound else "received"
            row["peers"].add(flow[peer])
            measurements[f"{side}_flows"] += 1
            measurements[f"{side}_tcp_flows"] += flow["transport"] == "tcp"
            measurements["packets_sent"] += flow["origin_packets" if outbound else "response_packets"] or 0
            measurements["packets_received"] += flow["response_packets" if outbound else "origin_packets"] or 0
            if outbound:
                row["times"].append(flow["start_time"])
                add_initiated_evidence(row, flow, confirmed)
            else:
                for protocol in {item["protocol"] for item in confirmed["originator"]}:
                    measurements[f"received_{protocol}"] += 1
                if not row["references"]:
                    row["references"].extend(references(flow, confirmed["responder"] or [{}]))
    for row in rows.values():
        features = row["features"]
        times = sorted(row.pop("times"))
        features["peer_count"] = len(row.pop("peers"))
        features["median_initiation_interval"] = round(median(
            [after - before for before, after in zip(times, times[1:])]), 3) if len(times) > 1 else 0
        features["has_repeated_initiations"] = int(len(times) > 1)
    return list(rows.values())


def add_initiated_evidence(row, flow, confirmed):
    origin, reply = confirmed["originator"], confirmed["responder"]
    protocols = {item["protocol"] for item in origin if item["protocol"] in ("HL7/MLLP", "DICOM")}
    row["protocols"].update(protocols)
    features = row["features"]
    for protocol in protocols:
        features[f"initiated_{protocol}"] += 1
    orus = [item for item in origin if item["protocol"] == "HL7/MLLP" and
            item["metadata"].get("message_type", "").split("^", 1)[0] == "ORU"]
    acks = [item for item in reply if item["protocol"] == "HL7/MLLP" and
            item["metadata"].get("message_type", "").split("^", 1)[0] == "ACK"]
    kinds = {kind for item in orus for kind in item["metadata"].get("measurement_kinds", [])
             if kind in HL7_CATEGORIES}
    features["oru_flows"] += bool(orus)
    features["oru_reply_flows"] += bool(orus and acks)
    classes = {DICOM_CATEGORIES[uid] for item in origin if item["protocol"] == "DICOM"
               for uid in item["metadata"].get("requested_abstract_syntax_uids", []) if uid in DICOM_CATEGORIES}
    dicom_reply = any(item["protocol"] == "DICOM" for item in reply)
    features["dicom_reply_flows"] += bool("DICOM" in protocols and dicom_reply)
    for kind in kinds:
        features[f"hl7_{kind}"] += 1
        for category in HL7_CATEGORIES[kind]:
            row["candidates"][category] += 1
            row["supported"][category] += bool(acks)
    for category in classes:
        features[f"dicom_storage_{category}"] += 1
        row["candidates"][category] += 1
        row["supported"][category] += dicom_reply
    if protocols:
        row["references"].extend(references(flow, [*origin, *reply]))
    elif not row["references"]:
        row["references"].extend(references(flow, [{}]))


def rule(row):
    if row["presence"] != "observed_transmitting" or not row["candidates"]:
        return UNKNOWN, "insufficient_category_evidence"
    if len(row["protocols"]) > 1 or len(row["candidates"]) > 1:
        if set(row["candidates"]) == {"bedside_monitor", "ecg_monitor"} and len(row["protocols"]) == 1:
            return UNKNOWN, "shared_heart_rate_evidence"
        return UNKNOWN, "conflicting_category_evidence"
    category = next(iter(row["candidates"]))
    if row["supported"][category] < MIN_EXCHANGES:
        return UNKNOWN, "fewer_than_two_bidirectional_exchanges"
    return category, "repeated_category_specific_exchanges"


def baseline(row):
    if len(row["protocols"]) == 1:
        return UNKNOWN, "protocol_group_only"
    return UNKNOWN, "ambiguous_protocol_group" if row["protocols"] else "no_attributed_protocol"
