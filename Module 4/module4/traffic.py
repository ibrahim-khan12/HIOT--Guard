"""Label-free endpoint traffic summaries from canonical Module 2 flows.

Bytes mean Zeek transport payload bytes, not captured Ethernet frame lengths.
The same extractor is used for hospital recordings and imported public PCAPs.
"""
from collections import defaultdict
from contextlib import closing
from copy import deepcopy
import json
import math
from pathlib import Path
import sqlite3
from statistics import mean, median, pstdev

from .classifier import endpoint_rows
from .experiment import load_json

VERSION = "canonical-endpoint-traffic-v1"


def canonical_flows(database, recording):
    """Read a consistent snapshot and verify it belongs to the supplied export."""
    with closing(sqlite3.connect(Path(database).resolve().as_uri() + "?mode=ro", uri=True)) as db:
        db.execute("BEGIN")
        flows = [json.loads(data) for (data,) in db.execute(
            "SELECT data FROM canonical WHERE scope=? ORDER BY start_time,id", (recording["scope"],))]
    expected = {flow["flow_id"]: flow for flow in recording["flows"]}
    if len(expected) != len(recording["flows"]) or len(flows) != len(expected):
        raise ValueError("Module 2 canonical flow set differs from Module 3 export")
    for flow in flows:
        previous = expected.get(flow["flow_id"])
        if previous is None or any(flow.get(key) != previous.get(key) for key in (
                "source_ip", "destination_ip", "start_time", "duration", "transport",
                "origin_packets", "response_packets")):
            raise ValueError("Module 2 and Module 3 canonical flows disagree")
    return flows


def number(value):
    if value is None:
        return 0.0
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError("Traffic measurements must be finite nonnegative numbers")
    return float(value)


def summary(features, prefix, values):
    for suffix, function in (("mean", mean), ("median", median), ("std", pstdev), ("max", max)):
        features[prefix + "_" + suffix] = float(function(values)) if values else 0.0


def traffic_features(recording, flows):
    """One feature row per endpoint per recording; identifiers only join records."""
    addresses = {asset["ip"] for asset in recording["assets"] if asset["address_kind"] == "unicast_address"}
    attached = defaultdict(list)
    seen = set()
    for flow in flows:
        if flow["flow_id"] in seen:
            raise ValueError("Duplicate canonical flow ID would double-count traffic")
        seen.add(flow["flow_id"])
        if flow["source_ip"] == flow["destination_ip"]:
            continue
        for own, peer, outbound in (("source_ip", "destination_ip", True),
                                    ("destination_ip", "source_ip", False)):
            if flow[own] in addresses:
                attached[flow[own]].append((flow, peer, outbound))
    result = {}
    for ip in sorted(addresses):
        features = defaultdict(float)
        times, endings, durations, initiation_times = [], [], [], []
        sent_sizes, received_sizes, flow_packets = [], [], []
        peers = set()
        for flow, peer, outbound in attached[ip]:
            peers.add(flow[peer])
            start = number(flow["start_time"])
            duration = number(flow.get("duration"))
            times.append(start)
            endings.append(start + duration)
            if outbound:
                initiation_times.append(start)
            if flow.get("duration") is not None:
                durations.append(duration)
            features["flow_count"] += 1
            features["initiated_flows" if outbound else "received_flows"] += 1
            transport = flow.get("transport")
            features["tcp_flows"] += transport == "tcp"
            features["udp_flows"] += transport == "udp"
            features["other_transport_flows"] += transport not in ("tcp", "udp")
            features["missing_duration_flows"] += flow.get("duration") is None
            origin_packets = number(flow.get("origin_packets"))
            response_packets = number(flow.get("response_packets"))
            sent = origin_packets if outbound else response_packets
            received = response_packets if outbound else origin_packets
            origin_bytes, response_bytes = (number(flow.get(key)) for key in ("origin_bytes", "response_bytes"))
            sent_bytes = origin_bytes if outbound else response_bytes
            received_bytes = response_bytes if outbound else origin_bytes
            features["packets_sent"] += sent
            features["packets_received"] += received
            features["payload_bytes_sent"] += sent_bytes
            features["payload_bytes_received"] += received_bytes
            features["missing_byte_counter_flows"] += any(flow.get(key) is None for key in (
                "origin_bytes", "response_bytes"))
            features["bidirectional_flows"] += sent > 0 and received > 0
            features["missed_payload_bytes"] += number(flow.get("missed_bytes"))
            sent_sizes.append(sent_bytes)
            received_sizes.append(received_bytes)
            flow_packets.append(sent + received)
        # Explicit zero-valued keys keep the schema identical on sparse captures.
        for key in ("flow_count", "initiated_flows", "received_flows", "tcp_flows", "udp_flows",
                    "other_transport_flows", "missing_duration_flows", "packets_sent", "packets_received",
                    "payload_bytes_sent", "payload_bytes_received", "missing_byte_counter_flows",
                    "bidirectional_flows", "missed_payload_bytes"):
            features[key] += 0.0
        features["peer_count"] = float(len(peers))
        span = max(endings) - min(times) if times else 0.0
        features["observed_span_seconds"] = span
        features["has_activity_span"] = float(span > 0)
        features["packets_per_observed_second"] = (
            (features["packets_sent"] + features["packets_received"]) / span if span else 0.0)
        features["payload_bytes_per_observed_second"] = (
            (features["payload_bytes_sent"] + features["payload_bytes_received"]) / span if span else 0.0)
        features["sent_payload_bytes_per_packet"] = (
            features["payload_bytes_sent"] / features["packets_sent"] if features["packets_sent"] else 0.0)
        features["received_payload_bytes_per_packet"] = (
            features["payload_bytes_received"] / features["packets_received"] if features["packets_received"] else 0.0)
        summary(features, "flow_duration_seconds", durations)
        summary(features, "sent_payload_bytes_per_flow", sent_sizes)
        summary(features, "received_payload_bytes_per_flow", received_sizes)
        summary(features, "packets_per_flow", flow_packets)
        initiation_times.sort()
        intervals = [after - before for before, after in zip(initiation_times, initiation_times[1:])]
        summary(features, "initiation_interval_seconds", intervals)
        features["has_initiation_intervals"] = float(bool(intervals))
        result[ip] = dict(sorted(features.items()))
    return result


def feature_rows(recording, flows):
    statistics = traffic_features(recording, flows)
    rows = endpoint_rows(recording)
    for row in rows:
        row["traffic_features"] = statistics[row["ip"]]
    return rows


def load_rows(recording_path, database=None):
    path = Path(recording_path)
    recording = load_json(path)
    database = database or path.parent / "analysis" / "monitoring.sqlite3"
    flows = canonical_flows(database, recording)
    return recording, flows, feature_rows(recording, flows)


def selected_features(row, family):
    protocol = {key: value for key, value in row["features"].items() if key.startswith(
        ("initiated_HL7", "initiated_DICOM", "received_HL7", "received_DICOM", "oru_", "dicom_", "hl7_"))}
    if family == "protocol_evidence":
        return protocol
    stats = {"traffic_" + key: value for key, value in row["traffic_features"].items()}
    if family == "statistics":
        return stats
    if family == "combined":
        return {**row["features"], **stats}
    raise ValueError(f"Unknown feature family {family}")


def renamed_inputs(recording, flows):
    """Change laboratory identifiers and absolute time without changing traffic."""
    record, copied = deepcopy(recording), deepcopy(flows)
    addresses = sorted({f[key] for f in flows for key in ("source_ip", "destination_ip")} |
                       {asset["ip"] for asset in record["assets"]})
    aliases = {ip: f"2001:db8::{index:x}" for index, ip in enumerate(addresses, 1)}
    record.update(scope="changed", source_id="changed")
    for index, asset in enumerate(record["assets"]):
        asset.update(ip=aliases[asset["ip"]], asset_id=f"changed-{index}", mac="changed",
                     configured={"role": "changed"})
    for collection in (record["flows"], copied):
        for index, flow in enumerate(collection):
            flow.update(source_ip=aliases[flow["source_ip"]], destination_ip=aliases[flow["destination_ip"]],
                        flow_id=f"changed-{index}", observation_source="changed")
            # An integer offset preserves measured timestamp differences exactly.
            flow["start_time"] += 1024
            for event in flow.get("evidence", []):
                event.setdefault("metadata", {}).update(sender="changed", calling_ae="changed", called_ae="changed")
    return record, copied
