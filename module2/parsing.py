"""Normalize Zeek records and packet-backed DICOM/HL7 evidence."""
from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
from pathlib import Path
from collections import defaultdict

from . import SCHEMA_VERSION
from .sensor import FIELDS


def identity(*parts):
    return hashlib.sha256(json.dumps(parts, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def packet_rows(path):
    issues, rows = [], []
    with Path(path).open(encoding="utf-8") as source:
        for number, values in enumerate(csv.reader(source, delimiter="\t", quotechar='"'), 1):
            if len(values) != len(FIELDS):
                issues.append({"kind": "malformed_packet_row", "line": number})
                continue
            row = dict(zip(FIELDS, values))
            try:
                src, dst = row["ip.src"] or row["ipv6.src"], row["ip.dst"] or row["ipv6.dst"]
                if not src or not dst:
                    continue
                ipaddress.ip_address(src)
                ipaddress.ip_address(dst)
                row.update(source_ip=src, destination_ip=dst, timestamp=float(row["frame.time_epoch"]),
                           frame=int(row["frame.number"]),
                           source_port=int(row["tcp.srcport"] or row["udp.srcport"] or 0),
                           destination_port=int(row["tcp.dstport"] or row["udp.dstport"] or 0))
                if int(row["frame.cap_len"]) < int(row["frame.len"]):
                    issues.append({"kind": "truncated_packet", "frame": row["frame"]})
                rows.append(row)
            except (ValueError, KeyError):
                issues.append({"kind": "invalid_packet_fields", "line": number})
    return rows, issues


def endpoints(row):
    return (row["source_ip"], row["source_port"], row["destination_ip"], row["destination_port"])


def reassemble(segments, limit=1024 * 1024):
    """Rebuild a single TCP direction; never join bytes across a gap."""
    if not segments:
        return [], []
    anchor = segments[0][0]
    ordered = sorted((((seq - anchor + 2**31) % 2**32 - 2**31, data, frame)
                      for seq, data, frame in segments), key=lambda x: (x[0], x[2]))
    if sum(len(data) for _, data, _ in ordered) > limit:
        return [], [{"kind": "reassembly_limit", "limit_bytes": limit}]
    chunks, issues, buffer, start, first_frame = [], [], bytearray(), None, None
    for seq, data, frame in ordered:
        if start is None:
            start, first_frame = seq, frame
        end = start + len(buffer)
        if seq > end:
            chunks.append((bytes(buffer), first_frame))
            issues.append({"kind": "tcp_gap", "frame": frame, "missing_bytes": seq - end})
            buffer, start, first_frame = bytearray(), seq, frame
            end = seq
        overlap = max(0, end - seq)
        if overlap:
            existing = bytes(buffer[seq-start:seq-start+min(overlap, len(data))])
            if existing != data[:len(existing)]:
                issues.append({"kind": "conflicting_tcp_overlap", "frame": frame})
                # A conflicting stream has no trustworthy medical-message interpretation.
                return [], issues
        buffer.extend(data[overlap:])
    chunks.append((bytes(buffer), first_frame))
    return chunks, issues


def hl7_messages(chunks):
    messages, issues = [], []
    for data, frame in chunks:
        offset = 0
        while True:
            begin = data.find(b"\x0b", offset)
            if begin < 0:
                break
            end = data.find(b"\x1c\x0d", begin + 1)
            if end < 0:
                issues.append({"kind": "incomplete_mllp_message", "frame": frame})
                break
            msh = data[begin+1:end].split(b"\r", 1)[0].split(b"|")
            if len(msh) < 12 or msh[0] != b"MSH":
                issues.append({"kind": "malformed_hl7_msh", "frame": frame})
            else:
                try:
                    # Deliberately omit PID, OBX and clinical observation values.
                    messages.append({"frame": frame, "protocol": "HL7/MLLP", "parser_status": "confirmed",
                                     "metadata": {"sender": msh[2].decode("ascii")[:80],
                                                  "message_type": msh[8].decode("ascii")[:40]},
                                     "message_offset": begin})
                except UnicodeDecodeError:
                    issues.append({"kind": "non_ascii_hl7_metadata", "frame": frame})
            offset = end + 2
    return messages, issues


def normalize(folder, capture_id, source_id, scope):
    folder = Path(folder)
    rows, issues = packet_rows(folder / "packets.tsv")
    syns, stream_rows = defaultdict(list), defaultdict(list)
    for row in rows:
        if row["tcp.stream"]:
            stream_rows[row["tcp.stream"]].append(row)
        if row["tcp.flags.syn"].lower() in ("1", "true") and row["tcp.flags.ack"].lower() in ("0", "false"):
            syns[endpoints(row)].append(row)
    flows = []
    log = folder / "conn.log"
    for number, line in enumerate(log.read_text().splitlines() if log.exists() else [], 1):
        if not line.strip():
            continue
        try:
            conn = json.loads(line)
            origin = (conn["id.orig_h"], int(conn["id.orig_p"]), conn["id.resp_h"], int(conn["id.resp_p"]))
            ts = float(conn["ts"])
            matches = [r for r in syns[origin] if abs(r["timestamp"] - ts) < 0.25] if conn["proto"] == "tcp" else []
            syn = min(matches, key=lambda r: abs(r["timestamp"] - ts)) if matches else None
            identifier = identity(capture_id, *origin, conn["proto"], ts)
            flows.append({"schema_version": SCHEMA_VERSION, "observation_id": identifier,
                          "capture_id": capture_id, "observation_source": source_id, "scope": scope,
                          "start_time": ts, "source_ip": origin[0], "source_port": origin[1] if conn["proto"] in ("tcp", "udp") else None,
                          "destination_ip": origin[2], "destination_port": origin[3] if conn["proto"] in ("tcp", "udp") else None, "transport": conn["proto"],
                          "service": conn.get("service"), "connection_state": conn.get("conn_state", "unknown"),
                          "duration": conn.get("duration"), "origin_packets": conn.get("orig_pkts", 0),
                          "response_packets": conn.get("resp_pkts", 0), "origin_bytes": conn.get("orig_bytes", 0),
                          "response_bytes": conn.get("resp_bytes", 0), "missed_bytes": conn.get("missed_bytes", 0),
                          "zeek_uid": conn["uid"], "tcp_stream": syn["tcp.stream"] if syn else None,
                          "correlation_key": identity(scope, *origin, conn["proto"], syn["tcp.seq_raw"]) if syn else None,
                          "correlation_status": "syn_fingerprint" if syn else "observation_only",
                          "evidence": []})
        except (ValueError, KeyError, TypeError):
            issues.append({"kind": "malformed_zeek_record", "line": number})

    def find_flow(row):
        key = endpoints(row)
        reverse = (key[2], key[3], key[0], key[1])
        candidates = [f for f in flows if (f["source_ip"], f["source_port"], f["destination_ip"], f["destination_port"]) in (key, reverse)
                      and f["start_time"] - .25 <= row["timestamp"] <= f["start_time"] + (f["duration"] or 0) + 2]
        return min(candidates, key=lambda f: abs(f["start_time"] - row["timestamp"])) if candidates else None

    def add(flow, row, item):
        item.update(timestamp=row["timestamp"], capture_id=capture_id, observation_id=flow["observation_id"])
        item["evidence_id"] = identity(capture_id, flow["observation_id"], item["frame"], item["protocol"], item.get("message_offset"), item["metadata"])
        flow["evidence"].append(item)

    for row in rows:
        calling, called = row["dicom.assoc.ae.calling"].strip(), row["dicom.assoc.ae.called"].strip()
        if calling or called:
            flow = find_flow(row)
            if not calling or not called:
                issues.append({"kind": "incomplete_dicom_association", "frame": row["frame"]})
            elif flow:
                add(flow, row, {"frame": row["frame"], "protocol": "DICOM", "parser_status": "confirmed",
                                "metadata": {"calling_ae": calling, "called_ae": called,
                                             "abstract_syntax": row["dicom.pctx.abss.syntax"]}})

    for stream, packets in stream_rows.items():
        directions = defaultdict(list)
        for row in packets:
            if not row["tcp.payload"]:
                continue
            try:
                payload = bytes.fromhex(row["tcp.payload"].replace(":", ""))
                directions[endpoints(row)].append((int(row["tcp.seq_raw"]), payload, row["frame"]))
            except ValueError:
                issues.append({"kind": "invalid_tcp_payload", "frame": row["frame"]})
        for direction, segments in directions.items():
            if 2575 not in (direction[1], direction[3]) and not any(b"MSH|" in data or data.startswith(b"\x0b") for _, data, _ in segments):
                continue
            chunks, stream_issues = reassemble(segments)
            messages, message_issues = hl7_messages(chunks)
            issues.extend({**issue, "tcp_stream": stream} for issue in stream_issues + message_issues)
            for item in messages:
                row = next(r for r in packets if r["frame"] == item["frame"])
                flow = find_flow(row)
                if flow:
                    add(flow, row, item)
    for flow in flows:
        medical_port = flow["transport"] == "tcp" and bool({flow["source_port"], flow["destination_port"]} & {2575, 11112})
        flow["protocol_status"] = "confirmed" if flow["evidence"] else "unconfirmed" if medical_port else "not_identified"
        if medical_port and not flow["evidence"] and flow["origin_bytes"]+flow["response_bytes"] > 0:
            issues.append({"kind": "unconfirmed_medical_protocol", "observation_id": flow["observation_id"],
                           "detail": "Service port carried bytes, but no validated DICOM association or HL7/MLLP metadata was found"})
    unique_syns = {(*endpoints(r), r["tcp.seq_raw"]) for packets in syns.values() for r in packets}
    return flows, issues, {"packet_rows": len(rows), "independent_unique_syns": len(unique_syns),
                           "reference_syn_sample": [list(item) for item in sorted(unique_syns)[:5]],
                           "zeek_flows": len(flows), "confirmed_protocol_events": sum(len(f["evidence"]) for f in flows)}
