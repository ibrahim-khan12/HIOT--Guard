"""Validated disk staging: never publish partial upstream snapshots."""
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
import sqlite3
import tempfile
from contextlib import contextmanager

from module2.discovery import SNAPSHOT_SCHEMA


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def identity(*parts):
    return hashlib.sha256(encode(parts).encode()).hexdigest()


def validate(flow):
    if flow.get("schema_version") != "hiot.monitoring.v1":
        raise ValueError("Unsupported monitoring schema")
    for key in ("flow_id", "scope", "source_ip", "destination_ip", "transport"):
        if not isinstance(flow.get(key), str) or not flow[key] or len(flow[key]) > 256:
            raise ValueError(f"Invalid {key}")
    for key in ("source_ip", "destination_ip"):
        flow[key] = str(ipaddress.ip_address(flow[key]))
    for key in ("start_time", "duration"):
        n = flow.get(key)
        if key == "duration" and n is None:
            continue
        if type(n) not in (float, int) or not math.isfinite(n) or n < 0:
            raise ValueError(f"Invalid {key}")
    for key in ("origin_packets", "response_packets"):
        n = flow.get(key)
        if n is not None and (type(n) is not int or n < 0):
            raise ValueError(f"Invalid {key}")
    for key in ("source_port", "destination_port"):
        n = flow.get(key)
        if flow["transport"] not in ("tcp", "udp"):
            if n is not None:
                raise ValueError("Non-port transport has a port")
        elif n is not None and (type(n) is not int or not 0 <= n <= 65535):
            raise ValueError("Invalid port")
    for key in ("evidence", "link_layer_evidence"):
        if not isinstance(flow.get(key, []), list):
            raise ValueError(f"Invalid {key}")
    for e in flow.get("evidence", []) + flow.get("link_layer_evidence", []):
        if not isinstance(e, dict) or not isinstance(e.get("capture_id"), str) or not isinstance(e.get("observation_id"), str):
            raise ValueError("Evidence missing provenance")
        if e["capture_id"] not in flow.get("capture_ids", [flow.get("capture_id")]) or e["observation_id"] not in flow.get("observation_ids", [flow.get("observation_id")]):
            raise ValueError("Evidence does not belong to flow provenance")
        if type(e.get("frame")) is not int or e["frame"] < 1:
            raise ValueError("Invalid evidence frame")
        if type(e.get("timestamp")) not in (int, float) or not math.isfinite(e["timestamp"]):
            raise ValueError("Invalid evidence timestamp")
        if "mac" in e and (not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", e["mac"]) or
                           e.get("ethernet_direction") not in ("source", "destination")):
            raise ValueError("Invalid MAC observation")
    for e in flow.get("evidence", []):
        if not isinstance(e.get("protocol"), str) or not isinstance(e.get("metadata", {}), dict):
            raise ValueError("Invalid protocol evidence")
    # Random Zeek UIDs do not constitute meaningful inventory changes.
    flow.pop("zeek_uid", None)
    return flow


@contextmanager
def stage(lines, source_id=None, scope=None, legacy=False):
    """Spool untrusted records to a temporary indexed DB, bounding Python memory."""
    with tempfile.TemporaryDirectory(prefix="hiot-discovery-") as folder:
        db = sqlite3.connect(str(Path(folder)/"stage.sqlite3"))
        try:
            db.executescript("CREATE TABLE flows(id TEXT PRIMARY KEY,hash TEXT,data TEXT); CREATE TABLE captures(id TEXT PRIMARY KEY,data TEXT);")
            header, complete, count, digest = None, None, 0, hashlib.sha256()
            for raw in lines:
                if isinstance(raw, str):
                    raw = raw.encode()
                if len(raw) > 8*1024*1024:
                    raise ValueError("Snapshot line exceeds 8 MiB")
                if not raw.strip():
                    continue
                item = json.loads(raw)
                if not isinstance(item, dict):
                    raise ValueError("Record must be an object")
                if legacy:
                    if item.get("scope") != scope:
                        continue
                    flow = validate(item)
                    data = encode(flow)
                    db.execute("INSERT INTO flows VALUES(?,?,?)", (flow["flow_id"], identity(flow), data))
                    digest.update(raw)
                    count += 1
                    continue
                if complete:
                    raise ValueError("Data after completion marker")
                kind = item.get("type")
                if header is None:
                    if kind != "header" or item.get("schema_version") != SNAPSHOT_SCHEMA:
                        raise ValueError("Missing/unsupported snapshot header")
                    header = item
                    if not header.get("source_id") or not header.get("scope") or type(header.get("revision")) is not int:
                        raise ValueError("Invalid snapshot header")
                    if source_id and header["source_id"] != source_id or scope and header["scope"] != scope:
                        raise ValueError("Snapshot source/scope changed")
                elif kind == "complete":
                    complete = item
                elif kind in ("flow", "capture"):
                    record = item["record"]
                    if record.get("scope") != header["scope"]:
                        raise ValueError("Mixed snapshot scopes")
                    digest.update(raw)
                    count += 1
                    if kind == "flow":
                        flow = validate(record)
                        db.execute("INSERT INTO flows VALUES(?,?,?)", (flow["flow_id"], identity(flow), encode(flow)))
                    else:
                        db.execute("INSERT INTO captures VALUES(?,?)", (record["capture_id"], encode(record)))
                else:
                    raise ValueError("Unexpected snapshot record")
            if legacy:
                if not source_id or not scope or count == 0:
                    raise ValueError("Legacy import requires explicit source, nonempty scope and matching records")
                header = {"source_id": source_id, "scope": scope, "revision": digest.hexdigest(), "mode": "imported_snapshot"}
            elif not complete or complete.get("records") != count or complete.get("sha256") != digest.hexdigest() or complete.get("revision") != header["revision"]:
                raise ValueError("Incomplete or corrupt snapshot")
            header["digest"] = digest.hexdigest()
            db.commit()
            yield db, header
        finally:
            db.close()
