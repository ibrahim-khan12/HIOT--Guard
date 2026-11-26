"""Read-only, revision-bound Module 4 result attachment; never registry facts."""
from contextlib import nullcontext
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sqlite3
import subprocess
from tempfile import TemporaryDirectory
from threading import Event, Lock, Thread


ASSESSMENT_SCOPE = "observed_workflow; physical_device_unverified"
HANDOFF_SCHEMA = "hiot.module4.endpoint-context.v1"
CAPTURE_LIMIT = 32 * 1024 * 1024
MAX_CAPTURES = 16


def inventory_version(db, source, scope):
    row = db.execute("SELECT revision,digest FROM sync WHERE source=? AND scope=?", (source, scope)).fetchone()
    return tuple(row) if row else None


def current_assessment(row):
    return {**row, "state": "current", "assessment_scope": ASSESSMENT_SCOPE}


class Classification:
    def __init__(self, path):
        path = Path(path)
        if path.stat().st_size > 16*1024*1024:
            raise ValueError("Classification projection exceeds 16 MiB")
        self.data = json.loads(path.read_text(encoding="utf-8"))
        if self.data.get("schema_version") != "hiot.classification.projection.v1":
            raise ValueError("Unsupported classification projection")
        for key in ("source_id", "scope", "inventory_revision", "inventory_digest", "capture_sha256", "records"):
            if key not in self.data:
                raise ValueError("Missing classification provenance: " + key)
        self.rows = {}
        for row in self.data["records"]:
            endpoint = row["endpoint"]
            if endpoint in self.rows:
                raise ValueError("Duplicate endpoint in classification projection")
            if row.get("schema_version") != "hiot.workflow-evidence.v2.0" or row.get("category") != "unknown":
                raise ValueError("Only the reviewed conservative workflow projection is supported")
            if not isinstance(row.get("evidence"), list) or not isinstance(row.get("workflows"), list):
                raise ValueError("Missing workflow evidence")
            self.rows[endpoint] = row

    def for_asset(self, store, asset, db=None):
        data = self.data
        if (asset["source_id"], asset["scope"]) != (data["source_id"], data["scope"]):
            return None
        row = self.rows.get(asset["ip"])
        if row is None:
            return None
        with (nullcontext(db) if db is not None else store.connect()) as reader:
            if inventory_version(reader, data["source_id"], data["scope"]) != (data["inventory_revision"], data["inventory_digest"]):
                return {"state": "stale", "reason": "inventory_changed_since_classification"}
            hashes = {json.loads(r[0]).get("sha256") for r in reader.execute("SELECT data FROM captures WHERE source=? AND scope=?", (data["source_id"], data["scope"]))}
        if data["capture_sha256"] not in hashes or any(e.get("capture_sha256") != data["capture_sha256"] for e in row["evidence"]):
            return {"state": "unverified", "reason": "capture_provenance_mismatch"}
        return current_assessment(row)


def handoff(asset, version):
    """Stable Module 4 context for a downstream detector, without registry fields."""
    assessment = asset.get("classification") or {"state": "unavailable", "reason": "assessment_unavailable"}
    state = assessment["state"]
    context = {
        "schema_version": HANDOFF_SCHEMA,
        "asset_id": asset["asset_id"],
        "source_id": asset["source_id"],
        "scope": asset["scope"],
        "endpoint": asset["ip"],
        "inventory_revision": version[0] if version else None,
        "inventory_digest": version[1] if version else None,
        "assessment_state": state,
        "reason": assessment.get("reason", "assessment_reason_unavailable"),
        "category": None,
        "workflows": [],
        "evidence": [],
    }
    if state == "current":
        for key in ("assessment_scope", "category", "workflows", "evidence", "method", "model_score",
                    "window_seconds", "observed_seconds", "capture_id", "capture_sha256"):
            if key in assessment:
                context[key] = assessment[key]
        context["assessment_version"] = assessment["schema_version"]
    return context


class LiveClassification:
    """Refresh one scope away from the HTTP and inventory synchronization threads."""

    def __init__(self, store, scope, capture_root, tshark, window=120, interval=5):
        from module4.evidence_v2 import analyze, packets

        self.store = store
        self.scope = scope
        self.capture_root = Path(capture_root).resolve(strict=True)
        if not self.capture_root.is_dir():
            raise ValueError("Assessment capture root must be a directory")
        self.tshark = tshark
        self.window = window
        self.interval = interval
        self.analyze = analyze
        self.packets = packets
        self.lock = Lock()
        self.stop_event = Event()
        self.thread = None
        self.latest = None

    def for_asset(self, store, asset, db=None):
        if asset["scope"] != self.scope or not asset["current"] or asset["address_kind"] != "unicast_address":
            return None
        with (nullcontext(db) if db is not None else store.connect()) as reader:
            version = inventory_version(reader, asset["source_id"], self.scope)
        with self.lock:
            current = self.latest
        if current is None or current[:2] != (asset["source_id"], version):
            return {"state": "pending", "reason": "awaiting_current_assessment"}
        return current[2].get(asset["ip"], {"state": "unavailable", "reason": "no_verified_capture_for_endpoint"})

    def load_packets(self, record):
        from module2.pcap import complete_pcap

        digest = record.get("sha256", "")
        if record.get("raw_retained") is not True or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            return []
        location = record.get("raw_capture")
        if not isinstance(location, str) or not Path(location).is_absolute():
            return []
        path = Path(location).resolve(strict=True)
        if not path.is_relative_to(self.capture_root) or not path.is_file():
            return []
        with path.open("rb") as stream:
            data = stream.read(CAPTURE_LIMIT + 1)
        if len(data) > CAPTURE_LIMIT or hashlib.sha256(data).hexdigest() != digest:
            return []
        if len(complete_pcap(data)[0]) != len(data):
            return []
        # Decode the verified bytes. Module 2 can replace the original file during rotation.
        with TemporaryDirectory(prefix="hiot-assessment-") as folder:
            pinned = Path(folder) / "capture.pcap"
            pinned.write_bytes(data)
            return self.packets(pinned, self.tshark)

    def once(self):
        with self.store.connect() as db:
            db.execute("BEGIN")
            versions = db.execute("SELECT source,revision,digest FROM sync WHERE scope=?", (self.scope,)).fetchall()
            if len(versions) != 1:
                with self.lock:
                    self.latest = None
                return
            source, revision, digest = versions[0]
            version = (revision, digest)
            with self.lock:
                if self.latest is not None and self.latest[:2] == (source, version):
                    return
            captures = []
            for capture_id, data in db.execute("SELECT id,data FROM captures WHERE source=? AND scope=?", (source, self.scope)):
                record = json.loads(data)
                if record.get("raw_retained") is True:
                    captures.append((capture_id, record))
            ips = {row[0] for row in db.execute("SELECT ip FROM assets WHERE source=? AND scope=? AND active=1", (source, self.scope))}
            endpoints = {ip for ip in ips if ipaddress.ip_address(ip).version == 4 and not ipaddress.ip_address(ip).is_multicast}

        def last_observed(item):
            stamp = item[1].get("last_packet_time")
            return (stamp if type(stamp) in (int, float) else 0, item[0])

        rows = {}
        for capture_id, record in sorted(captures, key=last_observed, reverse=True)[:MAX_CAPTURES]:
            if not endpoints or self.stop_event.is_set():
                break
            try:
                items = self.load_packets(record)
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                continue  # Another retained view may still be usable.
            if not items:
                continue
            seen = {p[side] for p in items for side in ("src", "dst")}
            capture_end = max(p["time"] for p in items)
            for endpoint in sorted(endpoints & seen):
                row = self.analyze(items, endpoint, self.window, capture_end, record["sha256"])
                rows[endpoint] = current_assessment({**row, "capture_id": capture_id, "capture_sha256": record["sha256"]})
                endpoints.remove(endpoint)
        # The HTTP reader compares the revision again inside its inventory read snapshot.
        # Publish only complete results, and discard work that raced with a new snapshot.
        with self.store.connect() as db:
            if inventory_version(db, source, self.scope) == version and not self.stop_event.is_set():
                with self.lock:
                    self.latest = (source, version, rows)

    def start(self):
        def run():
            while not self.stop_event.is_set():
                try:
                    self.once()
                except (OSError, sqlite3.Error, ValueError):
                    with self.lock:
                        self.latest = None
                self.stop_event.wait(self.interval)

        self.thread = Thread(target=run, name="module4-live-assessment", daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=1)
