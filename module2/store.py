"""Transactional observations with deterministic canonical-flow selection."""
import json
from copy import deepcopy
from pathlib import Path
import sqlite3
import threading
import time
from contextlib import contextmanager

from . import SCHEMA_VERSION
from .parsing import identity


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self._cache, self._cache_revision = {}, -1
        with self.connect() as db:
            db.executescript('''
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS captures(id TEXT PRIMARY KEY, scope TEXT, source TEXT, updated REAL, data TEXT);
                CREATE TABLE IF NOT EXISTS observations(id TEXT PRIMARY KEY, capture_id TEXT, canonical_id TEXT,
                    correlation_key TEXT, start_time REAL, data TEXT);
                CREATE INDEX IF NOT EXISTS observation_correlation ON observations(correlation_key,start_time);
                CREATE INDEX IF NOT EXISTS observation_capture_canonical ON observations(capture_id,canonical_id);
                CREATE INDEX IF NOT EXISTS observation_canonical ON observations(canonical_id);
                CREATE INDEX IF NOT EXISTS capture_scope ON captures(scope);
                CREATE TABLE IF NOT EXISTS flow_revision(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL);
                INSERT OR IGNORE INTO flow_revision VALUES(1,0);
                CREATE TABLE IF NOT EXISTS issues(id TEXT PRIMARY KEY,capture_id TEXT,data TEXT);
                CREATE TABLE IF NOT EXISTS health(source TEXT PRIMARY KEY,data TEXT);
                CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,data TEXT);
            ''')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        try:
            with db:
                yield db
        finally:
            db.close()

    def ingest(self, capture, flows, issues):
        with self.lock, self.connect() as db:
            db.execute("INSERT OR REPLACE INTO captures VALUES(?,?,?,?,?)",
                       (capture["capture_id"], capture["scope"], capture["observation_source"], time.time(), json.dumps(capture)))
            for flow in flows:
                canonical = flow["observation_id"]
                if flow["correlation_key"]:
                    found = db.execute("SELECT canonical_id FROM observations WHERE correlation_key=? AND ABS(start_time-?)<=1 ORDER BY start_time,id LIMIT 1",
                                       (flow["correlation_key"], flow["start_time"])).fetchone()
                    if found:
                        canonical = found[0]
                db.execute("INSERT OR REPLACE INTO observations VALUES(?,?,?,?,?,?)",
                           (flow["observation_id"], flow["capture_id"], canonical, flow["correlation_key"], flow["start_time"], json.dumps(flow)))
            current = {flow["observation_id"] for flow in flows}
            previous = db.execute("SELECT id FROM observations WHERE capture_id=?", (capture["capture_id"],)).fetchall()
            db.executemany("DELETE FROM observations WHERE id=?", ((row[0],) for row in previous if row[0] not in current))
            # A growing snapshot may resolve a previous incomplete-message warning.
            db.execute("DELETE FROM issues WHERE capture_id=?", (capture["capture_id"],))
            for issue in issues:
                db.execute("INSERT OR REPLACE INTO issues VALUES(?,?,?)",
                           (identity(capture["capture_id"], issue), capture["capture_id"], json.dumps(issue)))
            db.execute("UPDATE flow_revision SET version=version+1 WHERE id=1")

    def health(self, source, **values):
        with self.lock, self.connect() as db:
            prior = db.execute("SELECT data FROM health WHERE source=?", (source,)).fetchone()
            data = json.loads(prior[0]) if prior else {"source": source}
            data.update(values, updated=time.time())
            db.execute("INSERT OR REPLACE INTO health VALUES(?,?)", (source, json.dumps(data)))

    def setting(self, key, value=None):
        with self.lock, self.connect() as db:
            if value is not None:
                db.execute("INSERT OR REPLACE INTO settings VALUES(?,?)", (key, json.dumps(value)))
            row = db.execute("SELECT data FROM settings WHERE key=?", (key,)).fetchone()
            return json.loads(row[0]) if row else None

    def _canonical_records(self, scope):
        with self.connect() as db:
            db.execute("BEGIN")
            revision = db.execute("SELECT version FROM flow_revision WHERE id=1").fetchone()[0]
            with self.lock:
                if revision == self._cache_revision and scope in self._cache:
                    return self._cache[scope]
            if scope is None:
                rows = db.execute("SELECT canonical_id,data FROM observations").fetchall()
            else:
                rows = db.execute("SELECT canonical_id,data FROM observations WHERE capture_id IN (SELECT id FROM captures WHERE scope=?)", (scope,)).fetchall()
        groups = {}
        for key, raw in rows:
            observation = json.loads(raw)
            if scope is None or observation["scope"] == scope:
                groups.setdefault(key, []).append(observation)
        result = []
        for key, observations in groups.items():
            def quality(flow):
                return (flow["missed_bytes"] == 0, flow["connection_state"] == "SF",
                        flow["origin_packets"] + flow["response_packets"], flow["observation_source"])
            record = dict(max(observations, key=quality))
            record.update(flow_id=key, observation_count=len(observations),
                          observation_ids=sorted(f["observation_id"] for f in observations),
                          capture_ids=sorted({f["capture_id"] for f in observations}),
                          observation_sources=sorted({f["observation_source"] for f in observations}),
                          evidence=[e for f in observations for e in f["evidence"]],
                          byte_count_policy="canonical observation; never sum overlapping links")
            # Keep cached development observations consistent with the public v1 contract.
            if record["transport"] not in ("tcp", "udp"):
                record["source_port"] = record["destination_port"] = None
            medical_port = record["transport"] == "tcp" and bool({record["source_port"], record["destination_port"]} & {2575, 11112})
            record["protocol_status"] = "confirmed" if record["evidence"] else "unconfirmed" if medical_port else "not_identified"
            result.append(record)
        result.sort(key=lambda r: (r["start_time"], r["flow_id"]), reverse=True)
        with self.lock:
            if revision >= self._cache_revision:
                if revision != self._cache_revision:
                    self._cache.clear()
                    self._cache_revision = revision
                self._cache[scope] = result
                if len(self._cache) > 2:
                    del self._cache[next(iter(self._cache))]
        return result

    def flows(self, query="", protocol="", limit=1000, scope=None, transport=None):
        if limit <= 0:
            return []
        result = []
        for record in self._canonical_records(scope):
            if transport and record["transport"] != transport:
                continue
            if query and query.lower() not in json.dumps({k: record[k] for k in ("source_ip", "source_port", "destination_ip", "destination_port", "observation_sources")}).lower():
                continue
            if protocol and not any(e["protocol"] == protocol for e in record["evidence"]):
                continue
            result.append(record)
            if len(result) >= limit:
                break
        return deepcopy(result)

    def status(self, scope=None):
        with self.connect() as db:
            captures = [json.loads(r[0]) for r in db.execute("SELECT data FROM captures ORDER BY updated DESC")]
            health = [json.loads(r[0]) for r in db.execute("SELECT data FROM health ORDER BY source")]
            issues = [{"capture_id": r[0], **json.loads(r[1])} for r in db.execute("SELECT capture_id,data FROM issues")]
            observations = db.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
            canonical = db.execute("SELECT COUNT(DISTINCT canonical_id) FROM observations").fetchone()[0]
        scopes = sorted({c["scope"] for c in captures})
        if scope is not None:
            captures = [c for c in captures if c["scope"] == scope]
            ids = {c["capture_id"] for c in captures}
            issues = [i for i in issues if i["capture_id"] in ids]
            with self.connect() as db:
                counts = db.execute("SELECT COUNT(*),COUNT(DISTINCT canonical_id) FROM observations WHERE capture_id IN (SELECT id FROM captures WHERE scope=?)", (scope,)).fetchone()
            observations, canonical = counts
        return {"schema_version": SCHEMA_VERSION, "scopes": scopes, "captures": captures, "health": health, "issues": issues,
                "observations": observations, "canonical_flows": canonical,
                "overlapping_observations": observations-canonical}

    def export(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="\n") as out:
            for record in self.flows(limit=2**31):
                out.write(json.dumps(record, sort_keys=True) + "\n")

    def summary(self, scope=None, window=60):
        records = self._canonical_records(scope)
        end = max((r["start_time"] for r in records), default=0)
        endpoints = {}
        for r in records:
            if r["start_time"] < end-window:
                continue
            item = endpoints.setdefault(r["source_ip"], {"source_ip": r["source_ip"], "connections": 0, "peers": set(), "payload_bytes": 0})
            item["connections"] += 1
            item["peers"].add(r["destination_ip"])
            item["payload_bytes"] += r["origin_bytes"]+r["response_bytes"]
        for item in endpoints.values():
            item["unique_peers"] = len(item.pop("peers"))
        return {"schema_version": SCHEMA_VERSION, "window_seconds": window, "window_end": end,
                "window_basis": "connection start time; byte totals cover complete selected connection records, not a packet-rate estimate",
                "endpoints": sorted(endpoints.values(), key=lambda x: x["connections"], reverse=True)}

    def expire_raw(self, capture_id):
        with self.lock, self.connect() as db:
            row = db.execute("SELECT data FROM captures WHERE id=?", (capture_id,)).fetchone()
            if not row:
                return
            record = json.loads(row[0])
            raw = Path(record["raw_capture"]).resolve()
            root = self.path.parent.resolve() / "artifacts"
            if not raw.is_relative_to(root) or raw.name != "input.pcap":
                raise ValueError("Refusing to expire a capture outside this service's artifact directory")
            raw.unlink(missing_ok=True)
            record.update(raw_retained=False, retention_expired_at=time.time())
            db.execute("UPDATE captures SET data=? WHERE id=?", (json.dumps(record), capture_id))
            (raw.parent / "capture.json").write_text(json.dumps(record, indent=2))
