"""Transactional observations with deterministic canonical-flow selection."""
import json
from copy import deepcopy
from pathlib import Path
import sqlite3
import threading
import time
import hashlib
import os
from contextlib import contextmanager, closing

from . import SCHEMA_VERSION
from .parsing import identity


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self._cache, self._cache_revision = {}, -1
        self._writer = None
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
                CREATE INDEX IF NOT EXISTS issue_capture ON issues(capture_id);
                CREATE TABLE IF NOT EXISTS health(source TEXT PRIMARY KEY,data TEXT);
                CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,data TEXT);
                CREATE TABLE IF NOT EXISTS canonical(id TEXT PRIMARY KEY,scope TEXT,start_time REAL,
                    transport TEXT,search TEXT,protocols TEXT,data TEXT);
                CREATE INDEX IF NOT EXISTS canonical_scope_time ON canonical(scope,start_time DESC,id DESC);
                CREATE INDEX IF NOT EXISTS canonical_time ON canonical(start_time DESC,id DESC);
                CREATE INDEX IF NOT EXISTS observation_time ON observations(start_time DESC);
                CREATE TABLE IF NOT EXISTS health_events(id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT,at REAL,data TEXT);
                CREATE TABLE IF NOT EXISTS analysis_metrics(id INTEGER PRIMARY KEY AUTOINCREMENT,scope TEXT,data TEXT);
            ''')
            if not db.execute("SELECT 1 FROM settings WHERE key='canonical_sql_v1'").fetchone():
                self._refresh_canonical(db, (r[0] for r in db.execute("SELECT DISTINCT canonical_id FROM observations")))
                db.execute("INSERT INTO settings VALUES('canonical_sql_v1','true')")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.execute("PRAGMA cache_size=-4096")
        try:
            with db:
                yield db
        finally:
            db.close()

    @contextmanager
    def write(self):
        # One serialized writer keeps a bounded page cache and avoids checkpointing on
        # the last connection close for every packet-health update.
        with self.lock:
            if self._writer is None:
                self._writer = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
                self._writer.execute("PRAGMA cache_size=-65536")
            with self._writer:
                yield self._writer

    def close(self):
        with self.lock:
            if self._writer is not None:
                self._writer.close()
                self._writer = None

    def __del__(self):
        if getattr(self, "_writer", None) is not None:
            self._writer.close()

    def ingest(self, capture, flows, issues):
        began = time.monotonic()
        processing_start = capture.pop("_processing_start", None)
        with self.write() as db:
            previous = {r[0]: (r[1], r[2]) for r in db.execute("SELECT id,canonical_id,data FROM observations WHERE capture_id=?", (capture["capture_id"],))}
            affected = set()
            db.execute("INSERT OR REPLACE INTO captures VALUES(?,?,?,?,?)",
                       (capture["capture_id"], capture["scope"], capture["observation_source"], time.time(), json.dumps(capture)))
            for flow in flows:
                prior = previous.get(flow["observation_id"])
                if prior:
                    old = json.loads(prior[1])
                    stable_old = {k:v for k,v in old.items() if k != "zeek_uid"}
                    stable_new = {k:v for k,v in flow.items() if k != "zeek_uid"}
                    if stable_old == stable_new:
                        # Completed flows in rolling context only acquire a fresh random
                        # Zeek UID. Avoid rebuilding their unchanged evidence groups.
                        db.execute("UPDATE observations SET data=? WHERE id=?", (json.dumps(flow), flow["observation_id"]))
                        db.execute("UPDATE canonical SET data=json_set(data,'$.zeek_uid',?) WHERE id=? AND json_extract(data,'$.observation_id')=?",
                                   (flow["zeek_uid"], prior[0], flow["observation_id"]))
                        continue
                    affected.add(prior[0])
                canonical = flow["observation_id"]
                if flow["correlation_key"]:
                    found = db.execute("SELECT canonical_id FROM observations WHERE correlation_key=? AND ABS(start_time-?)<=1 ORDER BY start_time,id LIMIT 1",
                                       (flow["correlation_key"], flow["start_time"])).fetchone()
                    if found:
                        canonical = found[0]
                db.execute("INSERT OR REPLACE INTO observations VALUES(?,?,?,?,?,?)",
                           (flow["observation_id"], flow["capture_id"], canonical, flow["correlation_key"], flow["start_time"], json.dumps(flow)))
                affected.add(canonical)
            current = {flow["observation_id"] for flow in flows}
            removed = set(previous)-current
            affected.update(previous[key][0] for key in removed)
            db.executemany("DELETE FROM observations WHERE id=?", ((key,) for key in removed))
            # A growing snapshot may resolve a previous incomplete-message warning.
            db.execute("DELETE FROM issues WHERE capture_id=?", (capture["capture_id"],))
            for issue in issues:
                db.execute("INSERT OR REPLACE INTO issues VALUES(?,?,?)",
                           (identity(capture["capture_id"], issue), capture["capture_id"], json.dumps(issue)))
            db.execute("UPDATE flow_revision SET version=version+1 WHERE id=1")
            self._refresh_canonical(db, affected)
            if "processed_at" in capture:
                now = time.time()
                capture["duration_seconds"] = (time.monotonic()-processing_start if processing_start is not None
                                               else capture.get("duration_seconds", 0)+time.monotonic()-began)
                capture["processed_at"] = now
                capture.setdefault("stages", {})["persist_seconds"] = round(time.monotonic()-began, 4)
                db.execute("UPDATE captures SET data=?,updated=? WHERE id=?", (json.dumps(capture), now, capture["capture_id"]))
            if capture.get("last_packet_time") is not None:
                metric = {"capture_id": capture["capture_id"], "source": capture["observation_source"],
                          "scope": capture["scope"], "at": capture["processed_at"], "frames": capture["frames"],
                          "last_packet_to_record_seconds": max(0, capture["processed_at"]-capture["last_packet_time"]),
                          "first_packet_to_record_seconds": max(0, capture["processed_at"]-capture["first_packet_time"]),
                          "analysis_seconds": capture.get("analysis_seconds"), "sha256": capture["sha256"]}
                db.execute("INSERT INTO analysis_metrics(scope,data) VALUES(?,?)", (capture["scope"], json.dumps(metric)))
                db.execute("DELETE FROM analysis_metrics WHERE id <= (SELECT COALESCE(MAX(id),0)-5000 FROM analysis_metrics)")

    def health(self, source, **values):
        with self.write() as db:
            prior = db.execute("SELECT data FROM health WHERE source=?", (source,)).fetchone()
            data = json.loads(prior[0]) if prior else {"source": source}
            signature = lambda item: tuple(item.get(k) for k in ("state", "error", "analysis_error"))
            before = signature(data)
            data.update(values, updated=time.time())
            db.execute("INSERT OR REPLACE INTO health VALUES(?,?)", (source, json.dumps(data)))
            if not prior or signature(data) != before:
                db.execute("INSERT INTO health_events(source,at,data) VALUES(?,?,?)", (source, time.time(), json.dumps(data)))
                db.execute("DELETE FROM health_events WHERE id <= (SELECT COALESCE(MAX(id),0)-1000 FROM health_events)")

    def setting(self, key, value=None):
        with self.write() if value is not None else self.connect() as db:
            if value is not None:
                db.execute("INSERT OR REPLACE INTO settings VALUES(?,?)", (key, json.dumps(value)))
            row = db.execute("SELECT data FROM settings WHERE key=?", (key,)).fetchone()
            return json.loads(row[0]) if row else None

    def _refresh_canonical(self, db, keys):
        for key in keys:
            observations = [json.loads(row[0]) for row in db.execute("SELECT data FROM observations WHERE canonical_id=?", (key,))]
            if not observations:
                db.execute("DELETE FROM canonical WHERE id=?", (key,))
                continue
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
            search = json.dumps({k: record[k] for k in ("source_ip", "source_port", "destination_ip", "destination_port", "observation_sources")}).lower()
            protocols = json.dumps(sorted({e["protocol"] for e in record["evidence"]}))
            db.execute("INSERT OR REPLACE INTO canonical VALUES(?,?,?,?,?,?,?)",
                       (key, record["scope"], record["start_time"], record["transport"], search, protocols, json.dumps(record)))

    def iter_flows(self, query="", protocol="", scope=None, transport=None, limit=None, offset=0, since=None, before=None):
        clauses, args = [], []
        for column, value in (("scope", scope), ("transport", transport)):
            if value is not None:
                clauses.append(column+"=?")
                args.append(value)
        if query:
            clauses.append("instr(search,?)>0")
            args.append(query.lower())
        if protocol:
            clauses.append("EXISTS(SELECT 1 FROM json_each(canonical.protocols) WHERE value=?)")
            args.append(protocol)
        if since is not None:
            clauses.append("start_time>=?")
            args.append(since)
        if before is not None:
            clauses.append("(start_time<? OR (start_time=? AND id<?))")
            args.extend((before[0], before[0], before[1]))
        sql = "SELECT data FROM canonical" + (" WHERE " + " AND ".join(clauses) if clauses else "")
        sql += " ORDER BY start_time DESC,id DESC LIMIT ? OFFSET ?"
        args.extend((-1 if limit is None else limit, offset))
        with self.connect() as db:
            db.execute("BEGIN")
            for row in db.execute(sql, args):
                yield json.loads(row[0])

    def flows(self, query="", protocol="", limit=1000, scope=None, transport=None, offset=0, before=None):
        if limit <= 0:
            return []
        return list(self.iter_flows(query, protocol, scope, transport, limit, offset, before=before))

    def status(self, scope=None, limit=None, offset=0, issue_limit=None, source=None):
        with self.connect() as db:
            clauses, args = [], []
            if scope is not None:
                clauses.append("scope=?")
                args.append(scope)
            if source:
                clauses.append("source=?")
                args.append(source)
            where = " WHERE " + " AND ".join(clauses) if clauses else ""
            capture_count = db.execute("SELECT COUNT(*) FROM captures"+where, args).fetchone()[0]
            captures = [json.loads(r[0]) for r in db.execute("SELECT data FROM captures"+where+" ORDER BY updated DESC,id DESC LIMIT ? OFFSET ?", (*args, -1 if limit is None else limit, offset))]
            health = [json.loads(r[0]) for r in db.execute("SELECT data FROM health ORDER BY source")]
            restriction = " WHERE capture_id IN (SELECT id FROM captures"+where+")" if clauses else ""
            issue_count = db.execute("SELECT COUNT(*) FROM issues"+restriction, args).fetchone()[0]
            issues = [{"capture_id": r[0], **json.loads(r[1])} for r in db.execute("SELECT capture_id,data FROM issues"+restriction+" ORDER BY rowid DESC LIMIT ?", (*args, -1 if issue_limit is None else issue_limit))]
            observations = db.execute("SELECT COUNT(*) FROM observations"+restriction, args).fetchone()[0]
            canonical = db.execute("SELECT COUNT(DISTINCT canonical_id) FROM observations"+restriction, args).fetchone()[0]
            unresolved = db.execute("SELECT COUNT(*) FROM observations"+(restriction+" AND " if restriction else " WHERE ")+"correlation_key IS NULL", args).fetchone()[0]
            scopes = [r[0] for r in db.execute("SELECT DISTINCT scope FROM captures ORDER BY scope")]
            sources = [r[0] for r in db.execute("SELECT DISTINCT source FROM captures"+(" WHERE scope=?" if scope is not None else ""), (scope,) if scope is not None else ())]
        return {"schema_version": SCHEMA_VERSION, "scopes": scopes, "captures": captures, "health": health, "issues": issues,
                "capture_count": capture_count, "capture_sources": sources, "issue_count": issue_count,
                "uncorrelated_observations": unresolved,
                "count_semantics": "Canonical records; unmatched observations are not proven unique sessions",
                "observations": observations, "canonical_flows": canonical,
                "overlapping_observations": observations-canonical}

    def export(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="\n") as out:
            for record in self.iter_flows():
                out.write(json.dumps(record, sort_keys=True) + "\n")

    def summary(self, scope=None, window=60):
        with self.connect() as db:
            end = db.execute("SELECT MAX(start_time) FROM canonical"+(" WHERE scope=?" if scope is not None else ""), (scope,) if scope is not None else ()).fetchone()[0] or 0
        endpoints = {}
        for r in self.iter_flows(scope=scope, since=end-window):
            item = endpoints.setdefault(r["source_ip"], {"source_ip": r["source_ip"], "connections": 0, "peers": set(), "payload_bytes": 0})
            item["connections"] += 1
            item["peers"].add(r["destination_ip"])
            item["payload_bytes"] += r["origin_bytes"]+r["response_bytes"]
        for item in endpoints.values():
            item["unique_peers"] = len(item.pop("peers"))
        return {"schema_version": SCHEMA_VERSION, "window_seconds": window, "window_end": end,
                "window_basis": "connection start time; byte totals cover complete selected connection records, not a packet-rate estimate",
                "endpoints": sorted(endpoints.values(), key=lambda x: x["connections"], reverse=True)}

    def capture(self, capture_id):
        with self.connect() as db:
            row = db.execute("SELECT data FROM captures WHERE id=?", (capture_id,)).fetchone()
            return json.loads(row[0]) if row else None

    def capture_watermarks(self, scope, source):
        with self.connect() as db:
            result = {}
            for key, raw in db.execute("SELECT id,data FROM captures WHERE scope=? AND source=?", (scope, source)):
                record = json.loads(raw)
                values = {key: record.get("spool_bytes", record.get("bytes", 0)), **record.get("context_watermarks", {})}
                for segment, size in values.items():
                    result[segment] = max(result.get(segment, 0), size)
            return result

    def health_records(self):
        with self.connect() as db:
            return [json.loads(r[0]) for r in db.execute("SELECT data FROM health ORDER BY source")]

    def events(self, limit=100):
        with self.connect() as db:
            return [{"id": r[0], "source": r[1], "at": r[2], **json.loads(r[3])}
                    for r in db.execute("SELECT id,source,at,data FROM health_events ORDER BY id DESC LIMIT ?", (min(1000, max(1, limit)),))]

    def metrics(self, scope=None, limit=100):
        with self.connect() as db:
            return [json.loads(r[0]) for r in db.execute("SELECT data FROM analysis_metrics"+
                    (" WHERE scope=?" if scope else "")+" ORDER BY id DESC LIMIT ?",
                    (scope, min(5000, max(1, limit))) if scope else (min(5000, max(1, limit)),))]

    def archive_history(self, before, archive_budget=1024*1024*1024):
        """Explicit maintenance: verified SQLite backup before pruning closed live scopes."""
        with self.lock:
            current = self.setting("live") or {}
            with self.connect() as db:
                original_revision = db.execute("SELECT version FROM flow_revision WHERE id=1").fetchone()[0]
                scopes = [r[0] for r in db.execute("SELECT scope FROM captures WHERE scope LIKE 'live-%' GROUP BY scope HAVING MAX(updated)<?", (before,))
                          if not (current.get("enabled") and r[0] == current.get("scope"))]
                if not scopes:
                    return {"archived_scopes": [], "backup": None}
                folder = self.path.parent / "archive" / "history"
                folder.mkdir(parents=True, exist_ok=True)
                used = sum(p.stat().st_size for p in folder.glob("*.sqlite3"))
                pages, page_size = db.execute("PRAGMA page_count").fetchone()[0], db.execute("PRAGMA page_size").fetchone()[0]
                if used + pages*page_size > archive_budget:
                    raise BufferError("Analytical archive budget reached; history preserved")
                backup = folder / f"history-{time.time_ns()}.sqlite3"
                temporary = backup.with_suffix(".partial")
                try:
                    with closing(sqlite3.connect(temporary)) as target:
                        db.backup(target)
                        if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                            raise ValueError("History backup integrity check failed")
                    os.replace(temporary, backup)
                    with backup.open("rb") as stream:
                        digest = hashlib.file_digest(stream, "sha256").hexdigest()
                    manifest = {"sha256": digest, "scopes": scopes, "created": time.time(), "pruned": False}
                    backup.with_suffix(".json").write_text(json.dumps(manifest, indent=2))
                    db.execute("BEGIN IMMEDIATE")
                    latest = db.execute("SELECT data FROM settings WHERE key='live'").fetchone()
                    latest = json.loads(latest[0]) if latest else {}
                    if db.execute("SELECT version FROM flow_revision WHERE id=1").fetchone()[0] != original_revision or (latest.get("enabled") and latest.get("scope") in scopes):
                        raise RuntimeError("History changed during backup; no records pruned. Stop all writers and retry maintenance.")
                    for scope in scopes:
                        ids = "SELECT id FROM captures WHERE scope=?"
                        db.execute("DELETE FROM observations WHERE capture_id IN ("+ids+")", (scope,))
                        db.execute("DELETE FROM issues WHERE capture_id IN ("+ids+")", (scope,))
                        db.execute("DELETE FROM canonical WHERE scope=?", (scope,))
                        db.execute("DELETE FROM captures WHERE scope=?", (scope,))
                    db.execute("UPDATE flow_revision SET version=version+1 WHERE id=1")
                finally:
                    temporary.unlink(missing_ok=True)
            # Reclaim pages during operator-requested maintenance, outside the write transaction.
            manifest["pruned"] = True
            backup.with_suffix(".json").write_text(json.dumps(manifest, indent=2))
            with self.connect() as db:
                db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                db.execute("VACUUM")
            return {"archived_scopes": scopes, "backup": str(backup), "sha256": digest}

    def expire_raw(self, capture_id):
        with self.write() as db:
            row = db.execute("SELECT data FROM captures WHERE id=?", (capture_id,)).fetchone()
            if not row:
                return
            record = json.loads(row[0])
            raw = Path(record["raw_capture"]).resolve()
            root = self.path.parent.resolve() / "artifacts"
            archive = self.path.parent.resolve() / "archive" / "raw"
            if not (raw.is_relative_to(root) or raw.is_relative_to(archive)) or raw.name != "input.pcap":
                raise ValueError("Refusing to expire a capture outside this service's artifact directory")
            raw.unlink(missing_ok=True)
            record.update(raw_retained=False, retention_expired_at=time.time())
            db.execute("UPDATE captures SET data=? WHERE id=?", (json.dumps(record), capture_id))
            (raw.parent / "capture.json").write_text(json.dumps(record, indent=2))
