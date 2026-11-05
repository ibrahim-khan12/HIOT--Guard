"""Transactional inventory projection of canonical monitoring observations."""
from contextlib import contextmanager
import json
import ipaddress
from pathlib import Path
import sqlite3
import threading
import time

from . import SCHEMA_VERSION
from .input import encode, identity


class Store:
    def __init__(self, path, registry=None, direct_links=None, activity_window=300):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.registry = registry or {}
        self.direct_links = direct_links or {}
        self.activity_window = activity_window
        with self.connect() as db:
            db.executescript('''
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS flows(source TEXT,scope TEXT,id TEXT,hash TEXT,src TEXT,dst TEXT,start REAL,end REAL,data TEXT,PRIMARY KEY(source,scope,id));
                CREATE INDEX IF NOT EXISTS flow_src ON flows(source,scope,src,start DESC);
                CREATE INDEX IF NOT EXISTS flow_dst ON flows(source,scope,dst,start DESC);
                CREATE INDEX IF NOT EXISTS flow_end ON flows(source,scope,end DESC);
                CREATE TABLE IF NOT EXISTS captures(source TEXT,scope TEXT,id TEXT,data TEXT,PRIMARY KEY(source,scope,id));
                CREATE TABLE IF NOT EXISTS assets(id TEXT PRIMARY KEY,source TEXT,scope TEXT,ip TEXT,presence TEXT,registered INTEGER,review INTEGER,active INTEGER,data TEXT);
                CREATE INDEX IF NOT EXISTS asset_scope ON assets(source,scope,active,ip);
                CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,asset_id TEXT,at REAL,kind TEXT,data TEXT);
                CREATE INDEX IF NOT EXISTS event_asset ON events(asset_id,id DESC);
                CREATE TABLE IF NOT EXISTS sync(source TEXT,scope TEXT,revision TEXT,digest TEXT,at REAL,mode TEXT,PRIMARY KEY(source,scope));
                CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,data TEXT);
            ''')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def setting(self, key, value=None):
        with self.lock, self.connect() as db:
            if value is not None:
                db.execute("INSERT OR REPLACE INTO settings VALUES(?,?)", (key, encode(value)))
            row = db.execute("SELECT data FROM settings WHERE key=?", (key,)).fetchone()
            return json.loads(row[0]) if row else None

    def apply(self, staged, header):
        began = time.monotonic()
        source, scope = header["source_id"], header["scope"]
        config = encode({"registry": self.registry, "direct_links": self.direct_links})
        with self.lock, self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            affected, changed, removed = set(), 0, 0
            old = {r["id"]: r for r in db.execute("SELECT id,hash,src,dst FROM flows WHERE source=? AND scope=?", (source, scope))}
            for row in staged.execute("SELECT id,hash,data FROM flows"):
                prior = old.pop(row[0], None)
                if prior and prior["hash"] == row[1]:
                    continue
                flow = json.loads(row[2])
                if prior:
                    affected.update((prior["src"], prior["dst"]))
                    previous_flow = json.loads(db.execute("SELECT data FROM flows WHERE source=? AND scope=? AND id=?", (source, scope, row[0])).fetchone()[0])
                    for endpoint in {prior["src"], prior["dst"], flow["source_ip"], flow["destination_ip"]}:
                        self._event(db, identity(source, scope, endpoint), "upstream_flow_updated", {"previous_flow": previous_flow, "current_flow": flow})
                affected.update((flow["source_ip"], flow["destination_ip"]))
                db.execute("INSERT OR REPLACE INTO flows VALUES(?,?,?,?,?,?,?,?,?)",
                           (source, scope, row[0], row[1], flow["source_ip"], flow["destination_ip"], flow["start_time"],
                            flow["start_time"]+(flow.get("duration") or 0), row[2]))
                changed += 1
            for key, prior in old.items():
                affected.update((prior["src"], prior["dst"]))
                previous_flow = json.loads(db.execute("SELECT data FROM flows WHERE source=? AND scope=? AND id=?", (source, scope, key)).fetchone()[0])
                for endpoint in {prior["src"], prior["dst"]}:
                    self._event(db, identity(source, scope, endpoint), "upstream_flow_withdrawn", {"previous_flow": previous_flow})
                db.execute("DELETE FROM flows WHERE source=? AND scope=? AND id=?", (source, scope, key))
                removed += 1
            config_key = "config:"+source+":"+scope
            prior_config = db.execute("SELECT data FROM settings WHERE key=?", (config_key,)).fetchone()
            if not prior_config or prior_config[0] != config:
                affected.update(r[0] for r in db.execute("SELECT ip FROM assets WHERE source=? AND scope=? AND active=1", (source, scope)))
                db.execute("INSERT OR REPLACE INTO settings VALUES(?,?)", (config_key, config))
            # Capture metadata changes update inspectability without inventing new discoveries.
            db.execute("DELETE FROM captures WHERE source=? AND scope=?", (source, scope))
            db.executemany("INSERT INTO captures VALUES(?,?,?,?)", ((source, scope, r[0], r[1]) for r in staged.execute("SELECT id,data FROM captures")))
            for ip in sorted(affected):
                self._project(db, source, scope, ip, bool(removed))
            db.execute("INSERT OR REPLACE INTO sync VALUES(?,?,?,?,?,?)", (source, scope, str(header["revision"]), header["digest"], time.time(), header.get("mode", "module2_snapshot")))
        return {"changed_flows": changed, "removed_flows": removed, "affected_endpoints": len(affected),
                "seconds": time.monotonic()-began, "source_id": source, "scope": scope}

    def _project(self, db, source, scope, ip, withdrawal):
        key = identity(source, scope, ip)
        previous = db.execute("SELECT data FROM assets WHERE id=?", (key,)).fetchone()
        prior = json.loads(previous[0]) if previous else None
        first, last, transmitting, target_only, unknown = None, None, False, False, False
        peers, ports_out, ports_in, transports, protocols, sources, macs, labels = set(), set(), set(), set(), set(), set(), {}, {}
        flow_count = 0
        for row in db.execute("SELECT data FROM flows WHERE source=? AND scope=? AND (src=? OR dst=?)", (source, scope, ip, ip)):
            f = json.loads(row[0])
            flow_count += 1
            first = f["start_time"] if first is None else min(first, f["start_time"])
            end = f["start_time"]+(f.get("duration") or 0)
            last = end if last is None else max(last, end)
            origin = f["source_ip"] == ip
            counters = [f.get("origin_packets")] if origin else [f.get("response_packets")]
            if f["source_ip"] == f["destination_ip"]:
                counters = [f.get("origin_packets"), f.get("response_packets")]
            transmitting |= any(n is not None and n > 0 for n in counters)
            target_only |= not origin and f.get("response_packets") == 0
            unknown |= any(n is None for n in counters)
            peers.add(f["destination_ip"] if origin else f["source_ip"])
            transports.add(f["transport"])
            sources.update(f.get("observation_sources", [f.get("observation_source", "unknown")]))
            if f.get("source_port") is not None:
                (ports_out if origin else ports_in).add((f["transport"], f["source_port"]))
            if f.get("destination_port") is not None:
                (ports_in if origin else ports_out).add((f["transport"], f["destination_port"]))
            for evidence in f.get("evidence", []):
                if evidence.get("parser_status") == "confirmed":
                    protocols.add(evidence["protocol"])
                for field, value in evidence.get("metadata", {}).items():
                    # Association labels describe an exchange, not necessarily this endpoint.
                    if field in ("sender", "calling_ae", "called_ae") and value:
                        labels.setdefault(field, set()).add(value)
            for e in f.get("link_layer_evidence", []):
                network_ip = e.get("network_source_ip") if e["ethernet_direction"] == "source" else e.get("network_destination_ip")
                if network_ip != ip:
                    continue
                # Binding requires an explicit, trusted direct-link IP configuration.
                direct = self.direct_links.get(e.get("observation_source")) == ip
                mkey = (e["mac"].lower(), e.get("observation_source"), direct)
                macs[mkey] = {"mac": mkey[0], "observation_source": mkey[1],
                              "association": "configured_direct_link" if direct else "unresolved_link_observation"}
        if not flow_count:
            if prior and prior["current"]:
                prior.update(current=False, presence="unresolved", flow_count=0)
                db.execute("UPDATE assets SET active=0,presence='unresolved',data=? WHERE id=?", (encode(prior), key))
                self._event(db, key, "observations_withdrawn", {"previous": json.loads(previous[0]), "current": prior})
            return
        configured = self.registry.get(ip, [])
        if isinstance(configured, dict):
            configured = [configured]
        review = []
        if len(configured) > 1:
            review.append("multiple_configured_registry_records")
        if len({m[0] for m in macs if m[2]}) > 1:
            review.append("multiple_macs_on_configured_direct_link")
        if any(len(values) > 1 for values in labels.values()):
            review.append("multiple_exchange_labels_review_context")
        presence = "observed_transmitting" if transmitting else "unresolved" if unknown else "addressed_only" if target_only else "unresolved"
        asset = {"schema_version": SCHEMA_VERSION, "asset_id": key, "source_id": source, "scope": scope, "ip": ip,
                 "address_kind": "multicast_group" if ipaddress.ip_address(ip).is_multicast else "unspecified" if ipaddress.ip_address(ip).is_unspecified else "unicast_address",
                 "current": True, "presence": presence, "first_seen": first, "last_seen": last,
                 "time_basis": "flow start and start+duration estimate; not exact last-packet time",
                 "flow_count": flow_count, "peer_count": len(peers), "transports": sorted(transports),
                 "protocols": sorted(protocols), "protocol_meaning": "participation in evidence-backed exchange; not device identity",
                 "local_ports": sorted(ports_out), "peer_ports": sorted(ports_in),
                 "observation_sources": sorted(sources), "mac_observations": sorted(macs.values(), key=encode),
                 "exchange_labels": {k: sorted(v) for k,v in labels.items()},
                 "configured": {"match": "ip_based_registry" if configured else "unregistered", "records": configured,
                                "provenance": "operator configuration; not authenticated identity"},
                 "review_findings": review,
                 "unknown": ["physical_device_identity", "device_category"] + ([] if macs else ["mac_not_available"])}
        db.execute("INSERT OR REPLACE INTO assets VALUES(?,?,?,?,?,?,?,?,?)", (key, source, scope, ip, presence, bool(configured), bool(review), 1, encode(asset)))
        if prior != asset:
            renewed = prior and db.execute("SELECT MIN(start) FROM flows WHERE source=? AND scope=? AND (src=? OR dst=?) AND start>?", (source, scope, ip, ip, prior["last_seen"])).fetchone()[0]
            kind = "discovered" if prior is None else "returned" if not prior["current"] or renewed is not None and renewed > prior["last_seen"]+self.activity_window else "observations_corrected" if withdrawal or first > prior["first_seen"] or last < prior["last_seen"] else "profile_updated"
            if prior and prior["configured"] != asset["configured"]:
                kind = "registry_changed"
            self._event(db, key, kind, {"previous": prior, "current": asset})

    def _event(self, db, asset_id, kind, data):
        db.execute("INSERT INTO events(asset_id,at,kind,data) VALUES(?,?,?,?)", (asset_id, time.time(), kind, encode(data)))

    def _activity(self, db, asset):
        end = db.execute("SELECT MAX(end) FROM flows WHERE source=? AND scope=?", (asset["source_id"], asset["scope"])).fetchone()[0]
        live = asset["scope"].startswith("live-")
        anchor = time.time() if live else (end or 0)
        asset["activity"] = {"state": "recently_observed" if asset["current"] and anchor-asset["last_seen"] <= self.activity_window else "not_recently_observed",
                             "window_seconds": self.activity_window, "anchor": "wall_clock" if live else "capture_time",
                             "meaning": "observation recency, not device online/offline status"}
        return asset

    def assets(self, q="", scope=None, presence=None, registered=None, review=None, source_id=None, limit=50, offset=0):
        clauses, args = ["active=1"], []
        for col, val in (("scope", scope), ("presence", presence), ("registered", registered), ("review", review), ("source", source_id)):
            if val is not None:
                clauses.append(col+"=?")
                args.append(val)
        if q:
            clauses.append("instr(lower(data),?)>0")
            args.append(q.lower())
        where = " WHERE "+" AND ".join(clauses)
        with self.connect() as db:
            db.execute("BEGIN")
            total = db.execute("SELECT COUNT(*) FROM assets"+where, args).fetchone()[0]
            rows = [self._activity(db, json.loads(r[0])) for r in db.execute("SELECT data FROM assets"+where+" ORDER BY scope,ip,id LIMIT ? OFFSET ?", (*args, limit, offset))]
        return {"schema_version": SCHEMA_VERSION, "records": rows, "total": total, "offset": offset,
                "next_offset": offset+len(rows) if limit >= 0 and offset+len(rows)<total else None}

    def asset(self, key):
        with self.connect() as db:
            row = db.execute("SELECT data FROM assets WHERE id=?", (key,)).fetchone()
            return self._activity(db, json.loads(row[0])) if row else None

    def related(self, key, evidence=False, limit=50, offset=0):
        with self.connect() as db:
            asset = db.execute("SELECT source,scope,ip FROM assets WHERE id=?", (key,)).fetchone()
            if not asset:
                return None
            source, scope, ip = asset
            args = (source, scope, ip, ip)
            where = " WHERE source=? AND scope=? AND (src=? OR dst=?)"
            total = db.execute("SELECT COUNT(*) FROM flows"+where, args).fetchone()[0]
            result = []
            for row in db.execute("SELECT data FROM flows"+where+" ORDER BY start DESC,id LIMIT ? OFFSET ?", (*args, limit, offset)):
                f = json.loads(row[0])
                if evidence:
                    refs = []
                    for cid in f.get("capture_ids", [f.get("capture_id")]):
                        cap = db.execute("SELECT data FROM captures WHERE source=? AND scope=? AND id=?", (source, scope, cid)).fetchone()
                        cap = json.loads(cap[0]) if cap else {}
                        refs.append({"capture_id": cid, "sha256": cap.get("sha256"), "raw_retained": cap.get("raw_retained"),
                                     "raw_capture": cap.get("raw_capture"), "status": "retained_as_reported_by_module2" if cap.get("raw_retained") else "unavailable" if cap.get("raw_retained") is False else "unknown_imported_metadata"})
                    result.append({"flow_id": f["flow_id"], "observation_ids": f.get("observation_ids", [f.get("observation_id")]),
                                   "protocol_evidence": f.get("evidence", []), "link_layer_evidence": f.get("link_layer_evidence", []), "captures": refs})
                else:
                    result.append({k: f.get(k) for k in ("flow_id", "source_ip", "destination_ip", "source_port", "destination_port", "transport", "start_time", "duration", "connection_state", "origin_packets", "response_packets", "correlation_status", "observation_sources")})
            return {"schema_version": SCHEMA_VERSION, "records": result, "total": total, "offset": offset,
                    "pagination_unit": "canonical_flow_evidence_groups" if evidence else "canonical_flows", "next_offset": offset+len(result) if offset+len(result)<total else None}

    def events(self, asset_id=None, limit=50, offset=0):
        with self.connect() as db:
            where, args = (" WHERE asset_id=?", (asset_id,)) if asset_id else ("", ())
            total = db.execute("SELECT COUNT(*) FROM events"+where, args).fetchone()[0]
            records = [{**dict(r), "data": json.loads(r["data"])} for r in db.execute("SELECT * FROM events"+where+" ORDER BY id DESC LIMIT ? OFFSET ?", (*args, limit, offset))]
            return {"schema_version": SCHEMA_VERSION, "records": records, "total": total, "next_offset": offset+len(records) if offset+len(records)<total else None}

    def status(self):
        with self.connect() as db:
            return {"schema_version": SCHEMA_VERSION, "app": "hiot-module3", "synchronizations": [dict(r) for r in db.execute("SELECT * FROM sync")],
                    "asset_count": db.execute("SELECT COUNT(*) FROM assets WHERE active=1").fetchone()[0],
                    "canonical_flow_count": db.execute("SELECT COUNT(*) FROM flows").fetchone()[0],
                    "events": db.execute("SELECT COUNT(*) FROM events").fetchone()[0],
                    "configured_unobserved": [{"source_id": s[0], "scope": s[1], "ip": ip, "configured": details} for s in db.execute("SELECT source,scope FROM sync") for ip,details in self.registry.items()
                                              if not db.execute("SELECT 1 FROM assets WHERE source=? AND scope=? AND ip=? AND active=1", (*s, ip)).fetchone()],
                    "input": self.setting("input") or {"state": "not_connected"},
                    "limitations": ["Passive visibility only", "IP registry matches are not authenticated identity", "Module 2 sustained strict acceptance was false; packet loss is not established as zero"]}

    def export(self, **filters):
        # Hold one read snapshot through streamed pages; do not materialize the export.
        with self.connect() as db:
            db.execute("BEGIN")
            for row in db.execute("SELECT data FROM assets WHERE active=1 ORDER BY scope,ip,id"):
                asset = json.loads(row[0])
                if filters.get("scope") and asset["scope"] != filters["scope"]:
                    continue
                if filters.get("source_id") and asset["source_id"] != filters["source_id"]:
                    continue
                if filters.get("presence") and asset["presence"] != filters["presence"]:
                    continue
                if filters.get("q") and filters["q"].lower() not in row[0].lower():
                    continue
                if filters.get("registered") is not None and bool(asset["configured"]["records"]) != bool(filters["registered"]):
                    continue
                if filters.get("review") is not None and bool(asset["review_findings"]) != bool(filters["review"]):
                    continue
                yield (encode(self._activity(db, asset))+"\n").encode()
