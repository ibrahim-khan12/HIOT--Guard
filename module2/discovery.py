"""Read-only, transactionally consistent discovery snapshot protocol."""
import hashlib
import json

SNAPSHOT_SCHEMA = "hiot.monitoring.snapshot.v1"


def revision(store):
    with store.connect() as db:
        db.execute("BEGIN")
        return {"schema_version": SNAPSHOT_SCHEMA,
                "source_id": json.loads(db.execute("SELECT data FROM settings WHERE key='discovery_source_id'").fetchone()[0]),
                "revision": db.execute("SELECT version FROM flow_revision WHERE id=1").fetchone()[0],
                "scopes": [r[0] for r in db.execute("SELECT DISTINCT scope FROM captures ORDER BY scope")]}


def snapshot(store, scope):
    """One WAL read snapshot; a missing trailer is never a valid replacement."""
    digest = hashlib.sha256()
    count = 0
    with store.connect() as db:
        db.execute("BEGIN")
        header = {"type": "header", "schema_version": SNAPSHOT_SCHEMA, "scope": scope,
                  "source_id": json.loads(db.execute("SELECT data FROM settings WHERE key='discovery_source_id'").fetchone()[0]),
                  "revision": db.execute("SELECT version FROM flow_revision WHERE id=1").fetchone()[0]}
        yield (json.dumps(header, sort_keys=True)+"\n").encode()
        for kind, table in (("capture", "captures"), ("flow", "canonical")):
            for row in db.execute(f"SELECT data FROM {table} WHERE scope=? ORDER BY id", (scope,)):
                raw = (json.dumps({"type": kind, "record": json.loads(row[0])}, sort_keys=True)+"\n").encode()
                digest.update(raw)
                count += 1
                yield raw
        yield (json.dumps({"type": "complete", "records": count, "sha256": digest.hexdigest(),
                           "revision": header["revision"]})+"\n").encode()
