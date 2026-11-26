"""Verify Module 2 polling, live Module 4 assessment, and its detector context API."""

import argparse
from contextlib import closing, contextmanager
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from threading import Event, Thread
import time
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import _bootstrap  # noqa: F401
from module2.server import handler as monitoring_handler
from module2.store import Store as MonitoringStore
from module3.classification import HANDOFF_SCHEMA, LiveClassification
from module3.server import handler as discovery_handler
from module3.store import Store
from module3.sync import Worker


@contextmanager
def loopback(handler):
    with ThreadingHTTPServer(("127.0.0.1", 0), handler) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}"
        finally:
            server.shutdown()
            thread.join()


def read(url):
    with urlopen(url, timeout=3) as response:
        return json.load(response)


def wait_for(get, ready, timeout=12):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = get()
        if ready(value):
            return value
        time.sleep(.05)
    assessment = value.get("classification") or value
    detail = {key: assessment[key] for key in ("state", "assessment_state", "reason", "inventory_revision") if key in assessment}
    raise RuntimeError(f"Expected assessment state did not arrive. Last status {detail}")


def detector_context(record):
    """Contract consumer fixture. It accepts context for a current inventory revision."""
    assert record["schema_version"] == HANDOFF_SCHEMA
    assert record["inventory_revision"] and record["inventory_digest"]
    assert "configured" not in record and "features" not in record
    if record["assessment_state"] != "current":
        assert record["category"] is None and record["workflows"] == record["evidence"] == []
        return None
    assert record["category"] == "unknown"
    assert record["assessment_scope"] == "observed_workflow; physical_device_unverified"
    assert record["method"] and record["assessment_version"]
    assert all(item["capture_sha256"] == record["capture_sha256"] and item["frames"] for item in record["evidence"])
    return record["endpoint"], record["category"], tuple(record["workflows"])


def updated_capture(store, scope, digest):
    with store.write() as db:
        rows = db.execute("SELECT id,data FROM captures WHERE scope=?", (scope,)).fetchall()
        assert len(rows) == 1, "Expected the saved single-view stage-2 recording"
        key, serialized = rows[0]
        capture = json.loads(serialized)
        capture["sha256"] = digest
        db.execute("UPDATE captures SET data=? WHERE id=?", (json.dumps(capture), key))
        db.execute("UPDATE flow_revision SET version=version+1 WHERE id=1")
        return str(db.execute("SELECT version FROM flow_revision WHERE id=1").fetchone()[0])


def verify(baseline, tshark):
    expected = json.loads((baseline / "classification.json").read_text(encoding="utf-8"))
    scope = expected["scope"]
    expected_rows = {row["endpoint"]: row for row in expected["records"]}
    address = "10.88.0.15"
    with TemporaryDirectory(prefix="hiot-live-demo-") as folder:
        folder = Path(folder)
        monitoring_path = folder / "monitoring.sqlite3"
        source = (baseline / "module2" / "monitoring.sqlite3").resolve().as_uri() + "?mode=ro"
        with closing(sqlite3.connect(source, uri=True)) as upstream, closing(sqlite3.connect(monitoring_path)) as fresh:
            upstream.backup(fresh)
        monitoring = MonitoringStore(monitoring_path)
        inventory = Store(folder / "inventory.sqlite3", {address: {"role": "configured_fixture_role"}})
        assessment = LiveClassification(inventory, scope, baseline / "module2", tshark, interval=.1)
        original_load = assessment.load_packets
        pace_decoder, decoder_started, decoder_gate = Event(), Event(), Event()

        def controlled_load(capture):
            if pace_decoder.is_set():
                decoder_started.set()
                if not decoder_gate.wait(10):
                    raise RuntimeError("Verification did not release the fixture decoder")
            return original_load(capture)

        assessment.load_packets = controlled_load
        collector = SimpleNamespace(running=False, scope=scope, interval=1, status=lambda: {"state": "stopped"})
        with loopback(monitoring_handler(monitoring, collector, 0)) as module2, loopback(discovery_handler(inventory, assessment)) as module3:
            worker = Worker(inventory, module2, [scope], interval=.1)
            worker.start()
            assessment.start()
            try:
                listing = wait_for(lambda: read(module3 + "/api/assets?limit=200"), lambda item: item["total"] > 0)
                assets = {asset["ip"]: asset for asset in listing["records"]}
                assert set(expected_rows).issubset(assets)
                for endpoint, row in expected_rows.items():
                    detail = module3 + "/api/assets/" + assets[endpoint]["asset_id"]
                    live = wait_for(lambda: read(detail), lambda item: (item.get("classification") or {}).get("state") == "current")
                    assert {key: live["classification"][key] for key in row} == row, endpoint
                    assert live["configured"] == assets[endpoint]["configured"], endpoint

                handoff_url = module3 + "/api/assets/" + assets[address]["asset_id"] + "/module4-handoff"
                first = read(handoff_url)
                assert first["inventory_revision"] == expected["inventory_revision"]
                assert first["inventory_digest"] == expected["inventory_digest"]
                assert detector_context(first) == (address, "unknown", ("ct_storage",))
                try:
                    urlopen(Request(handoff_url, data=b"{}", method="POST"), timeout=3).close()
                except HTTPError as error:
                    assert error.code == 501
                else:
                    raise AssertionError("Read-only assessment route unexpectedly accepted a write")

                pace_decoder.set()
                bad_revision = updated_capture(monitoring, scope, "0" * 64)
                assert decoder_started.wait(8), "The live worker did not process the new inventory revision"
                pending = read(handoff_url)
                assert pending["inventory_revision"] == bad_revision
                assert pending["assessment_state"] == "pending" and detector_context(pending) is None
                decoder_gate.set()
                unavailable = wait_for(lambda: read(handoff_url), lambda item: item["assessment_state"] == "unavailable")
                assert unavailable["inventory_revision"] == bad_revision and detector_context(unavailable) is None

                restored_revision = updated_capture(monitoring, scope, expected["capture_sha256"])
                restored = wait_for(lambda: read(handoff_url), lambda item: item["inventory_revision"] == restored_revision
                                    and item["assessment_state"] == "current")
                assert detector_context(restored) == detector_context(first)
                assert restored["evidence"] == first["evidence"]
                return {
                    "fixture": "saved benign GNS3 capture through actual Module 2 snapshot and Module 3 HTTP services",
                    "offline_replay_equivalent_endpoints": len(expected_rows),
                    "registry_facts_preserved": True,
                    "handoff_schema": HANDOFF_SCHEMA,
                    "handoff_read_only": True,
                    "module5_consumer": "contract fixture",
                    "transitions": [{"revision": row["inventory_revision"], "state": row["assessment_state"],
                                     "category": row["category"]} for row in (first, pending, unavailable, restored)],
                    "sample_handoff": restored,
                }
            finally:
                decoder_gate.set()
                assessment.stop()
                worker.stop()
                monitoring.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, default=Path("runs/module4-stage2-evaluation-20261124/A"))
    parser.add_argument("--tshark", default=r"C:\Program Files\Wireshark\tshark.exe")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = verify(args.baseline, args.tshark)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(f"Verified {report['offline_replay_equivalent_endpoints']} replay-equivalent assessments and the read-only handoff")


if __name__ == "__main__":
    main()
