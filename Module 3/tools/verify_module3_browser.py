"""Serve a copy of saved inventory plus an explicitly labelled UI fixture."""
import _bootstrap
import argparse
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import threading
from http.server import ThreadingHTTPServer

from module3.input import encode, stage
from module3.store import Store
from module3.server import handler
from evaluate_module3_service import generated
from config import registry


def seed_ci_reference(store):
    """Synthetic UI metadata only: no PCAP, medical data or live sensor required."""
    scope = "ci-reference-fixture"
    flows = []
    for key, src, dst, port, protocol in (
        ("ci-pump", "10.77.20.20", "10.77.30.40", 2575, "HL7/MLLP"),
        ("ci-ct", "10.77.20.30", "10.77.30.30", 11112, "DICOM"),
    ):
        f = next(generated(1))
        f.update(flow_id=key, observation_id=key, capture_id="synthetic-ci-no-pcap",
                 scope=scope, source_ip=src, destination_ip=dst, destination_port=port,
                 observation_source="synthetic_ci_fixture")
        metadata = {"sender": "CI_PUMP_FIXTURE", "message_type": "ORU^R01"} if port == 2575 else {
            "calling_ae": "CI_CT_FIXTURE", "called_ae": "CI_PACS_FIXTURE"}
        f["evidence"] = [{"capture_id": f["capture_id"], "observation_id": key,
                         "frame": 1, "timestamp": f["start_time"], "protocol": protocol,
                         "parser_status": "confirmed", "metadata": metadata}]
        flows.append(f)
    with stage((encode(f)+"\n" for f in flows), "synthetic-ci-reference", scope, True) as (db, header):
        store.apply(db, header)
    return scope


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--inventory", default="runs/module3-evaluation/offline-final/inventory.sqlite3")
    p.add_argument("--output", default="runs/module3-evaluation/browser")
    p.add_argument("--port", type=int, default=8879)
    p.add_argument("--fixture", action="store_true", help="Use labelled synthetic CI records instead of saved hospital inventory")
    p.add_argument("--reference-scope", help="Recording selected by the browser checks")
    args = p.parse_args()
    out = Path(args.output); out.mkdir(parents=True, exist_ok=True)
    if not args.fixture:
        with sqlite3.connect(Path(args.inventory).resolve().as_uri()+"?mode=ro", uri=True) as src, sqlite3.connect(out/"inventory.sqlite3") as dst:
            src.backup(dst)
    store = Store(out/"inventory.sqlite3", registry("gns3"))
    reference_scope = seed_ci_reference(store) if args.fixture else args.reference_scope or "acceptance-1792340111388501600"
    flows = list(generated(35))
    for f in flows: f["scope"] = "demonstration-fixture"
    f = dict(flows[0]); f.update(flow_id="unanswered", observation_id="unanswered", destination_ip="10.92.0.250", response_packets=0, connection_state="S0")
    flows.append(f)
    with stage((encode(f)+"\n" for f in flows), "explicit-ui-fixture", "demonstration-fixture", True) as (db, header):
        store.apply(db, header)
    store.setting("input", {"state": "imported_snapshot", "meaning":
        "Synthetic CI fixtures only; no captured hospital traffic or raw PCAP" if args.fixture else
        "Saved hospital inventory plus separately scoped synthetic browser-test fixture"})
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler(store))
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        env = {**os.environ, "MODULE3_URL": "http://127.0.0.1:"+str(args.port),
               "MODULE3_REFERENCE_SCOPE": reference_scope,
               "MODULE3_TEST_DATA": "synthetic_ci_fixture" if args.fixture else "saved_inventory_and_ui_fixture"}
        result = subprocess.run(["node", str(Path(__file__).with_suffix(".mjs")), str(out)], env=env)
        if result.returncode: raise SystemExit(result.returncode)
    finally:
        server.shutdown(); server.server_close(); thread.join()


if __name__ == "__main__": main()
