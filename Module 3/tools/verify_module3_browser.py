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


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--inventory", default="runs/module3-evaluation/offline-final/inventory.sqlite3")
    p.add_argument("--output", default="runs/module3-evaluation/browser")
    p.add_argument("--port", type=int, default=8879)
    args = p.parse_args()
    out = Path(args.output); out.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(Path(args.inventory).resolve().as_uri()+"?mode=ro", uri=True) as src, sqlite3.connect(out/"inventory.sqlite3") as dst:
        src.backup(dst)
    store = Store(out/"inventory.sqlite3", registry("gns3"))
    flows = list(generated(35))
    for f in flows: f["scope"] = "demonstration-fixture"
    f = dict(flows[0]); f.update(flow_id="unanswered", observation_id="unanswered", destination_ip="10.92.0.250", response_packets=0, connection_state="S0")
    flows.append(f)
    with stage((encode(f)+"\n" for f in flows), "explicit-ui-fixture", "demonstration-fixture", True) as (db, header):
        store.apply(db, header)
    store.setting("input", {"state": "imported_snapshot", "meaning": "Saved hospital inventory plus separately scoped synthetic browser-test fixture"})
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler(store))
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        env = {**os.environ, "MODULE3_URL": "http://127.0.0.1:"+str(args.port)}
        result = subprocess.run(["node", str(Path(__file__).with_suffix(".mjs")), str(out)], env=env)
        if result.returncode: raise SystemExit(result.returncode)
    finally:
        server.shutdown(); server.server_close(); thread.join()


if __name__ == "__main__": main()
