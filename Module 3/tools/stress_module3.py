"""Capacity characterization, separate from the 10k-flow acceptance workload."""
import _bootstrap
import argparse
import json
from pathlib import Path
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer
from types import SimpleNamespace
from urllib.request import urlopen

from evaluate_module3_service import memory, percentile, seed
from module2.store import Store as MonitoringStore
from module2.server import handler as monitoring_handler
from module3.store import Store
from module3.server import handler
from module3.sync import Worker


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--flows", type=int, default=100000)
    p.add_argument("--output", default="runs/module3-evaluation/stress.json")
    args = p.parse_args()
    report = {"flows": args.flows, "workload": "Synthetic canonical records, no packet capture", "errors": []}
    with tempfile.TemporaryDirectory(prefix="module3-stress-") as folder:
        root = Path(folder)
        monitor = MonitoringStore(root/"monitor.sqlite3")
        store = Store(root/"inventory.sqlite3")
        seed(monitor, args.flows)
        live = SimpleNamespace(running=False, interval=5, scope=None, status=lambda: {"state": "stopped"})
        upstream = ThreadingHTTPServer(("127.0.0.1", 0), monitoring_handler(monitor, live, 0))
        api = ThreadingHTTPServer(("127.0.0.1", 0), handler(store))
        threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (upstream, api)]
        for t in threads: t.start()
        worker = Worker(store, "http://127.0.0.1:"+str(upstream.server_port))
        cpu = time.process_time()
        try:
            started = time.monotonic(); worker.once()
            report["initial_sync_seconds"] = time.monotonic()-started
            with monitor.write() as db:
                db.execute("UPDATE canonical SET data=json_set(data,'$.duration',2) WHERE id='0'")
                db.execute("UPDATE flow_revision SET version=version+1")
            started = time.monotonic(); worker.once()
            report["one_old_flow_update_sync_seconds"] = time.monotonic()-started
            key = store.assets(limit=1)["records"][0]["asset_id"]
            queries = []
            for _ in range(10):
                for path in ("/api/assets?limit=50", "/api/assets/"+key):
                    started = time.monotonic()
                    with urlopen("http://127.0.0.1:"+str(api.server_port)+path, timeout=30) as response:
                        json.load(response)
                    queries.append(time.monotonic()-started)
            report.update(p95_warm_query_seconds=percentile(queries), memory_mib=memory(), cpu_seconds=time.process_time()-cpu,
                          actual_flows=store.status()["canonical_flow_count"], assets=store.status()["asset_count"])
            report["passed_integrity"] = report["actual_flows"] == args.flows and report["assets"] == 251
            report["meaning"] = "Characterization only. No 10-second update target is claimed at this larger workload."
        except Exception as error:
            report["errors"].append(str(error)); raise
        finally:
            for s in (upstream, api): s.shutdown(); s.server_close()
            for t in threads: t.join()
            monitor.close()
            path = Path(args.output); path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__": main()
