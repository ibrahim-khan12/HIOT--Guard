"""Measured Module 3 API/replay evaluation. This does not evaluate packet capture."""
import _bootstrap
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer
from types import SimpleNamespace
from urllib.request import urlopen

from module2.store import Store as MonitoringStore
from module2.server import handler as monitoring_handler
from module3.input import encode
from module3.store import Store
from module3.server import handler
from module3.sync import Worker


def percentile(values, p=.95):
    return sorted(values)[min(len(values)-1, int((len(values)-1)*p))] if values else None


def memory():
    if os.name != "nt":
        return None
    class Counters(ctypes.Structure):
        _fields_ = [("cb", ctypes.c_ulong), ("faults", ctypes.c_ulong)] + [(n, ctypes.c_size_t) for n in ("peak", "working", "p1", "p2", "p3", "p4", "p5", "p6")]
    item = Counters(); item.cb = ctypes.sizeof(item)
    from ctypes import wintypes
    process = ctypes.windll.kernel32.GetCurrentProcess
    process.restype = wintypes.HANDLE
    call = ctypes.windll.psapi.GetProcessMemoryInfo
    call.argtypes = (wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD)
    return item.working/1024/1024 if call(process(), ctypes.byref(item), item.cb) else None


def generated(n):
    for i in range(n):
        yield {"schema_version": "hiot.monitoring.v1", "flow_id": str(i), "observation_id": str(i), "capture_id": "benchmark",
               "scope": "benchmark", "source_ip": f"10.90.{(i%250)//250}.{i%250+1}", "destination_ip": "10.91.0.1",
               "source_port": 10000+i%50000, "destination_port": 2575, "transport": "tcp", "start_time": 100.+i,
               "duration": 1., "origin_packets": 4, "response_packets": 3, "evidence": [], "observation_source": "synthetic_replay",
               "connection_state": "SF", "correlation_status": "observation_only"}


def seed(monitor, n):
    with monitor.write() as db:
        db.executemany("INSERT INTO canonical VALUES(?,?,?,?,?,?,?)", ((f["flow_id"], f["scope"], f["start_time"], f["transport"], "", "[]", encode(f)) for f in generated(n)))
        db.execute("INSERT INTO captures VALUES('benchmark','benchmark','synthetic_replay',0,?)", (encode({"capture_id": "benchmark", "scope": "benchmark", "raw_retained": False, "synthetic": True}),))
        db.execute("UPDATE flow_revision SET version=version+1")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--seconds", type=float, default=900)
    p.add_argument("--flows", type=int, default=10000)
    p.add_argument("--output", default="runs/module3-evaluation/service.json")
    args = p.parse_args()
    output = Path(args.output); output.parent.mkdir(parents=True, exist_ok=True)
    report = {"started": time.time(), "pid": os.getpid(), "requested_seconds": args.seconds, "flows": args.flows,
              "workload": "Synthetic canonical-flow replay through real Module 2/3 HTTP APIs; no sensor or VM", "checks": [], "samples": [], "errors": []}
    report["source_hashes"] = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for folder in ("module2", "Module 3/module3") for path in Path(folder).glob("*.py")}
    with tempfile.TemporaryDirectory(prefix="module3-benchmark-") as folder:
        root = Path(folder)
        monitor = MonitoringStore(root/"monitoring.sqlite3")
        seed(monitor, args.flows)
        store = Store(root/"inventory.sqlite3")
        live = SimpleNamespace(running=False, interval=5, scope=None, status=lambda: {"state": "stopped"})
        upstream = ThreadingHTTPServer(("127.0.0.1", 0), monitoring_handler(monitor, live, 0))
        api = ThreadingHTTPServer(("127.0.0.1", 0), handler(store))
        threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (upstream, api)]
        for t in threads: t.start()
        worker = Worker(store, "http://127.0.0.1:"+str(upstream.server_port))
        base = "http://127.0.0.1:"+str(api.server_port)
        def request(path):
            began = time.monotonic()
            with urlopen(base+path, timeout=30) as r: data = json.load(r)
            return data, time.monotonic()-began
        latencies, query_times = [], []
        try:
            warmup = time.monotonic(); worker.once()
            report["initial_sync_seconds"] = time.monotonic()-warmup
            key = store.assets(limit=1)["records"][0]["asset_id"]
            worker.start()
            started, cpu = time.monotonic(), time.process_time()
            tick = 0
            while time.monotonic()-started < args.seconds:
                tick += 1
                # Add a previously absent protocol to one existing endpoint. This
                # exercises updates to old flow timestamps rather than newer-only cursors.
                label = "BENCHMARK_"+str(tick)
                with monitor.write() as db:
                    row = db.execute("SELECT data FROM canonical WHERE id='0'").fetchone()
                    f = json.loads(row[0]); f["evidence"] = [{"capture_id": "benchmark", "observation_id": "0", "frame": tick,
                        "timestamp": 100., "protocol": label, "parser_status": "confirmed", "metadata": {}}]
                    db.execute("UPDATE canonical SET data=? WHERE id='0'", (encode(f),))
                    db.execute("UPDATE flow_revision SET version=version+1")
                committed = time.monotonic()
                target = next(a["asset_id"] for a in store.assets(q='10.90.0.1')["records"] if a["ip"] == "10.90.0.1")
                seen = False
                while time.monotonic()-committed < 30:
                    data, elapsed = request('/api/assets/'+target); query_times.append(elapsed)
                    if label in data["protocols"]:
                        seen = True; break
                    time.sleep(.2)
                latency = time.monotonic()-committed
                latencies.append(latency)
                rows, elapsed = request('/api/assets?limit=50'); query_times.append(elapsed)
                _, detail_time = request('/api/assets/'+key); query_times.append(detail_time)
                status, _ = request('/api/status')
                sample = {"elapsed": time.monotonic()-started, "freshness_seconds": latency, "updated": seen,
                          "query_seconds": elapsed, "memory_mib": memory(), "flows": status["canonical_flow_count"], "assets": status["asset_count"], "input": status["input"]["state"]}
                report["samples"].append(sample)
                if not seen or status["canonical_flow_count"] != args.flows or rows["total"] != 251:
                    report["errors"].append(sample)
                report["elapsed_seconds"] = time.monotonic()-started
                output.write_text(json.dumps(report, indent=2))
                time.sleep(min(5, max(0, args.seconds-(time.monotonic()-started))))
            report.update(elapsed_seconds=time.monotonic()-started, cpu_seconds=time.process_time()-cpu,
                          p95_freshness_seconds=percentile(latencies), p95_query_seconds=percentile(query_times))
            report["checks"] = [{"name": "No inconsistent inventory or unhandled failure", "passed": not report["errors"]},
                                {"name": "p95 committed-to-inventory <=10s", "passed": bool(latencies) and percentile(latencies)<=10},
                                {"name": "p95 warm API <=1s", "passed": bool(query_times) and percentile(query_times)<=1},
                                {"name": "Requested 15-minute exercise", "passed": report["elapsed_seconds"]>=900}]
        except Exception as error:
            report["errors"].append(str(error))
            raise
        finally:
            worker.stop()
            for s in (upstream, api): s.shutdown(); s.server_close()
            for t in threads: t.join()
            monitor.close()
            report["passed"] = bool(report["checks"]) and all(c["passed"] for c in report["checks"])
            output.write_text(json.dumps(report, indent=2))
    print(json.dumps({k:v for k,v in report.items() if k != "samples"}, indent=2))


if __name__ == "__main__": main()
