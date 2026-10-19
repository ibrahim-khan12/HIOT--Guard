"""Loopback-only monitoring API; the collector is independent of browser lifetime."""
import atexit
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading
import time
import math
from urllib.parse import parse_qs, urlsplit

from . import SCHEMA_VERSION


def handler(store, live, port):
    control_lock = threading.Lock()
    class API(BaseHTTPRequestHandler):
        def send(self, code, data, content_type="application/json", attachment=None):
            raw = data if isinstance(data, bytes) else json.dumps(data).encode()
            try:
                self.send_response(code)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                if attachment:
                    self.send_header("Content-Disposition", f'attachment; filename="{attachment}"')
                self.end_headers()
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
                pass

        def do_GET(self):
            parsed = urlsplit(self.path)
            params = parse_qs(parsed.query)
            scope = params.get("scope", [None])[0] or None
            if parsed.path == "/api/ready":
                return self.send(200, {"app": "hiot-module2", "pid": os.getpid()})
            if parsed.path == "/":
                return self.send(200, Path(__file__).with_name("index.html").read_bytes(), "text/html; charset=utf-8")
            if parsed.path == "/api/status":
                return self.send(200, {"app": "hiot-module2", "pid": os.getpid(), "live": live.running, "scope": getattr(live, "scope", None),
                                       "collector": live.status(), "snapshot_interval": live.interval, "generated": time.time(), **store.status(scope, limit=200, issue_limit=100)})
            if parsed.path == "/api/health-events":
                return self.send(200, {"events": store.events()})
            if parsed.path == "/api/metrics":
                return self.send(200, {"metrics": store.metrics(scope, 5000)})
            if parsed.path == "/api/captures":
                try:
                    offset = max(0, int(params.get("offset", ["0"])[0]))
                    limit = min(200, max(1, int(params.get("limit", ["10"])[0])))
                except ValueError:
                    return self.send(400, {"error": "offset/limit must be integers"})
                result = store.status(scope, limit=limit, offset=offset, issue_limit=0, source=params.get("source", [None])[0])
                return self.send(200, {"captures": result["captures"], "total": result["capture_count"]})
            if parsed.path == "/api/summary":
                return self.send(200, store.summary(scope))
            if parsed.path in ("/api/flows", "/api/export.jsonl"):
                try:
                    limit = min(1000, max(1, int(params.get("limit", ["100"])[0])))
                    offset = max(0, int(params.get("offset", ["0"])[0]))
                    before = json.loads(params["before"][0]) if "before" in params else None
                    if before is not None and (not isinstance(before, list) or len(before) != 2 or
                                               not isinstance(before[0], (int, float)) or not math.isfinite(before[0]) or not isinstance(before[1], str)):
                        raise ValueError("Invalid cursor")
                except (ValueError, TypeError):
                    return self.send(400, {"error": "Invalid limit, offset or cursor"})
                query, protocol, transport = params.get("q", [""])[0][:200], params.get("protocol", [""])[0], params.get("transport", [None])[0]
                if parsed.path.endswith("jsonl"):
                    # HTTP/1.0 close-delimited body: records never accumulate in the web process.
                    try:
                        self.send_response(200)
                        self.send_header("Content-Type", "application/x-ndjson")
                        self.send_header("Content-Disposition", 'attachment; filename="module-2-flows.jsonl"')
                        self.send_header("Cache-Control", "no-store")
                        self.send_header("X-Content-Type-Options", "nosniff")
                        self.send_header("Connection", "close")
                        self.end_headers()
                        self.connection.settimeout(30)
                        self.close_connection = True
                        for record in store.iter_flows(query, protocol, scope, transport):
                            self.wfile.write((json.dumps(record)+"\n").encode())
                    except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, TimeoutError):
                        pass
                    return
                records = store.flows(query, protocol, limit+1, scope, transport, offset, before)
                more = len(records) > limit
                records = records[:limit]
                cursor = [records[-1]["start_time"], records[-1]["flow_id"]] if more and records else None
                return self.send(200, {"schema_version": SCHEMA_VERSION, "records": records, "returned": len(records), "next_cursor": cursor})
            return self.send(404, {"error": "Not found"})

        def do_POST(self):
            if self.headers.get("Origin") not in (None, f"http://127.0.0.1:{port}"):
                return self.send(403, {"error": "Cross-origin control refused"})
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                return self.send(415, {"error": "JSON required"})
            if not control_lock.acquire(blocking=False):
                return self.send(409, {"error": "A monitoring action is already running"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 4096:
                    raise ValueError("Invalid request size")
                data = json.loads(self.rfile.read(length))
                if self.path == "/api/live" and data.get("enabled") is True:
                    live.start()
                elif self.path == "/api/live" and data.get("enabled") is False:
                    live.stop()
                else:
                    raise ValueError("Only live-monitor start/stop controls are supported")
                return self.send(200, {"success": True, "live": live.running})
            except Exception as error:
                return self.send(400, {"error": str(error)})
            finally:
                control_lock.release()

        def log_message(self, *args):
            pass
    return API


def serve(store, live, port=8878):
    server = ThreadingHTTPServer(("127.0.0.1", port), handler(store, live, port))
    atexit.register(live.stop)
    if (store.setting("live") or {}).get("enabled"):
        live.start()
    print(f"Module 2 monitoring: http://127.0.0.1:{port}/", flush=True)
    try:
        server.serve_forever()
    finally:
        live.stop()
        server.server_close()
