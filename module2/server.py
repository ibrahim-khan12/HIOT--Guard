"""Loopback-only monitoring API; the collector is independent of browser lifetime."""
import atexit
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading
import time
from urllib.parse import parse_qs, urlsplit

from . import SCHEMA_VERSION


def handler(store, live, port):
    class API(BaseHTTPRequestHandler):
        def send(self, code, data, content_type="application/json", attachment=None):
            raw = data if isinstance(data, bytes) else json.dumps(data).encode()
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            if attachment:
                self.send_header("Content-Disposition", f'attachment; filename="{attachment}"')
            self.end_headers()
            try:
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
                pass

        def do_GET(self):
            parsed = urlsplit(self.path)
            params = parse_qs(parsed.query)
            scope = params.get("scope", [None])[0] or None
            if parsed.path == "/":
                return self.send(200, Path(__file__).with_name("index.html").read_bytes(), "text/html; charset=utf-8")
            if parsed.path == "/api/status":
                return self.send(200, {"app": "hiot-module2", "pid": os.getpid(), "live": live.running, "scope": getattr(live, "scope", None),
                                       "snapshot_interval": live.interval, "generated": time.time(), **store.status(scope)})
            if parsed.path == "/api/summary":
                return self.send(200, store.summary(scope))
            if parsed.path in ("/api/flows", "/api/export.jsonl"):
                try:
                    limit = min(1000, max(1, int(params.get("limit", ["100"])[0])))
                except ValueError:
                    return self.send(400, {"error": "limit must be an integer"})
                records = store.flows(params.get("q", [""])[0][:200], params.get("protocol", [""])[0],
                                      2**31 if parsed.path.endswith("jsonl") else limit, scope,
                                      params.get("transport", [None])[0])
                if parsed.path.endswith("jsonl"):
                    return self.send(200, ("".join(json.dumps(r)+"\n" for r in records)).encode(),
                                     "application/x-ndjson", "module-2-flows.jsonl")
                return self.send(200, {"schema_version": SCHEMA_VERSION, "records": records, "returned": len(records)})
            return self.send(404, {"error": "Not found"})

        def do_POST(self):
            if self.headers.get("Origin") not in (None, f"http://127.0.0.1:{port}"):
                return self.send(403, {"error": "Cross-origin control refused"})
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                return self.send(415, {"error": "JSON required"})
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
