"""Read-only inventory API, bound to loopback."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


def handler(store):
    class API(BaseHTTPRequestHandler):
        def send(self, code, data, content_type="application/json"):
            raw = data if isinstance(data, bytes) else json.dumps(data).encode()
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            try:
                parsed = urlsplit(self.path)
                query = parse_qs(parsed.query)
                limit, offset = int(query.get("limit", ["50"])[0]), int(query.get("offset", ["0"])[0])
                if not 1 <= limit <= 200 or offset < 0:
                    raise ValueError("limit must be 1..200; offset must be nonnegative")
                filters = {k: query[k][0][:256] for k in ("q", "scope", "presence", "source_id") if k in query}
                for k in ("registered", "review"):
                    if k in query:
                        if query[k][0] not in ("0", "1"):
                            raise ValueError(k+" must be 0 or 1")
                        filters[k] = int(query[k][0])
                if parsed.path in ("/", "/app.js"):
                    file = "index.html" if parsed.path == "/" else "app.js"
                    return self.send(200, Path(__file__).with_name(file).read_bytes(), "text/html; charset=utf-8" if file.endswith("html") else "text/javascript; charset=utf-8")
                if parsed.path == "/api/ready":
                    return self.send(200, {"app": "hiot-module3"})
                if parsed.path == "/api/status":
                    return self.send(200, store.status())
                if parsed.path == "/api/assets":
                    return self.send(200, store.assets(**filters, limit=limit, offset=offset))
                if parsed.path == "/api/events":
                    return self.send(200, store.events(query.get("asset_id", [None])[0], limit, offset))
                if parsed.path == "/api/export.jsonl":
                    self.connection.settimeout(30)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/x-ndjson")
                    self.send_header("Content-Disposition", 'attachment; filename="module3-inventory.jsonl"')
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.close_connection = True
                    for raw in store.export(**filters):
                        self.wfile.write(raw)
                    return
                parts = parsed.path.strip("/").split("/")
                if len(parts) in (3, 4) and parts[:2] == ["api", "assets"]:
                    if len(parts) == 3:
                        data = store.asset(parts[2])
                    elif parts[3] in ("communications", "evidence"):
                        data = store.related(parts[2], parts[3] == "evidence", limit, offset)
                    else:
                        data = None
                    return self.send(200, data) if data is not None else self.send(404, {"error": "Endpoint or view not found"})
                return self.send(404, {"error": "Not found"})
            except (ValueError, TypeError) as error:
                self.send(400, {"error": str(error)})
            except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, TimeoutError):
                pass

        def log_message(self, *args):
            pass
    return API


def serve(store, worker=None, port=8879):
    server = ThreadingHTTPServer(("127.0.0.1", port), handler(store))
    if worker:
        worker.start()
    print(f"Module 3 inventory: http://127.0.0.1:{port}/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if worker:
            worker.stop()
        server.server_close()
