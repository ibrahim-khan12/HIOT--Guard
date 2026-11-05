"""Browser-independent revision polling; fixed loopback upstream only."""
import json
import threading
import time
from urllib.parse import urlencode, urlsplit
from urllib.request import ProxyHandler, build_opener

from .input import stage


class Worker:
    def __init__(self, store, url="http://127.0.0.1:8878", scopes=None, interval=5):
        parsed = urlsplit(url)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.username:
            raise ValueError("Upstream must be a loopback HTTP origin")
        self.store, self.url = store, url.rstrip("/")
        self.scopes, self.interval = scopes, interval
        self.stop_event = threading.Event()
        self.thread = None
        self.opener = build_opener(ProxyHandler({}))

    def get(self, path):
        return self.opener.open(self.url+path, timeout=30)

    def once(self):
        began = time.monotonic()
        try:
            with self.get("/api/discovery-revision") as response:
                version = json.load(response)
            current = self.store.status()["synchronizations"]
            scopes = self.scopes if self.scopes is not None else sorted(set(version["scopes"]) | {s["scope"] for s in current if s["source"] == version["source_id"]})
            results = []
            for scope in scopes:
                prior = next((s for s in current if s["source"] == version["source_id"] and s["scope"] == scope), None)
                config = self.store.setting("worker_config")
                config_now = {"registry": self.store.registry, "direct_links": self.store.direct_links}
                if prior and prior["revision"] == str(version["revision"]) and config == config_now:
                    continue
                with self.get("/api/discovery-snapshot.jsonl?"+urlencode({"scope": scope})) as response:
                    with stage(iter(lambda: response.readline(8*1024*1024+1), b""), version["source_id"], scope) as (db, header):
                        results.append(self.store.apply(db, header))
            with self.get("/api/status") as response:
                health = json.load(response)
            collector = health.get("collector", {})
            self.store.setting("worker_config", {"registry": self.store.registry, "direct_links": self.store.direct_links})
            self.store.setting("input", {"state": "degraded" if collector.get("state") not in ("running", "stopped", None) else "connected",
                                        "url": self.url, "source_id": version["source_id"], "checked_at": time.time(),
                                        "last_success": time.time(), "collector": collector, "live": health.get("live"),
                                        "seconds": time.monotonic()-began, "error": None})
            return results
        except Exception as error:
            prior = self.store.setting("input") or {}
            self.store.setting("input", {**prior, "state": "unavailable", "checked_at": time.time(), "error": str(error)})
            raise

    def start(self):
        def run():
            while not self.stop_event.is_set():
                try:
                    self.once()
                except Exception:
                    pass  # Persistent input state contains the failure; retain inventory.
                self.stop_event.wait(self.interval)
        self.thread = threading.Thread(target=run, name="module3-discovery", daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=35)
