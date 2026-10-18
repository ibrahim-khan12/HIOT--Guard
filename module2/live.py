"""Independent, bounded GNS3 readers and periodic complete-PCAP analysis."""
from __future__ import annotations

import json
from pathlib import Path
import struct
import threading
import time
import uuid

from gns3 import GNS3
from config import CAPTURE_ROLES
from .parsing import identity
from .pcap import MAGICS, complete_pcap, snapshot
from .pipeline import Pipeline
from .retention import archive_processed


class Spool:
    def __init__(self, root, source, scope, store, limit=4*1024*1024, window=30):
        self.root, self.source, self.scope, self.store = Path(root), source, scope, store
        self.root.mkdir(parents=True, exist_ok=True)
        self.limit, self.lock = limit, threading.RLock()
        self.window, self.opened_at = window, time.monotonic()
        self.buffer, self.header, self.segments = bytearray(), None, []
        self.processed, self.counter = {}, 0
        for path in sorted(self.root.glob("segment-*.pcap")):
            number = int(path.stem.split("-")[-1])
            self.counter = max(self.counter, number)
            self.segments.append({"id": identity(scope, source, number), "path": path,
                                  "boundary": number > 1, "bytes": path.stat().st_size})
        known = store.capture_watermarks(scope, source)
        self.processed.update((s["id"], known[s["id"]]) for s in self.segments if s["id"] in known)
        self.pending_since = None
        self.pending_age()

    def pending_age(self, progress=False):
        with self.lock:
            pending = any(s["bytes"] > max(24, self.processed.get(s["id"], 0)) for s in self.segments)
            now = time.monotonic()
            if not pending:
                self.pending_since = None
            elif progress or self.pending_since is None:
                self.pending_since = now
            return now-self.pending_since if pending else None

    def new_segment(self):
        if len(self.segments) >= 2:
            old = self.segments[0]
            if old["bytes"] > 24 and self.processed.get(old["id"], 0) < old["bytes"]:
                raise BufferError("Analysis cannot keep up with the two-segment raw retention budget")
            self.store.expire_raw(old["id"])
            old["path"].unlink(missing_ok=True)
            self.segments.pop(0)
        self.counter += 1
        path = self.root / f"segment-{self.counter:06d}.pcap"
        path.write_bytes(self.header)
        self.segments.append({"id": identity(self.scope, self.source, self.counter), "path": path,
                              "boundary": self.counter > 1, "bytes": 24})
        self.opened_at = time.monotonic()

    def rotate_due(self):
        with self.lock:
            if self.header and self.segments[-1]["bytes"] > 24 and time.monotonic()-self.opened_at >= self.window:
                # Analysis of an older tail must finish before it can leave the rolling window.
                if len(self.segments) < 2 or self.processed.get(self.segments[0]["id"], 0) >= self.segments[0]["bytes"]:
                    self.new_segment()

    def reconnect(self):
        with self.lock:
            self.buffer.clear()
            self.header = None

    def feed(self, data):
        with self.lock:
            self.buffer.extend(data)
            if self.header is None:
                if len(self.buffer) < 24:
                    return
                self.header = bytes(self.buffer[:24])
                complete_pcap(self.header)
                del self.buffer[:24]
                self.new_segment()
            endian = MAGICS[self.header[:4]]
            snaplen = struct.unpack_from(endian + "I", self.header, 16)[0]
            while len(self.buffer) >= 16:
                captured, original = struct.unpack_from(endian + "II", self.buffer, 8)
                if captured > snaplen or captured > original or captured+40 > self.limit:
                    raise ValueError("Invalid or oversized streamed PCAP record")
                if len(self.buffer) < 16+captured:
                    break
                record = bytes(self.buffer[:16+captured])
                if self.segments[-1]["bytes"] + len(record) > self.limit:
                    self.new_segment()
                del self.buffer[:16+captured]
                segment = self.segments[-1]
                with segment["path"].open("ab") as target:
                    target.write(record)
                segment["bytes"] += len(record)
            self.pending_age()


class Live:
    def __init__(self, store, state, sensor_factory, manifest, interval=5, workers=2, window=30):
        self.store, self.state, self.sensor_factory = store, Path(state), sensor_factory
        self.manifest_path, self.interval = Path(manifest), interval
        self.stop_event = threading.Event()
        self.threads, self.streams, self.spools = [], {}, {}
        self.lock = threading.RLock()
        self.running = False
        self.workers, self.window = workers, window
        self.analysis_workers = []
        self.lifecycle = threading.RLock()
        self.started_at = time.time()

    def status(self):
        readers = sum(thread.is_alive() for thread in self.threads[:-1])
        analyzer = bool(self.threads and self.threads[-1].is_alive())
        sources = set(self.spools)
        failures = [h["source"] for h in self.store.health_records()
                    if (h["source"] in sources or h["source"].startswith("sensor")) and not h.get("expected_failure")
                    and (h.get("analysis_error") or h.get("error") or h.get("state") in ("limited", "error", "retrying"))]
        stale = []
        for source, spool in self.spools.items():
            if not isinstance(spool, Spool):
                continue
            pending_age = spool.pending_age()
            if pending_age is not None and pending_age > 60:
                stale.append(source)
        failures = sorted(set(failures + stale))
        degraded = self.stop_event.is_set() or not analyzer or readers != len(sources) or bool(failures) or any(not t.is_alive() for t in self.analysis_workers)
        return {"state": "stopped" if not self.running else "degraded" if degraded else "running",
                "expected_readers": len(sources), "active_readers": readers, "analysis_thread_alive": analyzer,
                "sources_with_errors": failures, "stale_sources": stale, "analysis_workers": len(self.analysis_workers),
                "processing_mode": "bounded rolling PCAP windows", "window_seconds": self.window}

    def start(self):
        if self.running:
            return
        manifest = json.loads(self.manifest_path.read_text())
        if not manifest.get("complete") or not set(CAPTURE_ROLES).issubset(manifest.get("links", {})):
            raise ValueError("A complete Module 1 manifest with all actor capture links is required")
        self.adapter = GNS3(manifest["server"], self.manifest_path.parent)
        self.adapter.manifest = manifest
        prior = self.store.setting("live") or {}
        self.scope = prior["scope"] if prior.get("enabled") and prior.get("manifest") == str(self.manifest_path.resolve()) else "live-" + uuid.uuid4().hex
        self.stop_event.clear()
        self.started_at = time.time()
        self.store.health("sensor", state="connecting", error=None, analysis_error=None)
        self.spools = {source: Spool(self.state / "live" / self.scope / source, source, self.scope, self.store, window=self.window) for source in CAPTURE_ROLES}
        try:
            archive_processed(self.store, self.state, required=8*1024*1024)
        except BufferError as error:
            # Start the workers so pending captures can drain; never make a full budget a permanent stop.
            self.store.health("sensor", state="limited", error=str(error))
        self.running = True
        self.store.setting("live", {"enabled": True, "scope": self.scope, "manifest": str(self.manifest_path.resolve()), "interval": self.interval})
        self.threads = [threading.Thread(target=self.read, args=(source,), daemon=True) for source in CAPTURE_ROLES]
        self.threads.append(threading.Thread(target=self.analyze, daemon=True))
        for thread in self.threads:
            thread.start()

    def read(self, source):
        failures = 0
        last_health_update = float("-inf")
        while not self.stop_event.is_set():
            stream = None
            try:
                self.store.health(source, state="connecting", error=None, reconnects=failures, scope=self.scope)
                stream = self.adapter.stream(source)
                with self.lock:
                    self.streams[source] = stream
                self.store.health(source, state="waiting_for_packets", error=None)
                self.spools[source].reconnect()
                while not self.stop_event.is_set():
                    data = stream.read1(65536)
                    if not data:
                        raise ConnectionError("GNS3 capture stream ended")
                    while not self.stop_event.is_set():
                        try:
                            self.spools[source].feed(data)
                            break
                        except BufferError as error:
                            self.store.health(source, state="limited", error=str(error), backpressure_at=time.time())
                            data = b""  # Pending complete records remain in the spool buffer.
                            self.stop_event.wait(1)
                    now = time.monotonic()
                    if now-last_health_update >= 1:
                        self.store.health(source, state="receiving", last_received=time.time(), error=None)
                        last_health_update = now
            except BufferError as error:
                failures += 1
                self.store.health(source, state="limited", error=str(error), reconnects=failures)
                if self.stop_event.wait(min(30, 2**min(failures, 5))):
                    break
            except Exception as error:
                if self.stop_event.is_set():
                    break
                failures += 1
                self.store.health(source, state="retrying", error=str(error), reconnects=failures)
                if self.stop_event.wait(min(30, 2**min(failures, 5))):
                    break
            finally:
                if stream:
                    try:
                        stream.close()
                    except OSError:
                        pass
                with self.lock:
                    self.streams.pop(source, None)

    def analyze(self):
        sources = list(self.spools)
        if len(sources) <= 1:
            return self._analyze_sources(sources, "sensor")
        count = min(self.workers, len(sources))
        self.analysis_workers = [threading.Thread(target=self._analyze_sources,
                                args=(sources[i::count], f"sensor:{i}"), daemon=True) for i in range(count)]
        for thread in self.analysis_workers:
            thread.start()
        for thread in self.analysis_workers:
            thread.join()

    def _analyze_sources(self, sources, sensor_name):
        sensor = None
        while not self.stop_event.is_set():
            try:
                if sensor is None:
                    sensor = self.sensor_factory()
                pipeline = Pipeline(self.store, self.state, sensor)
                for source in sources:
                    spool = self.spools[source]
                    if self.stop_event.is_set():
                        break
                    with spool.lock:
                        spool.rotate_due()
                        # The newest snapshot includes the previous segment, so do not analyze
                        # the same old bytes twice in one cycle just to acknowledge their tail.
                        segments = ([s for s in spool.segments if s["bytes"] > 24][-1:] or spool.segments[-1:])
                    for segment in segments:
                        temporary = self.state / ("snapshot-" + source + ".pcap")
                        try:
                            with spool.lock:
                                if all(max(24, spool.processed.get(s["id"], 0)) >= s["bytes"] for s in spool.segments):
                                    continue
                                info = snapshot(segment["path"], temporary)
                                watermark = segment["bytes"]
                                # Previous-window context can reconstruct medical messages split at rotation.
                                index = spool.segments.index(segment)
                                watermarks = {segment["id"]: watermark}
                                if index and info["frames"]:
                                    context, _ = complete_pcap(spool.segments[index-1]["path"].read_bytes())
                                    watermarks[spool.segments[index-1]["id"]] = spool.segments[index-1]["bytes"]
                                    temporary.write_bytes(context + temporary.read_bytes()[24:])
                                    info = complete_pcap(temporary.read_bytes())[1]
                            if not info["frames"]:
                                with spool.lock:
                                    spool.processed[segment["id"]] = info["bytes"]
                                self.store.health(source, state="waiting_for_packets", error=None, analysis_error=None,
                                                  capture_loss="unavailable; no zero-loss claim")
                                continue
                            record = pipeline.import_file(temporary, source, self.scope, segment["id"], boundary=segment["boundary"],
                                                          extra={"spool_bytes": watermark, "rolling_context": bool(index),
                                                                 "context_watermarks": watermarks})
                            with spool.lock:
                                spool.processed.update(watermarks)
                                spool.pending_age(progress=True)
                            packets = record.get("last_packet_time")
                            self.store.health(source, analyzed_frames=record["frames"], analyzed_sha256=record["sha256"],
                                              snapshot_tail_bytes=info["incomplete_tail_bytes"],
                                              processing_mode="bounded rolling PCAP windows",
                                              latest_packet_to_record_seconds=max(0, time.time()-packets) if packets else None)
                        except Exception as error:
                            self.store.health(source, analysis_error=str(error), analysis_failed_at=time.time())
                            if not sensor.connected():
                                raise ConnectionError("Linux sensor SSH disconnected; pending captures are preserved for reconnection") from error
                        finally:
                            temporary.unlink(missing_ok=True)
                archive_processed(self.store, self.state, required=8*1024*1024)
                self.store.health(sensor_name, state="ready", error=None)
                if sensor_name != "sensor":
                    self.store.health("sensor", state="ready", error=None)
            except BufferError as error:
                self.store.health(sensor_name, state="limited", error=str(error))
            except Exception as error:
                if sensor:
                    sensor.close()
                    sensor = None
                self.store.health(sensor_name, state="error", error=str(error))
            self.stop_event.wait(self.interval)
        if sensor:
            sensor.close()

    def stop(self, timeout=210):
        self.stop_event.set()
        with self.lock:
            streams = list(self.streams.values())
        for stream in streams:
            try:
                stream.close()
            except OSError:
                pass
        deadline = time.monotonic()+timeout
        for thread in self.threads:
            thread.join(timeout=max(0, deadline-time.monotonic()))
        if any(thread.is_alive() for thread in self.threads):
            raise RuntimeError("An analysis job is still finishing; restart remains disabled until it exits")
        self.running = False
        self.store.setting("live", {"enabled": False, "scope": getattr(self, "scope", None)})
        for source in self.spools:
            self.store.health(source, state="stopped")
