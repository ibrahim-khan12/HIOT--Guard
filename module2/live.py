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
from .retention import enforce_budget


class Spool:
    def __init__(self, root, source, scope, store, limit=4*1024*1024):
        self.root, self.source, self.scope, self.store = Path(root), source, scope, store
        self.root.mkdir(parents=True, exist_ok=True)
        self.limit, self.lock = limit, threading.RLock()
        self.buffer, self.header, self.segments = bytearray(), None, []
        self.processed, self.counter = set(), 0
        for path in sorted(self.root.glob("segment-*.pcap")):
            number = int(path.stem.split("-")[-1])
            self.counter = max(self.counter, number)
            self.segments.append({"id": identity(scope, source, number), "path": path,
                                  "boundary": number > 1, "bytes": path.stat().st_size})
        known = {c["capture_id"] for c in store.status()["captures"]}
        self.processed.update(s["id"] for s in self.segments if s["id"] in known)

    def new_segment(self):
        if len(self.segments) >= 2:
            old = self.segments[0]
            if old["id"] not in self.processed:
                raise BufferError("Analysis cannot keep up with the two-segment raw retention budget")
            self.store.expire_raw(old["id"])
            old["path"].unlink(missing_ok=True)
            self.segments.pop(0)
        self.counter += 1
        path = self.root / f"segment-{self.counter:06d}.pcap"
        path.write_bytes(self.header)
        self.segments.append({"id": identity(self.scope, self.source, self.counter), "path": path,
                              "boundary": self.counter > 1, "bytes": 24})

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
                del self.buffer[:16+captured]
                if self.segments[-1]["bytes"] + len(record) > self.limit:
                    self.new_segment()
                segment = self.segments[-1]
                with segment["path"].open("ab") as target:
                    target.write(record)
                segment["bytes"] += len(record)


class Live:
    def __init__(self, store, state, sensor_factory, manifest, interval=20):
        self.store, self.state, self.sensor_factory = store, Path(state), sensor_factory
        self.manifest_path, self.interval = Path(manifest), interval
        self.stop_event = threading.Event()
        self.threads, self.streams, self.spools = [], {}, {}
        self.lock = threading.RLock()
        self.running = False

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
        self.spools = {source: Spool(self.state / "live" / self.scope / source, source, self.scope, self.store) for source in CAPTURE_ROLES}
        enforce_budget(self.store, self.state, self.scope)
        self.running = True
        self.store.setting("live", {"enabled": True, "scope": self.scope, "manifest": str(self.manifest_path.resolve()), "interval": self.interval})
        self.threads = [threading.Thread(target=self.read, args=(source,), daemon=True) for source in CAPTURE_ROLES]
        self.threads.append(threading.Thread(target=self.analyze, daemon=True))
        for thread in self.threads:
            thread.start()

    def read(self, source):
        failures = 0
        while not self.stop_event.is_set():
            stream = None
            try:
                self.store.health(source, state="connecting", error=None, reconnects=failures)
                stream = self.adapter.stream(source)
                with self.lock:
                    self.streams[source] = stream
                self.store.health(source, state="waiting_for_packets", error=None)
                self.spools[source].reconnect()
                while not self.stop_event.is_set():
                    data = stream.read1(65536)
                    if not data:
                        raise ConnectionError("GNS3 capture stream ended")
                    self.spools[source].feed(data)
                    self.store.health(source, state="receiving", last_received=time.time(), error=None)
            except BufferError as error:
                self.store.health(source, state="limited", error=str(error))
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
        while not self.stop_event.is_set():
            sensor = None
            try:
                sensor = self.sensor_factory()
                pipeline = Pipeline(self.store, self.state, sensor)
                for source, spool in self.spools.items():
                    if self.stop_event.is_set():
                        break
                    with spool.lock:
                        segments = list(spool.segments)
                    for segment in segments:
                        temporary = self.state / ("snapshot-" + source + ".pcap")
                        try:
                            with spool.lock:
                                info = snapshot(segment["path"], temporary)
                            if not info["frames"]:
                                continue
                            record = pipeline.import_file(temporary, source, self.scope, segment["id"], boundary=segment["boundary"])
                            with spool.lock:
                                spool.processed.add(segment["id"])
                            self.store.health(source, analyzed_frames=record["frames"], analyzed_sha256=record["sha256"],
                                              snapshot_tail_bytes=info["incomplete_tail_bytes"],
                                              processing_mode="periodic cumulative PCAP snapshot")
                        except Exception as error:
                            self.store.health(source, analysis_error=str(error), analysis_failed_at=time.time())
                        finally:
                            temporary.unlink(missing_ok=True)
                enforce_budget(self.store, self.state, self.scope)
            except BufferError as error:
                self.store.health("sensor", state="limited", error=str(error))
                self.stop_event.set()
                with self.lock:
                    limited_streams = list(self.streams.values())
                for stream in limited_streams:
                    try:
                        stream.close()
                    except OSError:
                        pass
            except Exception as error:
                self.store.health("sensor", state="error", error=str(error))
            finally:
                if sensor:
                    sensor.close()
            self.stop_event.wait(self.interval)

    def stop(self):
        self.stop_event.set()
        with self.lock:
            streams = list(self.streams.values())
        for stream in streams:
            try:
                stream.close()
            except OSError:
                pass
        for thread in self.threads:
            thread.join(timeout=5)
        if any(thread.is_alive() for thread in self.threads):
            raise RuntimeError("An analysis job is still finishing; restart remains disabled until it exits")
        self.running = False
        self.store.setting("live", {"enabled": False, "scope": getattr(self, "scope", None)})
        for source in self.spools:
            self.store.health(source, state="stopped")
