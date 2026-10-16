"""Offline and live-snapshot imports share the same verified processing path."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import time

from . import SCHEMA_VERSION
from .parsing import identity, normalize
from .pcap import complete_pcap
from .retention import raw_size


class Pipeline:
    def __init__(self, store, state, sensor):
        self.store, self.state, self.sensor = store, Path(state), sensor

    def import_file(self, path, source, scope, logical_id=None, force=False, boundary=False):
        started = time.time()
        path = Path(path)
        if not source or len(source) > 100 or not scope or len(scope) > 150:
            raise ValueError("A bounded observation source and scope are required")
        try:
            if path.stat().st_size > 32 * 1024 * 1024:
                raise ValueError("Import exceeds the 32 MiB per-capture bound")
            data, facts = complete_pcap(path.read_bytes())
            capture_id = logical_id or identity(scope, source, facts["sha256"])
            prior = next((c for c in self.store.status()["captures"] if c["capture_id"] == capture_id), None)
            if not force and prior and prior["sha256"] == facts["sha256"]:
                return {**prior, "cached": True}
            folder = self.state / "artifacts" / capture_id
            folder.mkdir(parents=True, exist_ok=True)
            revision = folder / facts["sha256"]
            copied = revision / "input.pcap"
            disk_bytes = raw_size(self.state)
            replaced = copied.stat().st_size if copied.exists() else 0
            if disk_bytes-replaced+len(data) > 256*1024*1024:
                raise BufferError("Raw PCAP budget exceeded; existing evidence was preserved")
            self.store.health(source, state="analyzing", capture_id=capture_id, analysis_started=started)
            # Keep the last committed bytes intact until the new analysis succeeds.
            with TemporaryDirectory(prefix="analysis-", dir=folder) as temporary:
                staging = Path(temporary)
                staged_capture = staging / "input.pcap"
                staged_capture.write_bytes(data)
                tools = self.sensor.analyze(staged_capture, staging)
                flows, issues, reference = normalize(staging, capture_id, source, scope)
                (staging / "packets.tsv").unlink(missing_ok=True)
                revision.mkdir(exist_ok=True)
                for artifact in staging.iterdir():
                    artifact.replace(revision / artifact.name)
            if boundary:
                issues.append({"kind": "rotation_boundary", "detail": "Connections may start midstream; missing SYNs are not cross-link correlated"})
            if not flows and facts["frames"]:
                issues.append({"kind": "no_supported_connections", "detail": "Captured packets yielded no Zeek connection records"})
            record = {"schema_version": SCHEMA_VERSION, "capture_id": capture_id, "scope": scope,
                      "observation_source": source, "input_reference": str(path.resolve()), "raw_capture": str(copied.resolve()),
                      "raw_retained": True, "processed_at": time.time(), **facts, **tools, "reference": reference,
                      "duration_seconds": round(time.time()-started, 4), "issue_count": len(issues)}
            self.store.ingest(record, flows, issues)
            (revision / "capture.json").write_text(json.dumps(record, indent=2))
            (revision / "reference.json").write_text(json.dumps(reference, indent=2))
            if prior and prior["raw_capture"] != str(copied.resolve()):
                old_raw = Path(prior["raw_capture"]).resolve()
                if old_raw.is_relative_to(folder.resolve()) and old_raw.name == "input.pcap":
                    old_raw.unlink(missing_ok=True)
            self.store.health(source, state="analyzed", capture_id=capture_id, analyzed_at=time.time(), analysis_error=None,
                              error=None, analysis_seconds=record["duration_seconds"],
                              capture_loss="unavailable; no zero-loss claim", snapshot_bytes=facts["bytes"])
            return record
        except Exception as error:
            self.store.health(source, state="error", error=str(error), failed_at=time.time())
            raise
