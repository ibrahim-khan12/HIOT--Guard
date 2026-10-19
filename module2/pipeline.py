"""Offline and live-snapshot imports share the same verified processing path."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import time

from . import SCHEMA_VERSION
from .parsing import identity, normalize
from .pcap import complete_pcap
from .retention import archive_processed, STORAGE_LOCK


class Pipeline:
    def __init__(self, store, state, sensor):
        self.store, self.state, self.sensor = store, Path(state), sensor

    def import_file(self, path, source, scope, logical_id=None, force=False, boundary=False, extra=None):
        started = time.time()
        clock_started = time.monotonic()
        stages = {}
        path = Path(path)
        if not source or len(source) > 100 or not scope or len(scope) > 150:
            raise ValueError("A bounded observation source and scope are required")
        try:
            if path.stat().st_size > 32 * 1024 * 1024:
                raise ValueError("Import exceeds the 32 MiB per-capture bound")
            data, facts = complete_pcap(path.read_bytes())
            capture_id = logical_id or identity(scope, source, facts["sha256"])
            prior = self.store.capture(capture_id)
            if not force and prior and prior["sha256"] == facts["sha256"] and all(prior.get(k) == v for k, v in (extra or {}).items()):
                return {**prior, "cached": True}
            folder = self.state / "artifacts" / capture_id
            folder.mkdir(parents=True, exist_ok=True)
            revision = folder / facts["sha256"]
            copied = revision / "input.pcap"
            self.store.health(source, state="analyzing", capture_id=capture_id, analysis_started=started)
            # Keep the last committed bytes intact until the new analysis succeeds.
            with TemporaryDirectory(prefix="analysis-", dir=folder) as temporary:
                staging = Path(temporary)
                staged_capture = staging / "input.pcap"
                with STORAGE_LOCK:
                    phase = time.monotonic()
                    archive_processed(self.store, self.state, required=len(data))
                    staged_capture.write_bytes(data)
                    stages["reservation_seconds"] = round(time.monotonic()-phase, 4)
                self.store.health(source, analysis_phase="sensor")
                tools = self.sensor.analyze(staged_capture, staging)
                self.store.health(source, analysis_phase="normalize")
                phase = time.monotonic()
                flows, issues, reference = normalize(staging, capture_id, source, scope)
                stages["normalize_seconds"] = round(time.monotonic()-phase, 4)
                (staging / "packets.tsv").unlink(missing_ok=True)
                revision.mkdir(exist_ok=True)
                for artifact in staging.iterdir():
                    artifact.replace(revision / artifact.name)
            if boundary:
                issues.append({"kind": "rotation_boundary", "detail": "Connections may start midstream; without SYN evidence, only exact complete packet replays can correlate"})
            if not flows and facts["frames"]:
                issues.append({"kind": "no_supported_connections", "detail": "Captured packets yielded no Zeek connection records"})
            record = {"schema_version": SCHEMA_VERSION, "capture_id": capture_id, "scope": scope,
                      "observation_source": source, "input_reference": str(path.resolve()), "raw_capture": str(copied.resolve()),
                      "raw_retained": True, "processed_at": time.time(), **facts, **tools, "reference": reference,
                      "duration_seconds": round(time.monotonic()-clock_started, 4), "_processing_start": clock_started,
                      "issue_count": len(issues), "stages": stages, **(extra or {})}
            self.store.health(source, analysis_phase="persist")
            phase = time.monotonic()
            with STORAGE_LOCK:
                prior = self.store.capture(capture_id)
                self.store.ingest(record, flows, issues)
            stages["persist_seconds"] = round(time.monotonic()-phase, 4)
            (revision / "capture.json").write_text(json.dumps(record, indent=2))
            (revision / "reference.json").write_text(json.dumps(reference, indent=2))
            if prior and prior["raw_capture"] != str(copied.resolve()):
                old_raw = Path(prior["raw_capture"]).resolve()
                archived = (self.state / "archive" / "raw" / capture_id).resolve()
                if (old_raw.is_relative_to(folder.resolve()) or old_raw.is_relative_to(archived)) and old_raw.name == "input.pcap":
                    old_raw.unlink(missing_ok=True)
            self.store.health(source, state="analyzed", capture_id=capture_id, analyzed_at=time.time(), analysis_error=None, analysis_phase="complete", stages=stages,
                              error=None, analysis_seconds=record["duration_seconds"],
                              capture_loss="unavailable; no zero-loss claim", snapshot_bytes=facts["bytes"])
            return record
        except Exception as error:
            self.store.health(source, state="error", error=str(error), failed_at=time.time())
            raise
