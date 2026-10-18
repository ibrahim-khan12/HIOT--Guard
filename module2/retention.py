"""Expire only service-owned live PCAPs, keeping hashes and analytical history."""
from pathlib import Path
import hashlib
import os
import shutil
import threading
import time
import json

from .parsing import identity
from .pcap import complete_pcap

STORAGE_LOCK = threading.RLock()
RAW_BUDGET = 256 * 1024 * 1024
ARCHIVE_BUDGET = 1024 * 1024 * 1024


def archive_processed(store, state, required=0, budget=RAW_BUDGET, archive_budget=ARCHIVE_BUDGET):
    """Move committed evidence to a verified archive, never evict pending spool bytes."""
    state = Path(state).resolve()
    with STORAGE_LOCK:
        total = raw_size(state)
        if total + required <= budget:
            return total
        archive = state / "archive" / "raw"
        archive_size = sum(p.stat().st_size for p in archive.rglob("*.pcap")) if archive.exists() else 0
        captures = sorted(store.status()["captures"], key=lambda c: c.get("processed_at", 0))
        for record in captures:
            if not record.get("raw_retained") or not record["scope"].startswith("live-"):
                continue
            raw = Path(record["raw_capture"]).resolve()
            if not raw.is_relative_to(state / "artifacts") or raw.name != "input.pcap" or not raw.exists():
                continue
            size = raw.stat().st_size
            if archive_size + size > archive_budget:
                continue
            destination = archive / record["capture_id"] / record["sha256"] / "input.pcap"
            if not destination.resolve().is_relative_to(archive):
                raise ValueError("Unsafe raw archive path")
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_suffix(".copying")
            try:
                shutil.copyfile(raw, temporary)
                with temporary.open("rb") as stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                if digest != record["sha256"]:
                    raise ValueError("Raw archive hash mismatch; original preserved")
                os.replace(temporary, destination)
                # Publish the new reference before removing the old copy.
                with store.lock, store.connect() as db:
                    current = store.capture(record["capture_id"])
                    if Path(current["raw_capture"]).resolve() != raw:
                        continue
                    current.update(raw_capture=str(destination), raw_archived=True, archived_at=time.time())
                    db.execute("UPDATE captures SET data=? WHERE id=?", (json.dumps(current), record["capture_id"]))
                (destination.parent / "capture.json").write_text(json.dumps(current, indent=2))
                raw.unlink()
                archive_size += size
                total -= size
                if total + required <= budget:
                    return total
            finally:
                temporary.unlink(missing_ok=True)
        raise BufferError("Raw PCAP budget reached; pending evidence preserved. Archive capacity or processing must recover before retry.")


def raw_size(state):
    total = 0
    state = Path(state).resolve()
    for folder in (state/"live", state/"artifacts"):
        if not folder.exists():
            continue
        for path in folder.rglob("*.pcap"):
            try:
                if path.resolve().is_relative_to(folder.resolve()):
                    total += path.stat().st_size
            except FileNotFoundError:
                # Another source can retire a fully analyzed segment during this scan.
                continue
    return total


def enforce_budget(store, state, active_scope, budget=256*1024*1024):
    state = Path(state).resolve()

    def size():
        return raw_size(state)

    total = size()
    if total <= budget:
        return total
    records = store.status()["captures"]
    scopes = sorted({r["scope"] for r in records if r["scope"].startswith("live-") and r["scope"] != active_scope},
                    key=lambda scope: min(r["processed_at"] for r in records if r["scope"] == scope))
    for scope in scopes:
        directory = (state / "live" / scope).resolve()
        if not directory.is_relative_to(state / "live"):
            raise ValueError("Unsafe retention scope")
        known = {r["capture_id"]: r for r in records if r["scope"] == scope}
        complete = True
        for path in directory.glob("*/segment-*.pcap"):
            try:
                number = int(path.stem.split("-")[-1])
                record = known.get(identity(scope, path.parent.name, number))
                facts = complete_pcap(path.read_bytes())[1]
                if not facts["frames"]:
                    continue
                if not record or record.get("sha256") != facts["sha256"]:
                    complete = False
                    break
            except ValueError:
                complete = False
                break
        if not complete:
            continue
        for capture in records:
            if capture["scope"] == scope:
                store.expire_raw(capture["capture_id"])
        if directory.exists():
            for path in directory.rglob("*.pcap"):
                if path.resolve().is_relative_to(directory):
                    path.unlink()
        total = size()
        if total <= budget:
            return total
    raise BufferError("Raw PCAP budget reached; active/unprocessed or offline evidence was preserved")
