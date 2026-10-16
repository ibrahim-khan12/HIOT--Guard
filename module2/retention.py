"""Expire only service-owned live PCAPs, keeping hashes and analytical history."""
from pathlib import Path

from .parsing import identity
from .pcap import complete_pcap


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
