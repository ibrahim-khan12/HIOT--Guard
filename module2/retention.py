"""Expire only service-owned live PCAPs, keeping hashes and analytical history."""
from pathlib import Path


def enforce_budget(store, state, active_scope, budget=256*1024*1024):
    state = Path(state).resolve()

    def size():
        return sum(p.stat().st_size for folder in (state/"live", state/"artifacts") if folder.exists()
                   for p in folder.rglob("*.pcap") if p.resolve().is_relative_to(folder.resolve()))

    total = size()
    if total <= budget:
        return total
    records = store.status()["captures"]
    scopes = sorted({r["scope"] for r in records if r["scope"].startswith("live-") and r["scope"] != active_scope},
                    key=lambda scope: min(r["processed_at"] for r in records if r["scope"] == scope))
    for scope in scopes:
        for capture in records:
            if capture["scope"] == scope:
                store.expire_raw(capture["capture_id"])
        directory = (state / "live" / scope).resolve()
        if not directory.is_relative_to(state / "live"):
            raise ValueError("Unsafe retention scope")
        if directory.exists():
            for path in directory.rglob("*.pcap"):
                if path.resolve().is_relative_to(directory):
                    path.unlink()
        total = size()
        if total <= budget:
            return total
    raise BufferError("Raw PCAP budget reached; active/unprocessed or offline evidence was preserved")
