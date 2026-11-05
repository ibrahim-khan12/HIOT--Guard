"""Independent saved-byte inventory reference; never starts a VM or sensor."""
import _bootstrap
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess

from config import registry
from module2.discovery import snapshot
from module2.store import Store as MonitoringStore
from module3.input import stage, encode, identity
from module3.store import Store


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--monitoring-db", required=True)
    p.add_argument("--scope", required=True)
    p.add_argument("--output", default="runs/module3-evaluation/offline")
    p.add_argument("--tshark", default=r"C:\Program Files\Wireshark\tshark.exe")
    p.add_argument("--expected-tcp", type=int)
    args = p.parse_args()
    root = Path(args.output); root.mkdir(parents=True, exist_ok=True)
    copied = root/"reference-monitoring.sqlite3"
    # SQLite backup reads a consistent source without migrating the original DB.
    with sqlite3.connect(Path(args.monitoring_db).resolve().as_uri()+"?mode=ro", uri=True) as src, sqlite3.connect(copied) as dst:
        src.backup(dst)
    monitor = MonitoringStore(copied)
    # A read-only historical source may predate persistent source IDs. Give its
    # evaluation copy a deterministic identity so reruns do not duplicate assets.
    monitor.setting("discovery_source_id", "saved:"+identity(str(Path(args.monitoring_db).resolve())))
    store = Store(root/"inventory.sqlite3", registry("gns3"))
    report = {"scope": args.scope, "dataset": [], "checks": [], "reference": "Independent local TShark fields from retained packet bytes"}
    def check(name, passed, **facts):
        report["checks"].append({"name": name, "passed": bool(passed), **facts})
    try:
        report["tshark_version"] = subprocess.check_output([args.tshark, "--version"], text=True).splitlines()[0]
        lines = list(snapshot(monitor, args.scope))
        (root/"snapshot.jsonl").write_bytes(b"".join(lines))
        with stage(lines) as (db, header):
            store.apply(db, header)
        assets = store.assets(limit=-1)["records"]
        captures = monitor.status(args.scope)["captures"]
        frames, transmitted, addresses, reference_pairs = {}, set(), set(), set()
        fields = ["frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "eth.src", "eth.dst"]
        for cap in captures:
            path = Path(cap["raw_capture"])
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            check("Retained capture hash", digest == cap["sha256"], capture_id=cap["capture_id"])
            cmd = [args.tshark, "-n", "-r", str(path), "-T", "fields"]
            for field in fields: cmd.extend(["-e", field])
            raw = subprocess.check_output(cmd, text=True, stderr=subprocess.PIPE)
            byframe = {}
            for line in raw.splitlines():
                row = dict(zip(fields, line.split("\t")))
                byframe[int(row["frame.number"])] = row
                src, dst = row["ip.src"] or row["ipv6.src"], row["ip.dst"] or row["ipv6.dst"]
                try:
                    src, dst = str(ipaddress.ip_address(src)), str(ipaddress.ip_address(dst))
                except ValueError:
                    continue
                transmitted.add(src); addresses.update((src, dst))
                transport = "tcp" if row["tcp.srcport"] else "udp" if row["udp.srcport"] else "other"
                sport, dport = row.get(transport+".srcport"), row.get(transport+".dstport")
                reference_pairs.add((src, dst, transport, sport or None, dport or None))
            frames[cap["capture_id"]] = byframe
            report["dataset"].append({"capture_id": cap["capture_id"], "sha256": digest, "frames": len(byframe), "source": cap["observation_source"]})
        observed = {a["ip"] for a in assets}
        check("One inventory entry per source/scope/address", len(assets) == len(observed), entries=len(assets), distinct_addresses=len(observed))
        predicted_tx = {a["ip"] for a in assets if a["presence"] == "observed_transmitting"}
        check("Exact endpoint address agreement", observed == addresses, discovered=sorted(observed), reference=sorted(addresses))
        check("Exact transmitting presence agreement", predicted_tx == transmitted, discovered=sorted(predicted_tx), reference=sorted(transmitted))
        report["endpoint_precision"] = len(observed & addresses)/len(observed) if observed else 0
        report["endpoint_recall"] = len(observed & addresses)/len(addresses) if addresses else 0
        bad_evidence, missing_pairs, evidence_count = [], [], 0
        tcp = 0
        for f in monitor.iter_flows(scope=args.scope):
            tcp += f["transport"] == "tcp"
            if f["transport"] in ("tcp", "udp"):
                pair = (f["source_ip"], f["destination_ip"], f["transport"], str(f["source_port"]), str(f["destination_port"]))
                if pair not in reference_pairs: missing_pairs.append(pair)
            for e in f.get("evidence", []) + f.get("link_layer_evidence", []):
                evidence_count += 1
                frame = frames.get(e["capture_id"], {}).get(e["frame"])
                if not frame or abs(float(frame["frame.time_epoch"])-e["timestamp"])>.001:
                    bad_evidence.append(e)
        check("Peer and port tuples backed by saved packets", not missing_pairs, missing=missing_pairs)
        check("Evidence frames and timestamps backed by saved packets", not bad_evidence, checked=evidence_count, invalid=len(bad_evidence))
        before = store.status()
        with stage(lines) as (db, header): result = store.apply(db, header)
        check("Repeated snapshot is idempotent", not result["changed_flows"] and store.status()["events"] == before["events"])
        check("Restart preserves inventory", Store(root/"inventory.sqlite3", registry("gns3")).status()["asset_count"] == len(assets))
        if args.expected_tcp is not None:
            check("Historical TCP connection reference", tcp == args.expected_tcp, actual=tcp, expected=args.expected_tcp)
        report["unique_ip_baseline"] = {"addresses": len(addresses), "limitations": ["No source/transmission distinction", "No registry separation", "No capture-linked profile", "No correction or replay history"]}
        report["mac_validation"] = "Historical snapshots lack MAC fields; new parser MAC extraction is verified separately on saved packet TSV/Zeek artifacts"
        with (root/"inventory.jsonl").open("wb") as out:
            for raw in store.export(): out.write(raw)
        report["passed"] = all(c["passed"] for c in report["checks"])
        (root/"report.json").write_text(json.dumps(report, indent=2))
        print(json.dumps(report, indent=2))
    finally:
        monitor.close()
    if not report["passed"]: raise SystemExit(1)


if __name__ == "__main__": main()
