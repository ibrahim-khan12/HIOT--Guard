"""Exercise the extended Module 2 parser with saved Zeek logs and local TShark.

This is a local compatibility check, not a fresh pinned Linux-sensor acceptance.
"""
import _bootstrap
import argparse
import csv
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from module2.parsing import normalize
from module2.sensor import FIELDS
from module2.store import Store as MonitoringStore
from module2.discovery import snapshot
from module3.input import stage
from module3.store import Store


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--reference-db", default="runs/module3-evaluation/offline-final/reference-monitoring.sqlite3")
    p.add_argument("--scope", default="acceptance-1792340111388501600")
    p.add_argument("--output", default="runs/module3-evaluation/mac")
    p.add_argument("--tshark", default=r"C:\Program Files\Wireshark\tshark.exe")
    args = p.parse_args()
    out = Path(args.output); out.mkdir(parents=True, exist_ok=True)
    monitor = MonitoringStore(args.reference_db)
    target = MonitoringStore(out/"monitoring.sqlite3")
    store = Store(out/"inventory.sqlite3")
    results = []
    try:
        for cap in monitor.status(args.scope)["captures"]:
            if cap["observation_source"] not in ("pump", "modality"):
                continue
            root = out/cap["observation_source"]; root.mkdir(exist_ok=True)
            original = Path(cap["raw_capture"])
            for name in ("input.pcap", "conn.log"):
                shutil.copyfile(original.parent/name, root/name)
            cmd = [args.tshark, "-n", "-2", "-r", str(root/"input.pcap"), "-o", "tcp.desegment_tcp_streams:TRUE", "-d", "tcp.port==11112,dicom",
                   "-T", "fields", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=f"]
            for field in FIELDS: cmd.extend(["-e", field])
            with (root/"packets.tsv").open("wb") as stream:
                subprocess.run(cmd, stdout=stream, stderr=subprocess.PIPE, check=True)
            flows, issues, reference = normalize(root, cap["capture_id"], cap["observation_source"], "mac-saved-reference")
            with (root/"packets.tsv").open() as stream:
                rows = {int(r[0]): dict(zip(FIELDS, r)) for r in csv.reader(stream, delimiter="\t")}
            evidence = [e for f in flows for e in f["link_layer_evidence"]]
            valid = all(rows[e["frame"]]["eth.src" if e["ethernet_direction"] == "source" else "eth.dst"].lower() == e["mac"] for e in evidence)
            manifest = {**cap, "scope": "mac-saved-reference", "raw_capture": str((root/"input.pcap").resolve()), "raw_retained": True}
            target.ingest(manifest, flows, issues)
            results.append({"source": cap["observation_source"], "link_evidence_groups": len(evidence), "all_mac_frames_match": valid,
                            "normalization_issues": issues, "reference": reference,
                            "sha256": hashlib.sha256((root/"input.pcap").read_bytes()).hexdigest()})
        with stage(snapshot(target, "mac-saved-reference")) as (db, header):
            store.apply(db, header)
        assets = store.assets(limit=-1)["records"]
        report = {"checks": results, "assets_with_mac_observations": sum(bool(a["mac_observations"]) for a in assets),
                  "tshark": subprocess.check_output([args.tshark, "--version"], text=True).splitlines()[0],
                  "limitation": "Saved pinned Zeek connection logs plus current local TShark; Linux sensor was not restarted",
                  "passed": len(results)==2 and all(r["link_evidence_groups"]>0 and r["all_mac_frames_match"] and not r["normalization_issues"] for r in results)}
        (out/"report.json").write_text(json.dumps(report, indent=2))
        print(json.dumps(report, indent=2))
        if not report["passed"]: raise SystemExit(1)
    finally:
        monitor.close(); target.close()


if __name__ == "__main__": main()
