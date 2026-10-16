"""Sample a running monitoring service and its isolated analysis containers."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import time
import urllib.request

from module2.sensor import Sensor
from config import NORMAL_ROLES


def status():
    with urllib.request.urlopen("http://127.0.0.1:8878/api/status", timeout=30) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=int, default=120)
    parser.add_argument("--sensor-host", default="192.168.209.142")
    parser.add_argument("--state", default="runs/module2")
    args = parser.parse_args()
    if not 10 <= args.seconds <= 3600:
        parser.error("seconds must be 10..3600")
    initial = status()
    report = {"started": time.time(), "scope": initial["scope"], "samples": [], "passed": False}
    output = Path(args.state) / "service-measurements.json"
    sensor = Sensor(args.sensor_host, args.state)
    try:
        report["vm_memory_at_start"] = sensor.run("free -b")
        while time.time()-report["started"] < args.seconds:
            state = status()
            process = subprocess.run(["powershell", "-NoProfile", "-Command",
                                      f"Get-Process -Id {int(state['pid'])} | Select-Object CPU,WorkingSet64,PeakWorkingSet64 | ConvertTo-Json -Compress"],
                                     capture_output=True, text=True, check=True)
            ids = sensor.run("docker ps -q --filter label=hiot.module=2").split()
            ids = [i for i in ids if re.fullmatch(r"[a-f0-9]+", i)]
            docker = []
            if ids:
                try:
                    raw = sensor.run("docker stats --no-stream --format '{{json .}}' " + " ".join(ids))
                    docker = [json.loads(line) for line in raw.splitlines() if line.strip()]
                except RuntimeError:
                    pass
            scope_captures = [c for c in state["captures"] if c["scope"] == report["scope"]]
            sample = {"at": time.time(), "service": json.loads(process.stdout), "containers": docker,
                      "collector": state.get("collector"),
                      "canonical_flows_all_scopes": state["canonical_flows"],
                      "latest_analysis": max((c["processed_at"] for c in scope_captures), default=0),
                      "live_sources_analyzed": len({c["observation_source"] for c in scope_captures}),
                      "unexpected_errors": [h for h in state["health"] if (h.get("analysis_error") or h.get("error")) and not h.get("expected_failure")]}
            sample["source_analysis_age_seconds"] = {h["source"]: round(sample["at"]-h["analyzed_at"], 3)
                                                     for h in state["health"] if h["source"] in NORMAL_ROLES and h.get("analyzed_at")}
            report["samples"].append(sample)
            output.write_text(json.dumps(report, indent=2))
            print(f"sample {len(report['samples'])}: {sample['live_sources_analyzed']} sources; containers sampled {len(docker)}", flush=True)
            time.sleep(5)
        report.update(finished=time.time(), passed=initial["live"] and status()["live"] and
                      max(s["latest_analysis"] for s in report["samples"]) > report["samples"][0]["latest_analysis"] and
                      not any(s["unexpected_errors"] for s in report["samples"]) and
                      all(s["collector"] and s["collector"]["state"] == "running" for s in report["samples"]) and
                      report["samples"][-1]["live_sources_analyzed"] >= len(NORMAL_ROLES))
        output.write_text(json.dumps(report, indent=2))
        print(str(output.resolve()), flush=True)
        if not report["passed"]:
            raise SystemExit(1)
    finally:
        sensor.close()


if __name__ == "__main__":
    main()
