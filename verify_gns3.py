"""Exercise the running PoC against an explicitly selected GNS3 lab."""
import argparse
import json
import time
from pathlib import Path
from gns3 import private_url, request_json


def dropped_packets(table, source):
    count = 0
    for line in table.splitlines():
        fields = line.split()
        if len(fields) >= 9 and fields[0].isdigit() and fields[2] == "DROP" and fields[7] == source:
            count += int(fields[0])
    return count


def verify(backend, controller, output):
    if backend != "http://127.0.0.1:8877":
        raise ValueError("Verification controls only the local PoC at port 8877")
    controller = private_url(controller)
    report = {"controller": controller, "started": time.time(), "passed": False, "phases": []}

    def get(endpoint):
        return request_json(backend + endpoint, timeout=30)

    def action(name, **values):
        return request_json(backend + "/api/action", {"action": name, **values}, timeout=180)

    def wait_for(check, label, timeout=30):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            state = get("/api/status")
            if state.get("error"):
                raise RuntimeError(state["error"])
            if check(state):
                return state
            time.sleep(0.3)
        raise RuntimeError("Timed out waiting for " + label)

    def record(label, results=None):
        state = get("/api/report")
        report["phases"].append({"phase": label, "results": results, "state": state})
        print("PASS:", label, flush=True)
        return state

    def require_paths(results, workstation, pump, modality=True):
        expected = {"workstation": workstation, "pump": pump, "modality": modality}
        for role, success in expected.items():
            if results[role]["success"] is not success:
                raise AssertionError(f"{role}: expected success={success}, got {results[role]}")

    try:
        state = get("/api/status")
        if state.get("app") != "iomt-live-v1":
            raise ValueError("The selected backend is not the live IoMT PoC")
        if state["mode"] and (state["mode"] != "gns3" or state["project"]["server"] != controller):
            raise ValueError("Stop the other session before testing this GNS3 lab")
        if not state["mode"]:
            action("start-gns3", url=controller)
        action("reset")
        state = get("/api/status")
        if len(state["capture"]) != 3 or any(not c["running"] or c["error"] for c in state["capture"]):
            raise AssertionError("Three healthy GNS3 packet streams are required")
        record("GNS3 nodes and three actual capture streams connected")

        action("normal")
        wait_for(lambda s: len(s["monitor"]["assets"]) >= 5 and
                 any("DICOM" in a["protocols"] for a in s["monitor"]["assets"]) and
                 any("HL7/MLLP" in a["protocols"] for a in s["monitor"]["assets"]),
                 "live DICOM and HL7 evidence")
        baseline = action("verify")["result"]
        require_paths(baseline, True, True)
        record("Normal clinical traffic succeeds and is parsed", baseline)

        action("recon")
        wait_for(lambda s: s["policy"]["workstation"] == "quarantined", "gateway quarantine")
        quarantined = action("verify")["result"]
        require_paths(quarantined, False, True)
        state = get("/api/status")
        workstation = next(a for a in state["monitor"]["assets"] if a["role"] == "workstation")
        if workstation["peakRisk"] != 85 or dropped_packets(state["endpoints"]["gateway"]["firewall"], "10.77.10.10") == 0:
            raise AssertionError("Measured risk 85 and a nonzero workstation DROP counter are required")
        record("Workstation blocked by gateway; medical paths preserved", quarantined)

        action("anomaly")
        wait_for(lambda s: s["policy"]["pump"] == "restricted", "pump restriction")
        restricted = action("verify")["result"]
        require_paths(restricted, False, True)
        blocked = action("anomaly")["result"]
        if any(r["success"] for r in blocked):
            raise AssertionError("Restricted pump must not connect to PACS")
        state = get("/api/status")
        if dropped_packets(state["endpoints"]["gateway"]["firewall"], "10.77.20.20") == 0:
            raise AssertionError("A nonzero pump DROP counter is required")
        record("Pump-to-PACS blocked while HL7 telemetry succeeds", {"clinical": restricted, "unexpected": blocked})

        action("approve", reviewer="Automated lab verification")
        isolated = action("verify")["result"]
        require_paths(isolated, False, False)
        record("Explicit lab approval isolates pump; imaging still succeeds", isolated)

        action("reset")
        restored = action("verify")["result"]
        require_paths(restored, True, True)
        record("Reset restores all three clinical paths", restored)
        report["passed"] = True
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        report["finished"] = time.time()
        Path(output).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print("Measured report:", output, flush=True)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--gns3", required=True)
    parser.add_argument("--backend", default="http://127.0.0.1:8877")
    parser.add_argument("--output", default=str(Path(__file__).with_name("gns3-verification-report.json")))
    args = parser.parse_args()
    verify(args.backend, args.gns3, args.output)
