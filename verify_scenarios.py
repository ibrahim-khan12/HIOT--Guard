"""Run repeatable scenario acceptance against connected Module 1 and Module 2 consoles."""
import argparse
import json
from pathlib import Path
import time
import uuid

from gns3 import request_json
from module2.scenario_evidence import evaluate
from scenario_profile import PROFILE, SCENARIOS


def verify(port, state, output, repeats, keys):
    base = f"http://127.0.0.1:{port}"
    output.mkdir(parents=True, exist_ok=True)
    report = {"runs": [], "control_checks": {}}

    def write():
        (output / "summary.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    def action(name, **args):
        return request_json(base + "/api/action", {"action": name, **args}, timeout=60)

    def status():
        return request_json(base + "/api/status", timeout=20)

    def start(key, token=None):
        return action("run-scenario", scenario_id=key, request_id=token or uuid.uuid4().hex)

    def await_finished(run):
        deadline = time.monotonic() + 70
        while time.monotonic() < deadline:
            current = status()["scenarios"]
            latest = current["latest"]
            if latest and latest["run_id"] == run["run_id"] and not current["active"]:
                return latest
            time.sleep(0.6)
        raise TimeoutError(f"Scenario {run['run_id']} did not finish")

    def rejected(key, phrase):
        try:
            start(key)
        except RuntimeError as error:
            if phrase in str(error):
                return True
            raise
        raise AssertionError(f"Unexpected acceptance for {key}")

    if status().get("project", {}).get("profile") != PROFILE:
        raise RuntimeError("Connect the GNS3 scenario project and start normal traffic and Module 2 first")
    try:
        report["control_checks"]["unsupported_id"] = rejected("unlisted", "listed scenario")
        token = uuid.uuid4().hex
        run = start("udp-single", token)
        report["control_checks"]["duplicate_request"] = start("udp-single", token)["run_id"] == run["run_id"]
        report["control_checks"]["concurrent_request"] = rejected("udp-dual", "current scenario")
        # Cancel during the planned baseline, before the active burst.
        time.sleep(4.5)
        action("cancel-scenario")
        cancel = await_finished(run)
        report["cancelled_run"] = cancel
        report["control_checks"]["cancellation"] = cancel["status"] == "cancelled"
        report["control_checks"]["normal_traffic_continues"] = all(
            status().get("endpoints", {}).get(role, {}).get("running")
            for role in ("workstation", "pump", "modality"))
        write()
        for _ in range(repeats):
            for key in keys:
                run = await_finished(start(key))
                run_id = run["run_id"]
                (output / (run_id + ".run.json")).write_text(json.dumps(run, indent=2), encoding="utf-8")
                raw = evaluate(run)
                (output / (run_id + ".module1.json")).write_text(json.dumps(raw, indent=2), encoding="utf-8")
                item = {"id": run_id, "scenario": key, "status": run["status"], "raw_passed": raw["passed"]}
                report["runs"].append(item)
                write()
                print(json.dumps(item), flush=True)
        clinical = action("verify")["result"]
        report["clinical_paths"] = clinical
        report["clinical_passed"] = len(clinical) == 12 and all(value["success"] for value in clinical.values())
        if state is not None:
            # Analyze the same experiment windows from Module 2's own retained snapshots.
            for item in report["runs"]:
                run_id = item["id"]
                run = json.loads((output / (run_id + ".run.json")).read_text(encoding="utf-8"))
                deadline = time.monotonic() + 60
                while True:
                    try:
                        parsed = evaluate(run, state, output / "captures")
                    except (FileNotFoundError, ValueError) as error:
                        parsed = {"passed": False, "reason": str(error)}
                    if parsed["passed"] or run["status"] != "completed" or time.monotonic() >= deadline:
                        break
                    time.sleep(3)
                item["module2_passed"] = parsed["passed"]
                (output / (run_id + ".module2.json")).write_text(json.dumps(parsed, indent=2), encoding="utf-8")
                write()
        report["passed"] = (report["clinical_passed"] and all(report["control_checks"].values()) and
                            all(item["raw_passed"] and (state is None or item["module2_passed"]) for item in report["runs"]))
        return report["passed"]
    finally:
        write()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8877)
    parser.add_argument("--state", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, choices=(1, 2, 3), default=3)
    parser.add_argument("--scenario", action="append", choices=SCENARIOS)
    args = parser.parse_args()
    return 0 if verify(args.port, args.state, args.output, args.repeats, args.scenario or SCENARIOS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
