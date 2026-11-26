"""Create/resume an isolated two-container GNS3 development pilot.

No existing project is changed. The saved manifest is the sole authority for
which nodes/capture can be started or stopped. Final-test collection is separate.
"""
import argparse
import base64
import hashlib
import http.client
import json
from pathlib import Path
import re
import secrets
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from gns3 import GNS3, request_json


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("setup", "refresh", "status", "capture", "close"))
    parser.add_argument("--server", default="http://192.168.209.142")
    parser.add_argument("--folder", required=True, type=Path)
    parser.add_argument("--stack", choices=("A", "B"), default="A")
    args = parser.parse_args()
    args.folder.mkdir(parents=True, exist_ok=True)
    manifest_path = args.folder / "pilot-manifest.json"
    lab = GNS3(args.server, args.folder)
    if manifest_path.exists():
        m = json.loads(manifest_path.read_text())
        if m["server"] != args.server:
            raise ValueError("Server differs from saved pilot")
    elif args.action == "setup":
        project = lab.api("/projects", {"name": "Module4 independent pilot " + time.strftime("%Y%m%d-%H%M%S"), "auto_close": False})
        m = {"schema": "hiot.stage2.pilot.v1", "server": args.server, "project_id": project["project_id"],
             "purpose": "development_only", "token": secrets.token_hex(24), "nodes": {}, "links": {}}
        manifest_path.write_text(json.dumps(m, indent=2))
    else:
        raise ValueError("Run setup first")
    pid = m["project_id"]
    def save():
        manifest_path.write_text(json.dumps(m, indent=2))
    def api(path, data=None):
        return lab.api(f"/projects/{pid}" + path, data, timeout=60)
    def worker(role, path="/state", data=None):
        node = api("/nodes/" + m["nodes"][role])
        host = args.server.split("://", 1)[1].split(":")[0]
        return request_json(f"http://{host}:{node['console']}{path}", data,
                            {"Authorization": "Bearer " + m["token"]}, timeout=20)
    if args.action in ("setup", "refresh"):
        nat = next(i["ip_address"] for i in lab.api("/compute/network/interfaces") if i["id"] == "virbr0")
        source = Path(__file__).with_name("pilot_worker.py").read_bytes()
        m["worker_sha256"] = hashlib.sha256(source).hexdigest()
        encoded = base64.b64encode(source).decode()
        for role in ("service", "actor"):
            start_command = f'python -u -c "import base64;exec(base64.b64decode(\'{encoded}\'))"'
            environment = f"PILOT_ROLE={role}\nPILOT_TOKEN={m['token']}\nPILOT_NAT={nat}"
            if args.action == "refresh" and role in m["nodes"]:
                api("/nodes/" + m["nodes"][role] + "/stop", {})
                request = urllib.request.Request(args.server + f"/v2/projects/{pid}/nodes/" + m["nodes"][role],
                    data=json.dumps({"properties": {"start_command": start_command, "environment": environment}}).encode(), method="PUT", headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(request, timeout=30) as response:
                    response.read()
            if role not in m["nodes"]:
                node = api("/nodes", {"compute_id": "local", "name": "pilot-" + role, "node_type": "docker", "console_type": "http",
                    "properties": {"image": "iomt-hospital:2", "adapters": 2 if role == "actor" else 1, "console_http_port": 8080,
                        "start_command": start_command,
                        "environment": environment}})
                m["nodes"][role] = node["node_id"]
                save()
        if "nat" not in m["nodes"]:
            m["nodes"]["nat"] = api("/nodes", {"compute_id": "local", "name": "pilot-setup-nat", "node_type": "nat"})["node_id"]
            save()
        for name, left, adapter, right in (("capture", "actor", 0, "service"), ("setup", "actor", 1, "nat")):
            if name not in m["links"]:
                m["links"][name] = api("/links", {"nodes": [
                    {"node_id": m["nodes"][left], "adapter_number": adapter, "port_number": 0},
                    {"node_id": m["nodes"][right], "adapter_number": 0, "port_number": 0}]})["link_id"]
                save()
        for role in ("service", "actor"):
            api("/nodes/" + m["nodes"][role] + "/start", {})
            for _ in range(40):
                try:
                    state = worker(role)
                    break
                except (OSError, RuntimeError, http.client.HTTPException):
                    time.sleep(1)
            else:
                raise RuntimeError(role + " management plane unavailable")
            if not state["ready"] and not state["busy"]:
                worker(role, "/setup", {})
        save()
        print("Setup started; use status to inspect package installation.")
    elif args.action == "status":
        for role in ("service", "actor"):
            node = api("/nodes/" + m["nodes"][role])
            encoded = re.search(r"b64decode\('([A-Za-z0-9+/=]+)'\)", node["properties"]["start_command"])
            if not encoded or hashlib.sha256(base64.b64decode(encoded[1])).hexdigest() != m["worker_sha256"]:
                raise ValueError("Running worker source differs from the saved manifest; refresh setup before capture")
            state = worker(role)
            print(json.dumps({"role": role, **state}, indent=2))
            (args.folder / (role + "-status.json")).write_text(json.dumps(state, indent=2))
    elif args.action == "capture":
        out = args.folder / ("stack-" + args.stack)
        out.mkdir(exist_ok=False)
        for role in ("service", "actor"):
            state = worker(role)
            if not state["ready"] or state["busy"]:
                raise RuntimeError(role + " not ready")
            (out / (role + "-versions.json")).write_text(json.dumps(state.get("versions"), indent=2))
        filename = "stage2-" + args.stack + ".pcap"
        link = "/links/" + m["links"]["capture"]
        started = time.time()
        api(link + "/start_capture", {"capture_file_name": filename, "data_link_type": "DLT_EN10MB"})
        try:
            worker("actor", "/run/" + args.stack, {})
            deadline = time.monotonic() + 360
            while True:
                state = worker("actor")
                print(json.dumps({"stack": args.stack, "elapsed": round(time.time()-started, 1), "cases": len(state["receipts"]), "busy": state["busy"]}), flush=True)
                if not state["busy"]:
                    break
                if time.monotonic() > deadline:
                    raise TimeoutError("Pilot exceeded bounded run time")
                time.sleep(10)
        finally:
            api(link + "/stop_capture", {})
        ended = time.time()
        with urllib.request.urlopen(args.server + f"/v2/projects/{pid}/files/project-files/captures/" + filename, timeout=60) as response:
            data = response.read(32 * 1024 * 1024 + 1)
        if len(data) > 32 * 1024 * 1024:
            raise RuntimeError("Pilot capture exceeded limit")
        (out / "traffic.pcap").write_bytes(data)
        report = {"purpose": "development_only", "stack": args.stack, "capture_started": started, "capture_stopped": ended,
                  "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "worker_sha256": m["worker_sha256"],
                  "independence_limit": "Six IP profiles share one container, one synthetic receiver, and one scheduler. B uses HAPI/DCMTK senders; proposal-only control uses Python.",
                  "endpoints": {"10.88.0.11": "infusion_pump", "10.88.0.12": "ct", "10.88.0.13": "bedside_monitor",
                                "10.88.0.14": "ecg_monitor", "10.88.0.15": "other", "10.88.0.16": "other", "10.88.0.2": "other"},
                  "state": state}
        (out / "capture.json").write_text(json.dumps(report, indent=2))
        print(json.dumps({k: report[k] for k in ("stack", "bytes", "sha256")}))
    else:
        api("/close", {})
        print("Closed only the saved pilot project; captures and containers retained.")


if __name__ == "__main__":
    main()
