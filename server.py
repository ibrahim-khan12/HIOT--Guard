"""Live PoC: real traffic -> packet dissection -> detection -> response -> verification."""
import argparse
import atexit
import json
import os
import queue
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from config import AGENT_PORTS, CAPTURE_ROLES, NORMAL_ROLES, ROLES, address
from gns3 import GNS3, request_json
from monitor import Capture, Engine

ROOT = Path(__file__).resolve().parent


class Lab:
    def __init__(self, folder=ROOT / "runs"):
        self.folder = Path(folder)
        self.mode = None
        self.engine = None
        self.captures = []
        self.children = []
        self.owned_roles = set()
        self.adapter = None
        self.policy = {"workstation": "normal", "pump": "normal"}
        self.jobs = queue.Queue()
        self.busy = threading.Lock()
        self.last_result = None
        self.error = None
        self.approval = None
        self.session = None
        self.generation = 0
        threading.Thread(target=self.response_loop, daemon=True).start()

    def agent(self, role, endpoint, data=None):
        if self.mode == "gns3":
            return self.adapter.agent(role, endpoint, data)
        return request_json(f"http://127.0.0.1:{AGENT_PORTS[role]}{endpoint}", data, timeout=15)

    def start(self, mode, url=None):
        if self.mode:
            raise ValueError("Stop the current lab before starting a different capture session")
        self.error = None
        self.adapter = None
        self.policy = {"workstation": "normal", "pump": "normal"}
        self.approval = None
        self.last_result = None
        self.generation += 1
        generation = self.generation
        self.session = self.folder / time.strftime("%Y%m%d-%H%M%S")
        self.session.mkdir(parents=True, exist_ok=True)
        self.engine = Engine(mode, lambda ip, policy: self.jobs.put((ip, policy, None, generation)))
        self.mode = mode
        try:
            if mode == "local":
                for role in ("pacs", "ehr", *CAPTURE_ROLES):
                    with socket.socket() as check:
                        try:
                            check.bind(("127.0.0.1", AGENT_PORTS[role]))
                        except OSError as error:
                            raise RuntimeError(f"Management port {AGENT_PORTS[role]} is already in use. Stop the other live lab first.") from error
                for role in ("pacs", "ehr", *CAPTURE_ROLES):
                    log = (self.session / (role + ".log")).open("w")
                    child = subprocess.Popen([sys.executable, str(ROOT / "agent.py"), "--role", role, "--mode", "local",
                                              "--port", str(AGENT_PORTS[role])], stdout=log, stderr=log,
                                             creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
                    log.close()
                    self.children.append(child)
                    self.owned_roles.add(role)
                for role in ("pacs", "ehr", *CAPTURE_ROLES):
                    for _ in range(50):
                        try:
                            self.agent(role, "/state")
                            break
                        except Exception:
                            time.sleep(0.1)
                    else:
                        raise RuntimeError(f"{role} did not start. Check logs in {self.session}")
                if any(child.poll() is not None for child in self.children):
                    raise RuntimeError(f"A service failed to bind. Check logs in {self.session}")
                interface = os.environ.get("IOMT_INTERFACE", r"\Device\NPF_Loopback" if os.name == "nt" else "lo")
                self.captures.append(Capture(self.engine, self.session / "native.pcapng", interface=interface))
            elif mode == "gns3":
                self.adapter = GNS3(url, self.folder)
                self.adapter.build()
                self.adapter.start()
                self.policy = self.agent("gateway", "/state")["policy"]
                for role in CAPTURE_ROLES:
                    self.captures.append(Capture(self.engine, self.session / (role + ".pcap"), stream=self.adapter.stream(role), name=role))
            else:
                raise ValueError("Unknown lab mode")
            time.sleep(1)
            if any(c.process.poll() is not None for c in self.captures):
                raise RuntimeError("Packet capture failed. Npcap/capture permissions are required; no simulated data will be substituted.")
            self.engine.event("SESSION", "Actual packet monitoring started: " + mode)
        except Exception:
            self.stop()
            raise

    def response_loop(self):
        while True:
            ip, policy, reviewer, generation = self.jobs.get()
            try:
                with self.busy:
                    if generation == self.generation and self.mode and self.engine and ip in self.engine.registry:
                        self.enforce(ip, policy, reviewer)
            except Exception as error:
                self.error = str(error)
                if self.engine and ip in self.engine.assets:
                    self.engine.assets[ip]["response"] = "failed"
                    self.engine.event("RESPONSE FAILED", str(error), ip)
            finally:
                self.jobs.task_done()

    def enforce(self, ip, policy, reviewer=None):
        role = self.engine.registry[ip]["role"]
        desired = dict(self.policy)
        if role not in desired:
            raise ValueError("This lab can contain only its registered workstation or pump")
        if role == "pump" and policy == "isolated":
            if self.policy["pump"] != "restricted" or not reviewer or not 3 <= len(reviewer.strip()) <= 80:
                raise ValueError("Restrict the pump first and enter a lab reviewer name (3-80 characters)")
        desired[role] = policy
        payload = dict(desired)
        if reviewer:
            payload["reviewer"] = reviewer.strip()
        if self.mode == "gns3":
            proof = self.agent("gateway", "/policy", payload)
        else:
            proof = [self.agent(target, "/policy", payload) for target in ("pacs", "ehr", "pump")]
        self.policy = desired
        if reviewer:
            self.approval = {"reviewer": reviewer.strip(), "time": time.time(), "authenticated": False}
        with self.engine.lock:
            asset = self.engine.asset(ip)
            asset["policy"], asset["response"] = policy, "applied"
        self.engine.event("POLICY APPLIED", ("Linux gateway firewall" if self.mode == "gns3" else "Local service ACL, not a network firewall") + ": " + policy, ip)
        self.last_result = {"operation": "containment", "proof": proof}

    def action(self, data):
        operation = data.get("action")
        if operation in ("start-local", "start-gns3"):
            self.start("local" if operation == "start-local" else "gns3", data.get("url"))
            return {"operation": operation, "success": True}
        if operation == "stop-lab":
            self.stop()
            return {"operation": operation, "success": True}
        if not self.mode:
            raise ValueError("Start a capture session first")
        if operation in ("normal", "recon", "anomaly", "unknown") and any(c.process.poll() is not None or c.error for c in self.captures):
            raise ValueError("The packet capture is no longer healthy. Stop and restart the session before generating more traffic.")
        if operation in ("normal", "pause"):
            result = {role: self.agent(role, "/action", {"action": "start" if operation == "normal" else "stop"})
                      for role in NORMAL_ROLES}
        elif operation == "recon":
            result = self.agent("workstation", "/action", {"action": "recon"})
        elif operation == "anomaly":
            result = self.agent("pump", "/action", {"action": "anomaly"})
        elif operation == "unknown":
            result = self.agent("unregistered", "/action", {"action": "probe"})
        elif operation == "verify":
            result = {role: self.agent(role, "/action", {"action": "probe"}) for role in NORMAL_ROLES}
        elif operation == "approve":
            self.enforce(address("pump", self.mode), "isolated", str(data.get("reviewer", "")))
            result = {"approved": True, "authenticated": False}
        elif operation == "reset":
            self.generation += 1
            generation = self.generation
            self.engine.respond = lambda ip, policy: self.jobs.put((ip, policy, None, generation))
            for role in NORMAL_ROLES:
                self.agent(role, "/action", {"action": "stop"})
            # Reset is a new incident window, not fabricated historical packet evidence.
            if self.mode == "gns3":
                self.agent("gateway", "/policy", {"workstation": "normal", "pump": "normal"})
            else:
                for role in ("pacs", "ehr", "pump"):
                    self.agent(role, "/policy", {"workstation": "normal", "pump": "normal"})
            self.policy = {"workstation": "normal", "pump": "normal"}
            self.approval = None
            with self.engine.lock:
                self.engine.attempts.clear()
                # Keep retransmission identities so old in-flight SYNs cannot reopen the incident.
                for asset in self.engine.assets.values():
                    asset.update(risk=0, peakRisk=0, scoreParts=[], policy="normal", response="none")
            self.engine.event("RESET", "Response policy restored; captured evidence and service counters retained")
            result = {"policy": self.policy}
        else:
            raise ValueError("Unknown action")
        self.last_result = {"operation": operation, "result": result}
        return self.last_result

    def status(self, endpoints=True):
        states = {}
        if self.mode and endpoints:
            for role in ("pacs", "ehr", *CAPTURE_ROLES) + (("gateway",) if self.mode == "gns3" else ()):
                try:
                    states[role] = self.agent(role, "/state")
                except Exception as error:
                    states[role] = {"error": str(error)}
        if self.engine:
            with self.engine.lock:
                for asset in self.engine.assets.values():
                    if asset["role"] in self.policy:
                        asset["policy"] = self.policy[asset["role"]]
        return {"app": "iomt-live-v1", "mode": self.mode, "enforcement": "Linux gateway firewall" if self.mode == "gns3" else "Local service ACL test" if self.mode else "Not connected",
                "capture": [c.state() for c in self.captures], "monitor": self.engine.snapshot() if self.engine else {"assets": [], "packets": [], "events": [], "frames": 0},
                "policy": self.policy, "endpoints": states, "lastResult": self.last_result, "error": self.error,
                "approval": self.approval, "project": self.adapter.manifest if self.adapter else None}

    def stop(self):
        self.generation += 1
        if self.captures and self.engine:
            report = {"generated": time.time(), "scope": "Isolated lab emulators; no real medical equipment", **self.status()}
            try:
                (self.session / "report.json").write_text(json.dumps(report, indent=2))
            except OSError as error:
                self.engine.event("REPORT SAVE ERROR", str(error))
        if self.mode:
            for role in NORMAL_ROLES:
                if self.mode == "local" and role not in self.owned_roles:
                    continue
                try:
                    self.agent(role, "/action", {"action": "stop"})
                except Exception:
                    pass
        if self.adapter and self.mode:
            self.adapter.stop_captures()
        for capture in self.captures:
            capture.stop()
        for child in self.children:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
        self.captures.clear()
        self.children.clear()
        self.owned_roles.clear()
        self.mode = None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8877)
    args = parser.parse_args()
    lab = Lab()
    atexit.register(lab.stop)

    class API(BaseHTTPRequestHandler):
        def respond(self, status, data):
            raw = json.dumps(data).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if self.path == "/":
                raw = (ROOT / "index.html").read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                return self.wfile.write(raw)
            if self.path == "/api/status":
                return self.respond(200, lab.status())
            if self.path == "/api/report":
                report = {"generated": time.time(), "scope": "Isolated lab emulators; no malware or real medical devices",
                          "limitations": ["TCP probes indicate behavior, not ransomware identity", "Roles come from the authorized registry; protocol classification comes from captured evidence",
                                          "Pump telemetry uses synthetic HL7, not a vendor pump protocol", "Lab reviewer entry is not clinical authentication"], **lab.status()}
                return self.respond(200, report)
            self.respond(404, {"error": "Not found"})

        def do_POST(self):
            if self.path != "/api/action":
                return self.respond(404, {"error": "Not found"})
            origin = self.headers.get("Origin")
            if origin and origin != f"http://127.0.0.1:{args.port}":
                return self.respond(403, {"error": "Cross-origin control is not allowed"})
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                return self.respond(415, {"error": "JSON required"})
            if not lab.busy.acquire(blocking=False):
                return self.respond(409, {"error": "A lab action is in progress"})
            try:
                length = int(self.headers.get("Content-Length", 0))
                if not 0 < length <= 4096:
                    raise ValueError("Invalid request length")
                data = json.loads(self.rfile.read(length))
                self.respond(200, lab.action(data))
            except Exception as error:
                lab.error = str(error)
                self.respond(400, {"error": str(error)})
            finally:
                lab.busy.release()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", args.port), API)
    print(f"Live IoMT PoC: http://127.0.0.1:{args.port}/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        lab.stop()
        server.server_close()


if __name__ == "__main__":
    main()
