"""Coordinate one bounded GNS3 experiment while the normal traffic continues."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import threading
import time
import uuid

from config import CAPTURE_ROLES, NORMAL_ROLES, address
from gns3 import request_json
from scenario_profile import (BASELINE_SECONDS, MAC, MQTT_TOPIC, PROFILE, RECOVERY_SECONDS, REQUEST_ID,
                              ROLE_IPS, SCENARIOS, capture_sources)

DISPATCH_LEAD = 3


def utc(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="milliseconds")


class ScenarioRuns:
    def __init__(self, lab, monitor_port=8878):
        self.lab = lab
        self.monitor_url = f"http://127.0.0.1:{monitor_port}/api/capture-context"
        self.lock = threading.RLock()
        self.runs = {}
        self.active = None
        self.latest = None
        self.cancelled = threading.Event()
        self.worker = None

    def summary(self):
        with self.lock:
            return {"active": bool(self.active), "latest": self.latest,
                    "options": [{"id": key, "label": spec["label"]} for key, spec in SCENARIOS.items()]}

    def reset(self):
        with self.lock:
            self.runs.clear()
            self.latest = None

    def context(self):
        manifest = self.lab.adapter.manifest
        roles = capture_sources(manifest, CAPTURE_ROLES)
        captures = {capture.name: capture for capture in self.lab.captures}
        if any(role not in captures or captures[role].process.poll() is not None or captures[role].error
               for role in roles):
            raise RuntimeError("Module 1 capture stopped or reported an error")
        try:
            context = request_json(self.monitor_url, timeout=1.5)
        except Exception as error:
            raise RuntimeError("Start Module 2 monitoring with the scenario profile manifest") from error
        if (context.get("collector", {}).get("state") != "running" or not context.get("scope")
                or context.get("project_id") != manifest["project_id"] or context.get("server") != manifest["server"]
                or any(context["links"].get(role) != manifest["links"][role] or role not in context["streams"]
                       for role in roles)):
            raise RuntimeError("Module 2 must be recording all capture links for this scenario project")
        return context

    def save(self, record):
        directory = self.lab.session / "scenarios"
        directory.mkdir(exist_ok=True)
        path = directory / (record["run_id"] + ".json")
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(record, indent=2), encoding="utf-8")
        temporary.replace(path)

    def start(self, data):
        if self.lab.mode != "gns3" or self.lab.adapter.manifest.get("profile") != PROFILE:
            raise ValueError("Select the GNS3 controlled scenarios profile first")
        key, token = data.get("scenario_id"), data.get("request_id")
        if not isinstance(key, str) or key not in SCENARIOS or not isinstance(token, str) or not REQUEST_ID.fullmatch(token):
            raise ValueError("Use a listed scenario and a valid request ID")
        with self.lock:
            if token in self.runs:
                previous = self.runs[token]
                if previous["scenario_id"] != key:
                    raise ValueError("This request ID already belongs to a different scenario")
                return previous
            if self.active:
                raise ValueError("Wait for the current scenario to finish or cancel it")
        if any(value != "normal" for value in self.lab.agent("gateway", "/state")["policy"].values()):
            raise ValueError("The scenario profile requires baseline gateway policy")
        with ThreadPoolExecutor(max_workers=6) as pool:
            if not all(list(pool.map(lambda role: self.lab.agent(role, "/state").get("running"), NORMAL_ROLES))):
                raise ValueError("Start all normal hospital traffic generators first")
        self.lab.adapter.validate_isolation()
        context = self.context()
        if key == "mqtt-burst" and not self.lab.agent("arp_observer", "/scenario").get("mqtt_ready"):
            raise ValueError("Wait for the isolated MQTT subscriber to connect")

        spec = SCENARIOS[key]
        run = uuid.uuid4().hex
        ip = lambda role: ROLE_IPS[role] if role in ROLE_IPS else address(role, "gns3")
        record = {"schema_version": 1, "scenario_id": key, "label": spec["label"], "run_id": run,
                  "request_id": token, "project_id": context["project_id"], "capture_scope": context["scope"],
                  "profile": PROFILE, "observation_only": True, "status": "preparing",
                  "expected_sources": {role: ip(role) for role in spec["actors"]},
                  "expected_destinations": {role: {"ip": ip(role), "ports": ports}
                                            for role, ports in spec["targets"].items()},
                  "capture_links": {role: context["links"][role] for role in spec["captures"]},
                  "module1_session": str(self.lab.session.resolve()), "requested_utc": utc(time.time()),
                  "agents": {}}
        with self.lock:
            self.save(record)
            self.runs[token] = self.active = self.latest = dict(record)
            self.cancelled = threading.Event()
            self.worker = threading.Thread(target=self.run, args=(record, spec, context), daemon=True)
            self.worker.start()
        return record

    def cancel(self, wait=False):
        with self.lock:
            worker = self.worker
            if self.active:
                self.cancelled.set()
                self.latest = {**self.active, "status": "cancelling"}
        if wait and worker and worker is not threading.current_thread():
            worker.join(timeout=45)
            if worker.is_alive():
                raise RuntimeError("Scenario agents have not confirmed shutdown yet")

    def call(self, role, run, action, **fields):
        return self.lab.agent(role, "/scenario", {"run_id": run, "action": action, **fields})

    def check_context(self, initial):
        current = self.context()
        if any(current[field] != initial[field] for field in ("scope", "project_id", "links", "streams", "recording_instance")):
            raise RuntimeError("A capture reader restarted or the recording changed")

    def run(self, record, spec, context):
        run, key = record["run_id"], record["scenario_id"]
        roles = tuple(spec["actors"])
        attempted, commands, fields = set(), {}, {}
        start = end = None
        status, reason = "completed", None
        dispatched = False
        try:
            if key == "arp-conflict":
                service = self.lab.agent("scenario_service", "/scenario")["mac"]
                observer = self.lab.agent("arp_observer", "/scenario")["mac"]
                if not MAC.fullmatch(service) or not MAC.fullmatch(observer):
                    raise ValueError("Invalid isolated actor MAC")
                record["neighbor_before"] = self.call("arp_observer", run, "pin", service_mac=service)["neighbor"]
                record["expected_service_mac"] = service
                record["expected_conflict_mac"] = self.lab.agent("burst_a", "/scenario")["mac"]
                fields["observer_mac"] = observer
            if self.cancelled.is_set():
                raise InterruptedError("Cancelled by operator")
            start = time.time() + DISPATCH_LEAD
            active = start + BASELINE_SECONDS
            end = active + spec["seconds"]
            recovery = end + RECOVERY_SECONDS
            record.update(status="running", start_epoch=start, start_utc=utc(start), active_epoch=active,
                          active_end_epoch=end, recovery_end_epoch=recovery)
            with self.lock:
                self.save(record)
                self.active = self.latest = self.runs[record["request_id"]] = dict(record)
            attempted.update(roles)  # A lost HTTP reply can still mean the actor accepted its command.
            with ThreadPoolExecutor(max_workers=len(roles)) as pool:
                for answer in pool.map(lambda role: self.call(role, run, "start", scenario_id=key,
                                                               start=start, **fields), roles):
                    if answer.get("run_id") != run:
                        raise RuntimeError("An actor did not acknowledge the scheduled run")
            dispatched = True
            while True:
                if self.cancelled.is_set():
                    raise InterruptedError("Cancelled by operator")
                self.check_context(context)
                if time.time() >= recovery:
                    break
                self.cancelled.wait(0.5)
        except InterruptedError as error:
            status, reason = "cancelled", str(error)
        except Exception as error:
            status, reason = ("cancelled" if dispatched else "incomplete"), str(error)
        finally:
            if attempted and status != "completed":
                for role in attempted:
                    try:
                        self.call(role, run, "cancel")
                    except Exception:
                        pass
            remaining = set(attempted)
            while remaining:
                for role in tuple(remaining):
                    try:
                        command = self.lab.agent(role, "/scenario").get("command")
                        if command and command["run_id"] == run and not command["running"]:
                            commands[role] = command
                            remaining.remove(role)
                        elif time.time() >= start and (not command or command["run_id"] != run):
                            remaining.remove(role)
                    except Exception:
                        pass
                if not remaining or time.time() >= end + 3:
                    break
                time.sleep(0.2)
            record["agents"] = commands
            try:
                if key in ("udp-single", "udp-dual", "mqtt-burst"):
                    receiver = "arp_observer" if key == "mqtt-burst" else "scenario_service"
                    record["receiver"] = self.call(receiver, run, "receipts")["counts"]
                if key == "arp-conflict" and "expected_service_mac" in record:
                    record["neighbor_after"] = self.call("arp_observer", run, "neighbor")["neighbor"]
                if status == "completed":
                    self.validate_results(key, roles, record)
            except Exception as error:
                if status == "completed":
                    status, reason = "incomplete", str(error)
                else:
                    record["receipt_error"] = str(error)
            stopped = time.time()
            record.update(status=status, reason=reason, end_epoch=stopped, end_utc=utc(stopped))
            with self.lock:
                try:
                    self.save(record)
                except OSError as error:
                    record.update(status="incomplete", reason=f"Could not persist run log: {error}")
                self.runs[record["request_id"]] = self.latest = record
                self.active = None

    @staticmethod
    def validate_results(key, roles, record):
        for role in roles:
            command = record["agents"].get(role)
            if not command or command.get("error") or command.get("cancelled") or not command.get("result"):
                raise RuntimeError(f"{role} did not complete: {command}")
            result = command["result"]
            if key in ("workstation-recon", "pump-to-pacs"):
                expected = 8 if key == "workstation-recon" else 4
                if len(result["attempts"]) != expected:
                    raise RuntimeError(f"{role} reported fewer than {expected} attempts")
            elif key == "arp-conflict":
                if result["sent"] != (1 if role == "scenario_service" else 3):
                    raise RuntimeError(f"{role} did not complete its ARP announcements")
            elif not result["sent"].get("baseline") or not result["sent"].get("burst"):
                raise RuntimeError(f"{role} did not send both baseline and burst traffic")
        if key == "arp-conflict" and (record["neighbor_before"] != record["neighbor_after"]
                                      or "PERMANENT" not in record["neighbor_after"]
                                      or record["expected_service_mac"] not in record["neighbor_after"]):
            raise RuntimeError("Observer did not retain the legitimate permanent neighbor")
        if key == "mqtt-burst" and not record["receiver"].get(MQTT_TOPIC, {}).get("burst"):
            raise RuntimeError("The MQTT subscriber recorded no burst messages")
