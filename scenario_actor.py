"""Actor-side scheduling and hard limits for the isolated GNS3 experiments."""
import math
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path

from scenario_profile import (BASELINE_SECONDS, BURST_SECONDS, MAC, MQTT_PORT, MQTT_RATE, MQTT_TOPIC,
                              ROLE_IPS, RUN_ID, SCENARIOS, UDP_PORT, UDP_RATE, parse_payload, payload)


def mac_bytes(value):
    if not isinstance(value, str) or not MAC.fullmatch(value):
        raise ValueError("Invalid lab interface MAC")
    raw = bytes.fromhex(value.replace(":", ""))
    if raw[0] & 1 or not any(raw):
        raise ValueError("A unicast lab interface MAC is required")
    return raw


class ScenarioActor:
    def __init__(self, agent):
        self.agent = agent
        self.lock = threading.RLock()
        self.command = None
        self.cancel = threading.Event()
        self.receipts = {}
        self.mqtt_ready = False
        self.broker = None
        self.mqtt_client = None

    @property
    def mac(self):
        return Path("/sys/class/net/eth0/address").read_text().strip()

    def status(self):
        with self.lock:
            return {"mac": self.mac, "command": dict(self.command) if self.command else None,
                    "mqtt_ready": self.mqtt_ready}

    def count(self, raw, source):
        key = parse_payload(raw)
        if key is None:
            return
        run, phase, _ = key
        with self.lock:
            if run not in self.receipts and len(self.receipts) >= 64:
                del self.receipts[next(iter(self.receipts))]
            counts = self.receipts.setdefault(run, {})
            counts.setdefault(source, {"baseline": 0, "burst": 0})[phase] += 1

    def start_services(self):
        role = self.agent.role
        if role == "scenario_service":
            ip = ROLE_IPS[role]
            config = Path("/etc/mosquitto/conf.d/hiot-scenarios.conf")
            config.write_text(f"listener {MQTT_PORT} {ip}\nallow_anonymous true\npersistence false\n")
            self.broker = subprocess.Popen(["mosquitto", "-c", str(config)], stdout=subprocess.DEVNULL)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((ip, UDP_PORT))

            def receive():
                while True:
                    data, (source, _) = sock.recvfrom(129)
                    if source in (ROLE_IPS["burst_a"], ROLE_IPS["burst_b"]):
                        self.count(data, source)

            threading.Thread(target=receive, daemon=True).start()
        elif role == "arp_observer":
            from paho.mqtt import client as mqtt
            client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
            client.on_connect = lambda c, u, f, reason, p: c.subscribe(MQTT_TOPIC) if not reason.is_failure else None
            client.on_subscribe = lambda c, u, mid, reasons, p: self.set_mqtt_ready(all(not r.is_failure for r in reasons))
            client.on_disconnect = lambda *args: self.set_mqtt_ready(False)
            client.on_message = lambda c, u, msg: self.count(msg.payload, MQTT_TOPIC)
            client.connect_async(ROLE_IPS["scenario_service"], MQTT_PORT, keepalive=15)
            client.loop_start()
            self.mqtt_client = client

    def set_mqtt_ready(self, ready):
        with self.lock:
            self.mqtt_ready = ready

    def neighbor(self):
        if self.agent.role != "arp_observer":
            raise ValueError("Only the isolated observer inspects this neighbor")
        return subprocess.check_output(["ip", "neigh", "show", "to", ROLE_IPS["scenario_service"],
                                        "dev", "eth0"], text=True, timeout=2).strip()

    def action(self, data):
        operation, run = data.get("action"), data.get("run_id")
        if not isinstance(run, str) or not RUN_ID.fullmatch(run):
            raise ValueError("Invalid scenario run ID")
        if operation == "receipts":
            with self.lock:
                return {"counts": {source: dict(counts) for source, counts in self.receipts.get(run, {}).items()}}
        if operation == "neighbor":
            return {"neighbor": self.neighbor()}
        if operation == "pin":
            if self.agent.role != "arp_observer":
                raise ValueError("Only the isolated observer can pin a neighbor")
            mac = data.get("service_mac")
            mac_bytes(mac)
            subprocess.run(["ip", "neigh", "replace", ROLE_IPS["scenario_service"], "lladdr", mac,
                            "nud", "permanent", "dev", "eth0"], check=True, timeout=2)
            return {"neighbor": self.neighbor()}
        if operation == "cancel":
            with self.lock:
                if self.command and self.command["run_id"] == run:
                    self.cancel.set()
                return dict(self.command) if self.command else {}
        if operation != "start":
            raise ValueError("Unsupported actor scenario action")
        scenario = SCENARIOS.get(data.get("scenario_id"), {})
        command = scenario.get("actors", {}).get(self.agent.role)
        start = data.get("start")
        if not command or type(start) not in (int, float) or not math.isfinite(start):
            raise ValueError("Invalid scenario for this actor")
        with self.lock:
            if self.command and self.command["run_id"] == run:
                return dict(self.command)
            lead = start - time.time()
            if not 0 < lead <= 10:
                raise ValueError("Missed the scheduled scenario start")
            if self.command and self.command["running"]:
                raise ValueError("Actor already running a scenario")
            self.cancel = threading.Event()
            self.command = {"run_id": run, "running": True, "result": None, "error": None}
            threading.Thread(target=self.execute, args=(command, run, time.monotonic() + lead,
                                                        scenario["seconds"], data.get("observer_mac")),
                             daemon=True).start()
            return dict(self.command)

    def execute(self, command, run, start, seconds, observer_mac):
        try:
            if command in ("recon", "anomaly"):
                active = start + BASELINE_SECONDS
                result = {"attempts": []} if self.cancel.wait(max(0, active - time.monotonic())) else {
                    "attempts": self.agent.action(command, cancelled=self.cancel, deadline=active + seconds)}
            elif command in ("udp", "mqtt"):
                result = self.send_paced(command, run, start)
            else:
                result = self.send_arp(start, observer_mac)
            with self.lock:
                self.command["result"] = result
        except Exception as error:
            with self.lock:
                self.command["error"] = str(error)
        finally:
            with self.lock:
                self.command.update(running=False, cancelled=self.cancel.is_set(), finished=time.time())

    def send_paced(self, command, run, start):
        mqtt = command == "mqtt"
        if mqtt:
            from paho.mqtt import client as mqtt_client
            sender = mqtt_client.Client(mqtt_client.CallbackAPIVersion.VERSION2)
            connected = threading.Event()
            sender.on_connect = lambda c, u, f, reason, p: connected.set() if not reason.is_failure else None
            sender.connect_timeout = 2
            sender.connect(ROLE_IPS["scenario_service"], MQTT_PORT, keepalive=15, bind_address=self.agent.ip)
            sender.loop_start()
        else:
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sender.bind((self.agent.ip, 0))
            sender.settimeout(0.25)
        counts = {}
        try:
            if mqtt and (not connected.wait(min(2, max(0, start - time.monotonic()))) or not sender.is_connected()):
                raise RuntimeError("MQTT publisher could not connect before baseline")
            for phase, rate, begin, duration in (
                ("baseline", 1, start, BASELINE_SECONDS),
                ("burst", MQTT_RATE if mqtt else UDP_RATE, start + BASELINE_SECONDS, BURST_SECONDS),
            ):
                counts[phase] = 0
                next_send, end = begin, begin + duration
                for index in range(rate * duration):
                    if self.cancel.wait(max(0, next_send - time.monotonic())) or time.monotonic() >= end:
                        break
                    sent_at = time.monotonic()
                    raw = payload(run, phase, index)
                    if mqtt:
                        sent = sender.publish(MQTT_TOPIC, raw, qos=0)
                        sent.wait_for_publish(timeout=0.25)
                        if not sent.is_published():
                            raise RuntimeError("MQTT publish did not complete")
                    else:
                        sender.sendto(raw, (ROLE_IPS["scenario_service"], UDP_PORT))
                    counts[phase] += 1
                    # Skip missed slots instead of releasing queued packets in a burst.
                    next_send = sent_at + 1 / rate
            return {"sent": counts}
        finally:
            if mqtt:
                sender.disconnect()
                sender.loop_stop()
            else:
                sender.close()

    def send_arp(self, start, observer_mac):
        source, target = mac_bytes(self.mac), mac_bytes(observer_mac)
        if source == target:
            raise ValueError("Observer and sender must be different interfaces")
        legitimate = self.agent.role == "scenario_service"
        claim = socket.inet_aton(ROLE_IPS["scenario_service"])
        receiver = socket.inet_aton(ROLE_IPS["arp_observer"])
        frame = target + source + struct.pack("!HHHBBH", 0x0806, 1, 0x0800, 6, 4, 2) + source + claim + target + receiver
        sent = 0
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sock:
            sock.bind(("eth0", 0))
            sock.settimeout(0.25)
            for index in range(1 if legitimate else 3):
                at = start + (1 if legitimate else BASELINE_SECONDS + index * 0.3)
                if self.cancel.wait(max(0, at - time.monotonic())) or time.monotonic() >= at + 0.3:
                    break
                sock.send(frame)
                sent += 1
        return {"sent": sent}
