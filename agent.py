"""Real protocol services and bounded traffic generators for an isolated lab."""
import argparse
import html
import json
import os
import socket
import socketserver
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian, generate_uid
from pynetdicom import AE, evt
from pynetdicom.sop_class import (CTImageStorage, DigitalXRayImageStorageForPresentation,
                                  MRImageStorage, UltrasoundImageStorage, Verification)
from config import NORMAL_ROLES, ROLES, SERVICE_PORTS, address


def synthetic_image(role):
    imaging = {"modality": (CTImageStorage, "CT"), "ultrasound": (UltrasoundImageStorage, "US"),
               "mri": (MRImageStorage, "MR"), "xray": (DigitalXRayImageStorageForPresentation, "DX")}
    sop_class, modality = imaging[role]
    dataset = Dataset()
    dataset.file_meta = FileMetaDataset()
    dataset.file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    dataset.SOPClassUID = sop_class
    dataset.SOPInstanceUID = generate_uid()
    dataset.StudyInstanceUID = generate_uid()
    dataset.SeriesInstanceUID = generate_uid()
    dataset.PatientName = "SYNTHETIC^LAB"
    dataset.PatientID = "LAB_ONLY"
    dataset.Modality = modality
    dataset.ImageType = ["ORIGINAL", "PRIMARY", "AXIAL"] if role in ("modality", "mri") else ["ORIGINAL", "PRIMARY"]
    dataset.StudyDate = time.strftime("%Y%m%d")
    dataset.StudyTime = time.strftime("%H%M%S")
    dataset.Rows = dataset.Columns = 16
    dataset.SamplesPerPixel = 1
    dataset.PhotometricInterpretation = "MONOCHROME2"
    dataset.BitsAllocated = dataset.BitsStored = 8
    dataset.HighBit = 7
    dataset.PixelRepresentation = 0
    dataset.PixelData = bytes(range(256))
    if role == "modality":
        dataset.PatientPosition = "HFS"
        dataset.KVP = "100"
        dataset.RescaleIntercept = "0"
        dataset.RescaleSlope = "1"
    return dataset


class Agent:
    def __init__(self, role, mode):
        self.role, self.mode = role, mode
        self.ip = address(role, mode)
        self.running = False
        self.lock = threading.RLock()
        self.traffic_lock = threading.Lock()
        self.traffic_stop = threading.Event()
        self.traffic_thread = None
        self.command = None
        self.command_thread = None
        self.probe_generation = 0
        self.policy = {"workstation": "normal", "pump": "normal"}
        self.counters = {"dicom_echo": 0, "dicom_store": 0, "hl7_received": 0,
                         "http_received": 0, "maintenance_received": 0, "denied": 0}
        self.receipts = []
        self.results = []
        self.servers = []
        self.firewall = "not configured"

    def count(self, key):
        with self.lock:
            self.counters[key] += 1

    def receipt(self, peer, protocol, detail):
        with self.lock:
            self.receipts.insert(0, {"time": time.time(), "peer": peer,
                                     "protocol": protocol, "detail": detail})
            del self.receipts[40:]

    def permitted(self, peer, protocol):
        if self.mode != "local":
            return True
        if self.role == "pump" and self.policy["pump"] != "normal" and protocol == "maintenance":
            return False
        if peer == address("workstation", self.mode) and self.policy["workstation"] == "quarantined":
            return False
        if peer == address("pump", self.mode):
            state = self.policy["pump"]
            return state != "isolated" and (state != "restricted" or protocol == "hl7")
        return True

    def record(self, operation, ok, detail):
        result = {"time": time.time(), "operation": operation, "success": bool(ok), "detail": str(detail)}
        with self.lock:
            self.results.insert(0, result)
            del self.results[30:]
        return result

    def configure_network(self):
        if self.mode != "gns3":
            return
        interfaces = [("eth0", self.ip)]
        if self.role == "gateway":
            interfaces = [(f"eth{i}", f"10.77.{zone}.1") for i, zone in enumerate((10, 20, 30))]
        for iface, ip in interfaces:
            for _ in range(60):
                if subprocess.run(["ip", "link", "show", iface], capture_output=True).returncode == 0:
                    break
                time.sleep(0.5)
            subprocess.run(["ip", "addr", "replace", ip + "/24", "dev", iface], check=True)
            subprocess.run(["ip", "link", "set", iface, "up"], check=True)
        if self.role == "gateway":
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
            self.apply_policy(self.policy)
        else:
            gateway = self.ip.rsplit(".", 1)[0] + ".1"
            subprocess.run(["ip", "route", "replace", "default", "via", gateway], check=True)

    def apply_policy(self, desired):
        ws, pump = desired.get("workstation"), desired.get("pump")
        if ws not in ("normal", "quarantined") or pump not in ("normal", "restricted", "isolated"):
            raise ValueError("Invalid lab policy")
        if pump == "isolated" and self.policy["pump"] != "isolated":
            reviewer = str(desired.get("reviewer", "")).strip()
            if self.policy["pump"] != "restricted" or not 3 <= len(reviewer) <= 80:
                raise ValueError("Full pump isolation requires a restricted state and a lab reviewer entry")
        if self.mode == "gns3":
            if self.role != "gateway":
                raise ValueError("Only the gateway applies firewall rules")
            # This chain belongs only to our disposable GNS3 gateway container.
            subprocess.run(["iptables", "-N", "IOMT_LAB"], capture_output=True)
            if subprocess.run(["iptables", "-C", "FORWARD", "-j", "IOMT_LAB"], capture_output=True).returncode:
                subprocess.run(["iptables", "-I", "FORWARD", "1", "-j", "IOMT_LAB"], check=True)
            rules = ["*filter", ":IOMT_LAB - [0:0]", "-F IOMT_LAB"]
            if ws == "quarantined":
                for direction in ("-s", "-d"):
                    rules.append(f"-A IOMT_LAB {direction} {address('workstation', self.mode)} -j DROP")
            if pump == "isolated":
                for direction in ("-s", "-d"):
                    rules.append(f"-A IOMT_LAB {direction} {address('pump', self.mode)} -j DROP")
            elif pump == "restricted":
                rules.extend([
                    f"-A IOMT_LAB -s {address('pump', self.mode)} -d {address('ehr', self.mode)} -p tcp --dport 2575 -j ACCEPT",
                    f"-A IOMT_LAB -d {address('pump', self.mode)} -s {address('ehr', self.mode)} -p tcp --sport 2575 -m conntrack --ctstate ESTABLISHED -j ACCEPT",
                    f"-A IOMT_LAB -s {address('pump', self.mode)} -j DROP",
                    f"-A IOMT_LAB -d {address('pump', self.mode)} -j DROP",
                ])
            rules.extend(["-A IOMT_LAB -j RETURN", "COMMIT", ""])
            subprocess.run(["iptables-restore", "--noflush"], input="\n".join(rules), text=True, check=True)
            self.firewall = subprocess.check_output(["iptables", "-nvL", "IOMT_LAB"], text=True)
        with self.lock:
            self.policy = {"workstation": ws, "pump": pump}
        return self.state()

    def state(self):
        if self.mode == "gns3" and self.role == "gateway":
            self.firewall = subprocess.check_output(["iptables", "-nvL", "IOMT_LAB"], text=True)
        with self.lock:
            return {"role": self.role, "ip": self.ip, "running": self.running, "policy": dict(self.policy),
                    "counters": dict(self.counters), "receipts": list(self.receipts),
                    "results": list(self.results), "firewall": self.firewall,
                    "command": dict(self.command) if self.command else None}

    def start_services(self):
        agent = self
        if self.role == "pacs":
            ae = AE(ae_title="LAB_PACS")
            ae.add_supported_context(Verification)
            ae.add_supported_context(CTImageStorage)
            ae.add_supported_context(UltrasoundImageStorage)
            ae.add_supported_context(MRImageStorage)
            ae.add_supported_context(DigitalXRayImageStorageForPresentation)

            def accepted(event):
                peer = event.assoc.requestor.address
                if not agent.permitted(peer, "dicom"):
                    agent.count("denied")
                    event.assoc.abort()

            def echo(event):
                if not agent.permitted(event.assoc.requestor.address, "dicom"):
                    return 0xC000
                agent.count("dicom_echo")
                agent.receipt(event.assoc.requestor.address, "DICOM C-ECHO", "Verification accepted")
                return 0x0000

            def store(event):
                if not agent.permitted(event.assoc.requestor.address, "dicom"):
                    agent.count("denied")
                    return 0xC000
                agent.count("dicom_store")
                agent.receipt(event.assoc.requestor.address, "DICOM C-STORE",
                              f"Synthetic {event.dataset.get('Modality', 'unknown')} instance accepted")
                return 0x0000

            self.servers.append(ae.start_server((self.ip, 11112), block=False,
                                evt_handlers=[(evt.EVT_ACCEPTED, accepted), (evt.EVT_C_ECHO, echo),
                                              (evt.EVT_C_STORE, store)]))
        if self.role == "ehr":
            class Telemetry(socketserver.BaseRequestHandler):
                def handle(self):
                    if not agent.permitted(self.client_address[0], "hl7"):
                        agent.count("denied")
                        return
                    self.request.settimeout(2)
                    data = b""
                    while b"\x1c\x0d" not in data and len(data) < 8192:
                        chunk = self.request.recv(4096)
                        if not chunk:
                            return
                        data += chunk
                    if data.startswith(b"\x0bMSH|") and b"\x1c\x0d" in data:
                        fields = data[1:].split(b"\r", 1)[0].decode("ascii", errors="replace").split("|")
                        sender = fields[2][:40] if len(fields) > 2 else "unknown"
                        message_type = fields[8][:40] if len(fields) > 8 else "unknown"
                        control_id = fields[9][:40] if len(fields) > 9 else "LAB"
                        agent.count("hl7_received")
                        agent.receipt(self.client_address[0], "HL7v2/MLLP", f"{sender} {message_type}")
                        ack = f"MSH|^~\\&|LAB_EHR|LAB|||{time.strftime('%Y%m%d%H%M%S')}||ACK|{control_id}|P|2.5\rMSA|AA|{control_id}\r"
                        self.request.sendall(b"\x0b" + ack.encode("ascii", errors="replace") + b"\x1c\r")

            class TCP(socketserver.ThreadingTCPServer):
                allow_reuse_address = True
                daemon_threads = True

            server = TCP((self.ip, 2575), Telemetry)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.servers.append(server)

            class Health(BaseHTTPRequestHandler):
                def do_GET(self):
                    allowed = agent.permitted(self.client_address[0], "http")
                    agent.count("http_received" if allowed else "denied")
                    if allowed:
                        agent.receipt(self.client_address[0], "HTTP", "EHR health request")
                    self.send_response(200 if allowed else 403)
                    self.end_headers()
                    self.wfile.write(b"LAB_EHR_OK" if allowed else b"DENIED")

                def log_message(self, *args):
                    pass

            server = ThreadingHTTPServer((self.ip, 8081), Health)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.servers.append(server)
        if self.role == "pump":
            class Maintenance(BaseHTTPRequestHandler):
                def do_GET(self):
                    allowed = agent.permitted(self.client_address[0], "maintenance")
                    if self.path != "/maintenance/status":
                        self.send_error(404)
                        return
                    agent.count("maintenance_received" if allowed else "denied")
                    if allowed:
                        agent.receipt(self.client_address[0], "HTTP", "Read-only synthetic maintenance status")
                    payload = b"SIMULATED_PUMP_READY" if allowed else b"DENIED"
                    self.send_response(200 if allowed else 403)
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)

                def log_message(self, *args):
                    pass

            server = ThreadingHTTPServer((self.ip, 8082), Maintenance)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.servers.append(server)

    def connect(self, target, port):
        sock = socket.socket()
        sock.settimeout(1)
        sock.bind((self.ip, 0))
        try:
            sock.connect((address(target, self.mode), port))
            return sock
        except Exception:
            sock.close()
            raise

    def normal_once(self):
        operation = {"modality": "CT DICOM study", "ultrasound": "Ultrasound DICOM study",
                     "mri": "MRI DICOM study", "xray": "X-ray DICOM study",
                     "pump": "Pump synthetic HL7", "monitor": "Monitor synthetic HL7",
                     "lab_analyzer": "Analyzer synthetic HL7", "ventilator": "Ventilator synthetic HL7",
                     "dialysis": "Dialysis synthetic HL7", "ecg": "ECG synthetic HL7",
                     "workstation": "Workstation EHR check",
                     "vendor": "Read-only maintenance check", "unregistered": "Unregistered EHR request"}.get(self.role, "Clinical path check")
        try:
            if self.role in ("modality", "ultrasound", "mri", "xray"):
                contexts = {"modality": ("LAB_CT", CTImageStorage), "ultrasound": ("LAB_US", UltrasoundImageStorage),
                            "mri": ("LAB_MR", MRImageStorage), "xray": ("LAB_DX", DigitalXRayImageStorageForPresentation)}
                title, sop_class = contexts[self.role]
                ae = AE(ae_title=title)
                ae.add_requested_context(Verification)
                ae.add_requested_context(sop_class)
                ae.acse_timeout = ae.dimse_timeout = ae.network_timeout = 1
                assoc = ae.associate(address("pacs", self.mode), 11112, ae_title="LAB_PACS", bind_address=(self.ip, 0))
                echo_ok = store_ok = False
                if assoc.is_established:
                    response = assoc.send_c_echo()
                    echo_ok = response and response.Status == 0
                    response = assoc.send_c_store(synthetic_image(self.role))
                    store_ok = response and response.Status == 0
                    assoc.release()
                return self.record(operation, echo_ok and store_ok,
                                   f"Synthetic {self.role} C-ECHO={bool(echo_ok)} C-STORE={bool(store_ok)}")
            if self.role in ("pump", "monitor", "lab_analyzer", "ventilator", "dialysis", "ecg"):
                readings = {
                    "pump": ("LAB_PUMP", "LAB_RATE", "25", "mL/h"),
                    "monitor": ("LAB_MONITOR", "HEART_RATE", "72", "beats/min"),
                    "lab_analyzer": ("LAB_ANALYZER", "GLUCOSE", "95", "mg/dL"),
                    "ventilator": ("LAB_VENT", "RESPIRATORY_RATE", "16", "breaths/min"),
                    "dialysis": ("LAB_DIALYSIS", "BLOOD_FLOW", "300", "mL/min"),
                    "ecg": ("LAB_ECG", "ECG_HEART_RATE", "76", "beats/min"),
                }
                sender, observation, value, units = readings[self.role]
                control_id = f"LAB{time.time_ns()}"
                with self.connect("ehr", 2575) as sock:
                    message = (f"MSH|^~\\&|{sender}|SYNTHETIC|LAB_EHR|LAB|{time.strftime('%Y%m%d%H%M%S')}||ORU^R01|{control_id}|P|2.5\r"
                               f"PID|1||LAB_ONLY\rOBR|1|||SYNTHETIC_{observation}\rOBX|1|NM|{observation}||{value}|{units}\r")
                    sock.sendall(b"\x0b" + message.encode("ascii") + b"\x1c\r")
                    response = sock.recv(4096)
                    accepted = f"MSA|AA|{control_id}".encode() in response
                    return self.record(operation, accepted, f"{sender} {observation}: " + ("ACK received" if accepted else "No matching ACK"))
            if self.role in ("workstation", "vendor", "unregistered"):
                target = "pump" if self.role == "vendor" else "ehr"
                port = 8082 if self.role == "vendor" else 8081
                path = "/maintenance/status" if self.role == "vendor" else "/health"
                with self.connect(target, port) as sock:
                    sock.sendall(f"GET {path} HTTP/1.0\r\nHost: lab\r\n\r\n".encode())
                    response = sock.recv(4096)
                    return self.record(operation, b" 200 " in response,
                                       response.split(b"\r\n")[0].decode(errors="replace"))
        except Exception as error:
            return self.record(operation, False, error)

    def traffic_loop(self, stop):
        while not stop.is_set():
            self.normal_once()
            stop.wait(8 if self.role == "vendor" else 3)

    def begin_command(self, operation, token):
        if operation not in ("start", "stop", "probe", "recon", "anomaly") or not isinstance(token, str) or not 1 <= len(token) <= 100:
            raise ValueError("Invalid node command")
        with self.lock:
            if self.command and self.command["id"] == token:
                return dict(self.command)
            if self.command and self.command["running"]:
                raise ValueError("Wait for the current node command to finish")
            self.command = {"id": token, "action": operation, "running": True, "result": None, "error": None}
            self.command_thread = threading.Thread(target=self.run_command, args=(operation,), daemon=True)
            self.command_thread.start()
            return dict(self.command)

    def run_command(self, operation):
        try:
            result = self.action(operation)
            with self.lock:
                self.command["result"] = result
        except Exception as error:
            with self.lock:
                self.command["error"] = str(error)
        finally:
            with self.lock:
                self.command["running"] = False

    def action(self, operation):
        if operation == "start":
            with self.traffic_lock:
                if not self.running:
                    if self.traffic_thread and self.traffic_thread.is_alive():
                        raise RuntimeError("Previous traffic request is still stopping; retry shortly")
                    self.traffic_stop = threading.Event()
                    self.running = True
                    self.traffic_thread = threading.Thread(target=self.traffic_loop, args=(self.traffic_stop,), daemon=True)
                    self.traffic_thread.start()
            return self.state()
        if operation == "stop":
            with self.lock:
                self.probe_generation += 1
            with self.traffic_lock:
                self.running = False
                self.traffic_stop.set()
                if self.traffic_thread:
                    self.traffic_thread.join(timeout=5)
            if self.command_thread and self.command_thread is not threading.current_thread():
                self.command_thread.join(timeout=2)
            return self.state()
        if operation == "probe":
            return self.normal_once()
        if operation == "recon" and self.role == "workstation":
            results = []
            generation = self.probe_generation
            # Eight connect attempts only, against two configured disposable lab services.
            for target in ("pacs", "ehr"):
                for port in (445, 3389, 11112, 8081):
                    if generation != self.probe_generation:
                        return results
                    try:
                        with self.connect(target, port):
                            results.append(self.record(f"Connect {target}:{port}", True, "TCP connected; no exploit sent"))
                    except OSError as error:
                        results.append(self.record(f"Connect {target}:{port}", False, error))
                    time.sleep(0.25)
            return results
        if operation == "anomaly" and self.role == "pump":
            results = []
            generation = self.probe_generation
            for _ in range(4):
                if generation != self.probe_generation:
                    return results
                try:
                    with self.connect("pacs", 11112):
                        results.append(self.record("Unexpected pump imaging connection", True, "TCP connected; no DICOM data sent"))
                except OSError as error:
                    results.append(self.record("Unexpected pump imaging connection", False, error))
                time.sleep(0.3)
            return results
        raise ValueError("Action is not supported by this lab role")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=ROLES, default=os.environ.get("LAB_ROLE", "workstation"))
    parser.add_argument("--mode", choices=("local", "gns3"), default=os.environ.get("LAB_MODE", "gns3"))
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    agent = Agent(args.role, args.mode)
    agent.configure_network()
    agent.start_services()

    class Control(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def respond(self, code, data):
            raw = json.dumps(data).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if self.path == "/":
                actions = ["start", "stop", "probe"] if agent.role in NORMAL_ROLES else ["probe"] if agent.role == "unregistered" else []
                if agent.role == "workstation":
                    actions.append("recon")
                if agent.role == "pump":
                    actions.append("anomaly")
                page = ("<!doctype html><html lang='en'><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
                        "<title>IoMT Lab Actor</title><style>body{font:14px Segoe UI,Arial;margin:24px;color:#21343a}h1{font-size:20px}button{padding:9px 14px;margin:0 8px 10px 0;background:white;border:1px solid #91afb2;border-radius:4px;cursor:pointer}pre{background:#f4f7f8;padding:16px;white-space:pre-wrap;overflow-wrap:anywhere}</style>"
                        f"<h1>{html.escape(ROLES[agent.role]['name'])}</h1><p>{html.escape(agent.ip)} / {html.escape(agent.mode)}</p>"
                        + "".join(f"<button data-action='{action}'>{action.title()}</button>" for action in actions)
                        + "<p id='notice' role='status'></p><pre id='state'>Connecting...</pre><script>let sending=false,refreshing=false;"
                        "function controls(disabled){document.querySelectorAll('[data-action]').forEach(b=>b.disabled=disabled)}"
                        "async function refresh(){if(refreshing)return;refreshing=true;try{const r=await fetch('/state');if(!r.ok)throw Error('Node unavailable');const s=await r.json();document.getElementById('state').textContent=JSON.stringify(s,null,2);controls(sending||!!s.command?.running);if(s.command)document.getElementById('notice').textContent=s.command.running?'Running '+s.command.action+'...':s.command.error||s.command.action+' completed'}catch(e){document.getElementById('notice').textContent=e.message}finally{refreshing=false}}"
                        "document.querySelectorAll('[data-action]').forEach(b=>b.onclick=async()=>{sending=true;controls(true);try{const r=await fetch('/action',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:b.dataset.action,background:true,request_id:Date.now()+'-'+Math.random()})});const j=await r.json();if(!r.ok)throw Error(j.error);document.getElementById('notice').textContent='Running '+b.dataset.action+'...'}catch(e){document.getElementById('notice').textContent=e.message}finally{sending=false;await refresh()}});refresh();setInterval(refresh,2000)</script></html>")
                raw = page.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                return self.wfile.write(raw)
            if self.path != "/state":
                return self.respond(404, {"error": "Not found"})
            self.respond(200, agent.state())

        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length", 0))
                if length > 4096:
                    raise ValueError("Request too large")
                data = json.loads(self.rfile.read(length))
                if self.path == "/policy":
                    return self.respond(200, agent.apply_policy(data))
                if self.path != "/action":
                    return self.respond(404, {"error": "Not found"})
                if data.get("background") is True:
                    return self.respond(202, agent.begin_command(data.get("action"), data.get("request_id")))
                self.respond(200, agent.action(data.get("action")))
            except Exception as error:
                self.respond(400, {"error": str(error)})

        def log_message(self, *args):
            pass

    # GNS3's HTTP console tunnels to container loopback, outside the data-plane network.
    ThreadingHTTPServer(("127.0.0.1", args.port), Control).serve_forever()


if __name__ == "__main__":
    main()
