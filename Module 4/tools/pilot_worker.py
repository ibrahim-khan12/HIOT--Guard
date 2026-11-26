"""Disposable GNS3 pilot worker. Only synthetic traffic on 10.88.0.0/24.

The HTTP management plane is token protected and exposes fixed pilot operations,
not a shell. Package installation occurs before capture, over a separate NIC.
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = {"ready": False, "busy": False, "receipts": []}
ROLE = os.environ["PILOT_ROLE"]
TOKEN = os.environ["PILOT_TOKEN"]
ROOT = Path("/tmp/module4-pilot")
ROOT.mkdir(exist_ok=True)


def command(args, timeout=120):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(str(args[:3]) + ": " + (result.stderr + result.stdout)[-3000:])
    return (result.stdout + result.stderr)[-4000:]


JAVA = r'''
import ca.uhn.hl7v2.model.v25.message.ORU_R01;
import ca.uhn.hl7v2.model.v25.segment.OBX;
import ca.uhn.hl7v2.parser.PipeParser;
import java.net.*;
import java.nio.charset.StandardCharsets;
public class PilotHL7 {
 public static void main(String[] a) throws Exception {
  int count=Integer.parseInt(a[4]);
  Socket s=new Socket(); s.bind(new InetSocketAddress(a[0],0));
  s.connect(new InetSocketAddress("10.88.0.2",Integer.parseInt(a[1])),5000);
  s.setSoTimeout(5000);
  for(int i=0;i<count;i++) {
   ORU_R01 m=new ORU_R01(); m.initQuickstart("ORU","R01","P");
   m.getMSH().getMessageControlID().setValue("B"+System.nanoTime());
   OBX obx=m.getPATIENT_RESULT().getORDER_OBSERVATION().getOBSERVATION().getOBX();
   obx.getSetIDOBX().setValue("1"); obx.getValueType().setValue("NM");
   obx.getObservationIdentifier().getIdentifier().setValue(a[2]);
   obx.getObservationIdentifier().getNameOfCodingSystem().setValue(a[3]);
   obx.getObservationResultStatus().setValue("F");
   byte[] b=("\013"+new PipeParser().encode(m)+"\034\015").getBytes(StandardCharsets.US_ASCII);
   s.getOutputStream().write(b); s.getOutputStream().flush();
   int prev=0,cur; while((cur=s.getInputStream().read())!=-1) { if(prev==28&&cur==13) break; prev=cur; }
  }
  s.close();
 }
}
'''


def setup():
    for _ in range(60):
        if subprocess.run(["ip", "link", "show", "eth0"], capture_output=True).returncode == 0:
            break
        time.sleep(.5)
    addresses = [2] if ROLE == "service" else list(range(11, 17))
    for value in addresses:
        command(["ip", "addr", "replace", f"10.88.0.{value}/24", "dev", "eth0"])
    command(["ip", "link", "set", "eth0", "up"])
    if ROLE == "service":
        services()
        STATE["versions"] = {"receiver": "Python MLLP + pynetdicom", "synthetic": True}
    else:
        gateway = os.environ["PILOT_NAT"]
        setup_ip = gateway.rsplit(".", 1)[0] + ".11/24"
        command(["ip", "addr", "flush", "dev", "eth1"])
        command(["ip", "addr", "replace", setup_ip, "dev", "eth1"])
        command(["ip", "link", "set", "eth1", "up"])
        command(["ip", "route", "replace", "default", "via", gateway])
        Path("/etc/resolv.conf").write_text("nameserver " + gateway + "\n")
        STATE["network"] = command(["ip", "route"])
        STATE["package_update"] = command(["apt-get", "-o", "APT::Update::Error-Mode=any", "update"], 180)
        command(["apt-get", "install", "-y", "--no-install-recommends", "default-jdk-headless", "dcmtk", "ca-certificates"], 600)
        artifacts = [
            "ca/uhn/hapi/hapi-base/2.5.1/hapi-base-2.5.1.jar",
            "ca/uhn/hapi/hapi-structures-v25/2.5.1/hapi-structures-v25-2.5.1.jar",
            "org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar",
            "org/slf4j/slf4j-simple/1.7.36/slf4j-simple-1.7.36.jar",
            "joda-time/joda-time/2.1/joda-time-2.1.jar",
        ]
        hashes = {}
        for artifact in artifacts:
            with urllib.request.urlopen("https://repo.maven.apache.org/maven2/" + artifact, timeout=60) as response:
                raw = response.read(16 * 1024 * 1024)
            target = ROOT / artifact.rsplit("/", 1)[1]
            target.write_bytes(raw)
            hashes[target.name] = hashlib.sha256(raw).hexdigest()
        (ROOT / "PilotHL7.java").write_text(JAVA)
        command(["javac", "-cp", str(ROOT / "*"), str(ROOT / "PilotHL7.java")])
        STATE["versions"] = {"java": command(["java", "-version"]), "dcmtk": command(["/usr/bin/storescu", "--version"]), "jars": hashes}
        command(["ip", "link", "set", "eth1", "down"])
    STATE["ready"] = True


def services():
    from pynetdicom import AE, evt
    from pynetdicom.sop_class import CTImageStorage, Verification
    class MLLP(socketserver.BaseRequestHandler):
        def handle(self):
            buffer = b""
            self.request.settimeout(20)
            while True:
                try:
                    part = self.request.recv(65536)
                except socket.timeout:
                    return
                if not part:
                    return
                buffer += part
                while b"\x1c\r" in buffer:
                    message, buffer = buffer.split(b"\x1c\r", 1)
                    fields = message.lstrip(b"\x0b").split(b"\r", 1)[0].decode().split("|")
                    control = fields[9]
                    port = self.server.server_address[1]
                    code = {2575: "AA", 2576: "AR", 2577: "AE", 2578: "AA"}[port]
                    if port == 2578:
                        control = "UNRELATED"
                    reply = f"MSH|^~\\&|S||R||20261124000000||ACK|ACK1|P|2.5\rMSA|{code}|{control}\r"
                    self.request.sendall(b"\x0b" + reply.encode() + b"\x1c\r")
    class TCP(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
    for port in (2575, 2576, 2577, 2578):
        server = TCP(("10.88.0.2", port), MLLP)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    for port in (11112, 11113, 11114):
        ae = AE(ae_title="PILOT_SCP")
        ae.add_supported_context(Verification)
        if port != 11114:
            ae.add_supported_context(CTImageStorage)
        ae.start_server(("10.88.0.2", port), block=False,
                        evt_handlers=[(evt.EVT_C_STORE, lambda event, status=(0xA700 if port == 11113 else 0): status)])


def send_hl7(stack, ip, code, namespace, port=2575, count=3, fragment=False):
    if stack == "B":
        return command(["java", "-cp", str(ROOT) + ":" + str(ROOT / "*"), "PilotHL7", ip, str(port), code, namespace, str(count)])
    with socket.socket() as sock:
        sock.settimeout(10)
        sock.bind((ip, 0))
        sock.connect(("10.88.0.2", port))
        for index in range(count):
            control = str(time.time_ns())
            message = f"MSH|^~\\&|A||S||20261124000000||ORU^R01|{control}|P|2.5\rPID|1||SYNTHETIC\rOBR|1\rOBX|1|NM|{code}^Observation^{namespace}||1|unit|||||F\r"
            data = b"\x0b" + message.encode() + b"\x1c\r"
            if fragment:
                sock.sendall(data[:50])
                time.sleep(3)
                sock.sendall(data[50:])
            else:
                sock.sendall(data)
            reply = b""
            while not reply.endswith(b"\x1c\r"):
                part = sock.recv(65536)
                if not part:
                    raise RuntimeError("Receiver closed before complete ACK")
                reply += part
    return "sent"


def send_ct(stack, ip, port=11112, proposal=False):
    command(["ip", "route", "replace", "10.88.0.2/32", "dev", "eth0", "src", ip])
    if stack == "A" or proposal:
        from agent import synthetic_image
        from pynetdicom import AE
        from pynetdicom.sop_class import CTImageStorage, Verification
        ae = AE(ae_title="PILOT_SCU")
        ae.add_requested_context(CTImageStorage)
        ae.add_requested_context(Verification)
        association = ae.associate("10.88.0.2", port, bind_address=(ip, 0))
        if not association.is_established:
            return "association_rejected"
        try:
            if proposal:
                return "proposed_without_storage"
            result = association.send_c_store(synthetic_image("modality"))
            return {"status": int(result.Status)}
        finally:
            association.release()
    dump = ROOT / "ct.dump"
    dump.write_text("(0008,0016) UI [1.2.840.10008.5.1.4.1.1.2]\n(0008,0018) UI [1.2.826.0.1.3680043.10.999.1]\n(0008,0060) CS [CT]\n(0010,0010) PN [SYNTHETIC]\n(0020,000d) UI [1.2.826.0.1.3680043.10.999.2]\n(0020,000e) UI [1.2.826.0.1.3680043.10.999.3]\n")
    command(["/usr/bin/dump2dcm", str(dump), str(ROOT / "ct.dcm")])
    # DCMTK constructs and sends the dataset; no Python DICOM serialization in B.
    return command(["/usr/bin/storescu", "-v", "-R", "-to", "5", "-td", "10", "10.88.0.2", str(port), str(ROOT / "ct.dcm")])


def run_pilot(stack):
    if stack not in ("A", "B"):
        raise ValueError("Invalid stack")
    STATE["receipts"] = []
    began = time.monotonic()
    def record(case, operation):
        start = time.time()
        try:
            detail = operation()
            result = {"case": case, "start": start, "end": time.time(), "ok": True, "detail": detail}
        except Exception as error:
            result = {"case": case, "start": start, "end": time.time(), "ok": False, "error": str(error)}
        STATE["receipts"].append(result)
    # These actors share a container and receiver. They are pilot profiles, not six independent devices.
    for name, suffix, code, namespace in (("pump", 11, "LAB_RATE", "99HIOT"), ("relay", 16, "LAB_RATE", "99HIOT"),
                                         ("bedside", 13, "8867-4", "LN"), ("ecg", 14, "8867-4", "LN")):
        record(name, lambda s=suffix,c=code,n=namespace: send_hl7(stack, f"10.88.0.{s}", c, n))
    for name, suffix in (("ct", 12), ("workstation", 15)):
        for index in range(2):
            record(name + str(index), lambda s=suffix: send_ct(stack, f"10.88.0.{s}"))
    for port in (2576, 2577, 2578):
        record("ack_" + str(port), lambda p=port: send_hl7(stack, "10.88.0.11", "LAB_RATE", "99HIOT", p))
    record("wrong_namespace", lambda: send_hl7(stack, "10.88.0.11", "LAB_RATE", "LN"))
    record("proposal_only", lambda: send_ct("A", "10.88.0.12", proposal=True))
    record("store_failure", lambda: send_ct(stack, "10.88.0.12", 11113))
    record("context_refused", lambda: send_ct(stack, "10.88.0.12", 11114))
    # A deliberate cutoff-crossing TCP fragment, with a known send-time receipt.
    if stack == "A":
        record("fragment", lambda: send_hl7(stack, "10.88.0.11", "LAB_RATE", "99HIOT", count=1, fragment=True))
    remaining = 125 - (time.monotonic() - began)
    if remaining > 0:
        time.sleep(remaining)
    for suffix in (11, 13, 14, 16):
        record("late_" + str(suffix), lambda s=suffix: send_hl7(stack, f"10.88.0.{s}", "8867-4" if s in (13,14) else "LAB_RATE", "LN" if s in (13,14) else "99HIOT", count=1))
    for suffix in (12, 15):
        record("late_" + str(suffix), lambda s=suffix: send_ct(stack, f"10.88.0.{s}"))


def background(fn):
    STATE["busy"] = True
    STATE.pop("error", None)
    def work():
        try:
            fn()
        except Exception as error:
            STATE["error"] = str(error)
        finally:
            STATE["busy"] = False
    threading.Thread(target=work, daemon=True).start()


class API(BaseHTTPRequestHandler):
    def respond(self, code, value):
        raw = json.dumps(value).encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            return self.respond(403, {})
        self.respond(200, STATE)

    def do_POST(self):
        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            return self.respond(403, {})
        if STATE["busy"]:
            return self.respond(409, {"error": "busy"})
        if self.path == "/setup":
            background(setup)
        elif self.path in ("/run/A", "/run/B") and ROLE == "actor" and STATE["ready"]:
            background(lambda: run_pilot(self.path[-1]))
        else:
            return self.respond(400, {"error": "invalid operation"})
        self.respond(202, {"accepted": True})

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), API).serve_forever()
