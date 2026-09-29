"""TShark-backed capture ingestion and transparent, traffic-derived heuristics."""
import csv
import io
from http.client import HTTPException
import subprocess
import threading
import time
from collections import deque
from pathlib import Path
from config import expected, registry, tshark_path

FIELDS = ["frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "tcp.flags.syn",
          "tcp.flags.ack", "tcp.seq_raw", "tcp.len", "tcp.payload", "dicom.assoc.ae.calling",
          "dicom.assoc.ae.called", "dicom.pctx.abss.syntax"]


def decode_row(line):
    values = next(csv.reader(io.StringIO(line), delimiter="\t", quotechar='"'))
    if len(values) != len(FIELDS) or not values[1] or not values[3]:
        return None
    return dict(zip(FIELDS, values))


class Engine:
    def __init__(self, mode, respond=None):
        self.mode = mode
        self.registry = registry(mode)
        self.respond = respond
        self.lock = threading.RLock()
        self.assets = {}
        self.packets = deque(maxlen=100)
        self.events = deque(maxlen=100)
        self.attempts = {}
        self.seen_syn = {}
        self.frames = 0
        self.last_packet = None

    def event(self, kind, detail, ip=None):
        with self.lock:
            self.events.appendleft({"time": time.time(), "kind": kind, "detail": detail, "ip": ip})

    def asset(self, ip):
        if ip not in self.assets:
            entry = self.registry.get(ip, {})
            self.assets[ip] = {"ip": ip, "name": entry.get("name", "Unregistered endpoint"),
                               "role": entry.get("role", "unknown"), "critical": entry.get("critical", False),
                               "registered": bool(entry), "protocols": [], "evidence": [], "packets": 0,
                               "risk": 0, "peakRisk": 0, "scoreParts": [], "policy": "normal", "response": "none"}
            self.event("DISCOVERY", "Address observed in a captured TCP packet", ip)
        return self.assets[ip]

    def evidence(self, asset, text, protocol):
        if protocol not in asset["protocols"]:
            asset["protocols"].append(protocol)
        if text not in asset["evidence"]:
            asset["evidence"].append(text)
            del asset["evidence"][:-8]

    def consume(self, row, capture="live"):
        if not row:
            return
        src, dst = row["ip.src"], row["ip.dst"]
        prefix = "127.77." if self.mode == "local" else "10.77."
        if not src.startswith(prefix) or not dst.startswith(prefix):
            return
        at = float(row["frame.time_epoch"])
        sport, dport = int(row["tcp.srcport"]), int(row["tcp.dstport"])
        syn = row["tcp.flags.syn"].lower() in ("true", "1")
        ack = row["tcp.flags.ack"].lower() in ("true", "1")
        response = None
        with self.lock:
            self.frames += 1
            self.last_packet = at
            source, target = self.asset(src), self.asset(dst)
            source["packets"] += 1
            target["packets"] += 1
            protocol = "TCP"
            if row["dicom.assoc.ae.calling"]:
                protocol = "DICOM"
                calling, called = row["dicom.assoc.ae.calling"].strip(), row["dicom.assoc.ae.called"].strip()
                detail = f"DICOM association: {calling} -> {called}"
                self.evidence(source, detail, protocol)
                self.evidence(target, detail, protocol)
                if row["dicom.pctx.abss.syntax"]:
                    self.evidence(source, row["dicom.pctx.abss.syntax"], protocol)
            try:
                payload = bytes.fromhex(row["tcp.payload"].replace(":", ""))
            except ValueError:
                payload = b""
            if payload.startswith(b"\x0bMSH|"):
                protocol = "HL7/MLLP"
                msh = payload[1:].split(b"\r", 1)[0].decode("ascii", errors="replace").split("|")
                if len(msh) > 9:
                    # Retain protocol metadata only, never PID or clinical observation values.
                    detail = f"MSH sender {msh[2][:40]}; message type {msh[8][:40]}"
                    self.evidence(source, detail, protocol)
                    self.evidence(target, "HL7 MLLP exchange observed", protocol)
            elif payload.startswith(b"GET ") or payload.startswith(b"HTTP/"):
                protocol = "HTTP"
                self.evidence(source, "HTTP request/response observed", protocol)
                self.evidence(target, "HTTP request/response observed", protocol)
            self.packets.appendleft({"time": at, "source": src, "destination": dst, "sport": sport,
                                     "dport": dport, "length": int(row["tcp.len"] or 0), "protocol": protocol,
                                     "flags": "SYN" if syn and not ack else "SYN/ACK" if syn else "TCP", "capture": capture})
            if syn and not ack:
                key = (src, dst, sport, dport, row["tcp.seq_raw"])
                self.seen_syn = {k: t for k, t in self.seen_syn.items() if at - t <= 60}
                if key not in self.seen_syn:
                    self.seen_syn[key] = at
                    recent = self.attempts.setdefault(src, deque(maxlen=200))
                    recent.append((at, dst, dport))
                    while recent and at - recent[0][0] > 60:
                        recent.popleft()
                    unexpected = [(d, p) for _, d, p in recent if not expected(source["role"], d, p, self.mode)]
                    destinations = len({d for d, _ in unexpected})
                    services = len(set(unexpected))
                    admin = any(p in (445, 3389) for _, p in unexpected)
                    parts = [("Protected destination spread (>=2)", 30 if destinations >= 2 else 0),
                             ("SMB/RDP connection attempts", 30 if admin else 0),
                             ("Unexpected service spread (>=6)", 25 if services >= 6 else 0)]
                    source["risk"] = sum(value for _, value in parts)
                    source["scoreParts"] = [{"label": label, "value": value} for label, value in parts]
                    if source["role"] == "pump" and unexpected:
                        source["risk"] = min(80, len(unexpected) * 20)
                        source["scoreParts"] = [{"label": "Unexpected clinical destination attempts", "value": source["risk"]}]
                    source["peakRisk"] = max(source["peakRisk"], source["risk"])
                    if unexpected:
                        self.evidence(source, f"{len(unexpected)} unexpected TCP connection attempts; {services} target/service pairs in 60s", "TCP behavior")
                    if source["role"] == "pump" and len(unexpected) >= 3 and source["policy"] == "normal" and source["response"] == "none":
                        response = (src, "restricted")
                    elif source["role"] == "workstation" and source["risk"] >= 85 and source["response"] == "none":
                        response = (src, "quarantined")
                    if response:
                        source["response"] = "pending"
                        self.event("DETECTION", f"Risk {source['risk']}; {len(unexpected)} unexpected attempts, {services} target/service pairs, {destinations} destinations in 60s. Requested {response[1]}; not proof of ransomware.", src)
        if response and self.respond:
            self.respond(*response)

    def snapshot(self):
        with self.lock:
            return json_copy({"sourceMode": self.mode, "frames": self.frames, "lastPacket": self.last_packet,
                              "assets": list(self.assets.values()), "packets": list(self.packets), "events": list(self.events)})


def json_copy(data):
    import json
    return json.loads(json.dumps(data))


class Capture:
    def __init__(self, engine, output, interface=None, stream=None, name="live"):
        self.engine, self.output, self.name = engine, Path(output), name
        self.output.parent.mkdir(parents=True, exist_ok=True)
        self.error = None
        self.stream = stream
        self.stopping = False
        args = [tshark_path(), "-n", "-l", "-d", "tcp.port==11112,dicom", "-T", "fields",
                "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=f"]
        if stream:
            args += ["-r", "-"]
        else:
            args += ["-i", interface, "-f", "net 127.77.0.0/16", "-w", str(self.output), "-a", "filesize:32768", "-P"]
        for field in FIELDS:
            args += ["-e", field]
        self.process = subprocess.Popen(args, stdin=subprocess.PIPE if stream else subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False)
        self.readers = [threading.Thread(target=self.read_packets, daemon=True), threading.Thread(target=self.read_errors, daemon=True)]
        for reader in self.readers:
            reader.start()
        if stream:
            threading.Thread(target=self.feed_stream, daemon=True).start()

    def read_packets(self):
        for line in self.process.stdout:
            try:
                self.engine.consume(decode_row(line.decode("utf-8", errors="replace")), self.name)
            except (ValueError, IndexError, csv.Error) as error:
                self.error = f"Packet parse error: {error}"

    def read_errors(self):
        tail = []
        for line in self.process.stderr:
            tail.append(line.decode(errors="replace").strip())
            tail = tail[-5:]
        if not self.stopping and self.process.wait() != 0:
            self.error = " | ".join(tail)
            self.engine.event("CAPTURE ERROR", self.error)

    def feed_stream(self):
        try:
            with self.output.open("wb") as file:
                while not self.stopping:
                    chunk = self.stream.read1(65536)
                    if not chunk:
                        break
                    file.write(chunk)
                    file.flush()
                    self.process.stdin.write(chunk)
                    self.process.stdin.flush()
                    if file.tell() >= 32 * 1024 * 1024:
                        self.error = "32 MB session capture limit reached; restart the capture session"
                        self.engine.event("CAPTURE LIMIT", self.error)
                        break
        except (OSError, ValueError, RuntimeError, HTTPException) as error:
            if not self.stopping:
                self.error = str(error)
                self.engine.event("CAPTURE ERROR", self.error)
        finally:
            if self.process.stdin and not self.process.stdin.closed:
                self.process.stdin.close()

    def stop(self):
        self.stopping = True
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.stream:
            self.stream.close()
        for reader in self.readers:
            reader.join(timeout=2)
        self.process.stdout.close()
        self.process.stderr.close()

    def state(self):
        return {"name": self.name, "running": self.process.poll() is None, "error": self.error,
                "file": self.output.name, "bytes": self.output.stat().st_size if self.output.exists() else 0}
