"""Pinned, network-isolated Zeek/TShark analysis on the existing Linux compute."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shlex
import time
import uuid

from gns3 import private_url

FIELDS = ["frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
          "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "tcp.flags.syn",
          "tcp.flags.ack", "tcp.seq_raw", "tcp.len", "tcp.payload", "dicom.assoc.ae.calling",
          "dicom.assoc.ae.called", "dicom.pctx.abss.syntax", "tcp.stream", "frame.cap_len", "frame.len"]
BASE_IMAGE = "zeek/zeek:8.0.10"
IMAGE = "hiot-module2-sensor:1"


class Sensor:
    def __init__(self, host, state, user="gns3", trust_first_use=False):
        import paramiko
        private_url("http://" + host)
        self.state = Path(state)
        self.state.mkdir(parents=True, exist_ok=True)
        self.client = paramiko.SSHClient()
        known = self.state / "known_hosts"
        if known.exists():
            self.client.load_host_keys(str(known))
        if trust_first_use:
            class Remember(paramiko.MissingHostKeyPolicy):
                def missing_host_key(policy, client, hostname, key):
                    client.get_host_keys().add(hostname, key.get_name(), key)
                    client.save_host_keys(str(known))
            self.client.set_missing_host_key_policy(Remember())
        else:
            self.client.set_missing_host_key_policy(paramiko.RejectPolicy())
        self.sftp = None
        try:
            self.client.connect(host, username=user, password=os.environ.get("GNS3_SSH_PASSWORD"),
                                timeout=15, banner_timeout=15, auth_timeout=15)
            self.sftp = self.client.open_sftp()
            self.sftp.get_channel().settimeout(180)
            self.root = self.sftp.normalize(".") + "/hiot-module2"
            try:
                self.sftp.mkdir(self.root)
            except OSError:
                self.sftp.stat(self.root)
            self.uid = self.run("id -u").strip()
            self.gid = self.run("id -g").strip()
        except Exception:
            self.close()
            raise
        self.versions = None

    def close(self):
        for connection in (self.sftp, self.client):
            if connection:
                try:
                    connection.close()
                except Exception:
                    pass

    def connected(self):
        transport = self.client.get_transport()
        return bool(transport and transport.is_active() and transport.is_authenticated())

    def run(self, command, timeout=600):
        _, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        # Setup output is bounded; stderr is drained concurrently to avoid SSH window deadlock.
        import threading
        errors = []
        reader = threading.Thread(target=lambda: errors.append(stderr.read()), daemon=True)
        reader.start()
        output = stdout.read().decode(errors="replace")
        reader.join(timeout)
        code = stdout.channel.recv_exit_status()
        if code:
            raise RuntimeError(f"Sensor command failed ({code}): " + (output + b"".join(errors).decode(errors="replace"))[-5000:])
        return output

    def setup(self):
        toolchain = json.loads(Path(__file__).with_name("toolchain.json").read_text())
        digest, candidate = toolchain["zeek_digest"], toolchain["tshark_package"]
        self.run("docker pull " + shlex.quote(digest))
        build = self.root + "/build"
        try:
            self.sftp.mkdir(build)
        except OSError:
            self.sftp.stat(build)
        self.sftp.put(str(Path(__file__).with_name("sensor.Dockerfile")), build + "/Dockerfile")
        self.run("docker build --build-arg " + shlex.quote("ZEEK_BASE=" + digest) + " --build-arg " +
                 shlex.quote("TSHARK_VERSION=" + candidate) + " -t " + IMAGE + " " + shlex.quote(build), timeout=1200)
        image_id = json.loads(self.run("docker image inspect " + IMAGE))[0]["Id"]
        self.versions = self.inspect(image_id)
        lock = {"base_image": BASE_IMAGE, "base_digest": digest, "image_id": image_id,
                "tshark_package": candidate, "versions": self.versions,
                "ssh_host_key_sha256": hashlib.sha256(self.client.get_transport().get_remote_server_key().asbytes()).hexdigest()}
        (self.state / "sensor-lock.json").write_text(json.dumps(lock, indent=2))
        return lock

    def image(self):
        lock = self.state / "sensor-lock.json"
        if not lock.exists():
            raise RuntimeError("Run module2 setup-sensor first; a pinned sensor-lock.json is required")
        return json.loads(lock.read_text())["image_id"]

    def docker(self, image, job, script):
        return ("docker run --rm --label hiot.module=2 --network none --cap-drop ALL --read-only --pids-limit 128 "
                "--memory 768m --cpus 1 --tmpfs /tmp:rw,noexec,size=64m --user " + self.uid + ":" + self.gid +
                " -v " + shlex.quote(job + ":/work") + " -w /work " + shlex.quote(image) + " sh -c " + shlex.quote(script))

    def inspect(self, image):
        output = self.run(self.docker(image, self.root, "zeek --version && tshark --version"), timeout=30)
        return {"zeek": next((x for x in output.splitlines() if x.startswith("zeek version")), "unavailable"),
                "tshark": next((x for x in output.splitlines() if x.startswith("TShark")), "unavailable")}

    def analyze(self, capture, output):
        output = Path(output)
        output.mkdir(parents=True, exist_ok=True)
        job = self.root + "/job-" + uuid.uuid4().hex
        self.sftp.mkdir(job)
        started = time.monotonic()
        self.sftp.put(str(capture), job + "/input.pcap")
        image = self.image()
        self.versions = self.inspect(image)
        fields = " ".join("-e " + shlex.quote(field) for field in FIELDS)
        script = ("zeek -C -r input.pcap LogAscii::use_json=T >zeek.stdout 2>zeek.stderr && "
                  "tshark -n -2 -r input.pcap -o tcp.desegment_tcp_streams:TRUE -d tcp.port==11112,dicom "
                  "-T fields -E separator=/t -E quote=d -E occurrence=f " + fields + " >packets.tsv 2>tshark.stderr")
        try:
            try:
                self.run(self.docker(image, job, script), timeout=180)
            except RuntimeError as error:
                diagnostics = []
                for name in ("zeek.stderr", "tshark.stderr"):
                    try:
                        with self.sftp.open(job + "/" + name) as source:
                            diagnostics.append(source.read().decode(errors="replace")[-2000:])
                    except FileNotFoundError:
                        pass
                raise RuntimeError(str(error) + "\n" + "\n".join(diagnostics)) from error
            for name in ("conn.log", "weird.log", "capture_loss.log", "zeek.stderr", "tshark.stderr", "packets.tsv"):
                try:
                    self.sftp.get(job + "/" + name, str(output / name))
                except FileNotFoundError:
                    if name in ("packets.tsv", "zeek.stderr", "tshark.stderr"):
                        raise
            return {"versions": self.versions, "image_id": image, "checksum_validation": "disabled for virtual NIC offload (-C)",
                    "analysis_seconds": round(time.monotonic() - started, 4), "remote_job": job}
        finally:
            # Delete only this UUID job's own files; preserve the build, image and other sessions.
            for name in self.sftp.listdir(job):
                self.sftp.remove(job + "/" + name)
            self.sftp.rmdir(job)
