"""Pinned, network-isolated Zeek/TShark analysis on the existing Linux compute."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shlex
import time
import uuid
import tarfile
import shutil
import sys

from gns3 import private_url

FIELDS = ["frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
          "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "tcp.flags.syn",
          "tcp.flags.ack", "tcp.seq_raw", "tcp.len", "tcp.payload", "dicom.assoc.ae.calling",
          "dicom.assoc.ae.called", "dicom.pctx.abss.syntax", "tcp.stream", "frame.cap_len", "frame.len"]
BASE_IMAGE = "zeek/zeek:8.0.10"
IMAGE = "hiot-module2-sensor:1"


class Sensor:
    def __init__(self, host, state, user="gns3", trust_first_use=False, persistent=False):
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
        self.persistent, self.container = persistent, None
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
        if getattr(self, "container", None):
            name, self.container = self.container, None
            try:
                self.run("docker rm -f " + shlex.quote(name), timeout=10)
            except (OSError, RuntimeError, EOFError):
                pass
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
        channel = stdout.channel
        output, errors = bytearray(), bytearray()
        deadline = time.monotonic() + timeout
        try:
            # Drain both SSH windows without unowned reader threads or unbounded output.
            while True:
                for ready, receive, target in ((channel.recv_ready, channel.recv, output),
                                               (channel.recv_stderr_ready, channel.recv_stderr, errors)):
                    if ready():
                        target.extend(receive(65536))
                        if len(target) > 1024 * 1024:
                            raise RuntimeError("Sensor command output exceeds 1 MiB safety bound")
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    code = channel.recv_exit_status()
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"Sensor command exceeded {timeout:g} seconds")
                if not self.connected():
                    raise ConnectionError("Sensor SSH disconnected during command")
                time.sleep(.01)
            text = output.decode(errors="replace")
            if code:
                raise RuntimeError(f"Sensor command failed ({code}): " +
                                   (text + errors.decode(errors="replace"))[-5000:])
            return text
        finally:
            channel.close()
            stdout.close()
            stderr.close()

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
        image = self.image()
        fields = " ".join("-e " + shlex.quote(field) for field in FIELDS)
        script = ("zeek -C -r input.pcap LogAscii::use_json=T >zeek.stdout 2>zeek.stderr && "
                  "tshark -n -2 -r input.pcap -o tcp.desegment_tcp_streams:TRUE -d tcp.port==11112,dicom "
                  "-T fields -E separator=/t -E quote=d -E occurrence=f " + fields + " >packets.tsv 2>tshark.stderr")
        names = ("conn.log", "weird.log", "capture_loss.log", "zeek.stderr", "tshark.stderr", "packets.tsv")
        script += "; result=$?; tar -cf results.tar --ignore-failed-read " + " ".join(names) + "; exit $result"
        try:
            self.sftp.put(str(capture), job + "/input.pcap")
            if self.versions is None:
                self.versions = self.inspect(image)
            try:
                if self.persistent:
                    if self.container and time.monotonic()-self.container_started > 840:
                        self.run("docker rm -f " + shlex.quote(self.container), timeout=10)
                        self.container = None
                    if self.container is None:
                        self.container = "hiot-sensor-" + uuid.uuid4().hex
                        command = ("docker run -d --rm --name " + self.container + " --label hiot.module=2 "
                                   "--network none --cap-drop ALL --read-only --pids-limit 128 --memory 768m --cpus 1 "
                                   "--tmpfs /tmp:rw,noexec,size=64m --user " + self.uid + ":" + self.gid +
                                   " -v " + shlex.quote(self.root+":/work") + " --entrypoint /bin/sh " +
                                   shlex.quote(image) + " -c 'sleep 900'")
                        self.run(command, timeout=30)
                        self.container_started = time.monotonic()
                    command = "docker exec -w " + shlex.quote("/work/"+job.rsplit("/", 1)[-1]) + " " + self.container + " sh -c " + shlex.quote(script)
                else:
                    command = self.docker(image, job, script)
                self.run(command, timeout=180)
            except (RuntimeError, OSError, EOFError) as error:
                if self.persistent and self.container:
                    name, self.container = self.container, None
                    try:
                        self.run("docker rm -f " + shlex.quote(name), timeout=10)
                    except (OSError, RuntimeError, EOFError):
                        pass
                diagnostics = []
                for name in ("zeek.stderr", "tshark.stderr"):
                    try:
                        with self.sftp.open(job + "/" + name) as source:
                            diagnostics.append(source.read(2000).decode(errors="replace"))
                    except (OSError, EOFError):
                        pass
                raise RuntimeError(str(error) + "\n" + "\n".join(diagnostics)) from error
            if self.sftp.stat(job + "/results.tar").st_size > 128*1024*1024:
                raise ValueError("Sensor result exceeds 128 MiB transfer bound")
            archive = output / "results.tar"
            self.sftp.get(job + "/results.tar", str(archive))
            try:
                with tarfile.open(archive) as bundle:
                    members = {m.name: m for m in bundle.getmembers()}
                    for name in names:
                        member = members.get(name)
                        if member is None:
                            if name in ("packets.tsv", "zeek.stderr", "tshark.stderr"):
                                raise ValueError("Missing required sensor output: " + name)
                            continue
                        if not member.isfile() or member.size > 64*1024*1024:
                            raise ValueError("Invalid or oversized sensor output: " + name)
                        with bundle.extractfile(member) as source, (output/name).open("wb") as target:
                            shutil.copyfileobj(source, target)
            finally:
                archive.unlink(missing_ok=True)
            return {"versions": self.versions, "image_id": image, "checksum_validation": "disabled for virtual NIC offload (-C)",
                    "analysis_seconds": round(time.monotonic() - started, 4), "remote_job": job}
        finally:
            # Delete only this UUID job's own files; preserve the build, image and other sessions.
            primary_error = sys.exc_info()[0]
            try:
                for name in self.sftp.listdir(job):
                    self.sftp.remove(job + "/" + name)
                self.sftp.rmdir(job)
            except (OSError, EOFError):
                # A disconnected SSH client cannot clean its remote job; preserve the original error.
                if self.connected() and primary_error is None:
                    raise
