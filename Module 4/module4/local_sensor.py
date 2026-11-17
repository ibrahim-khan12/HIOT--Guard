"""Offline local Zeek and TShark transport for the regular Module 2 importer."""
from pathlib import Path
import subprocess

from module2.sensor import DICOM_CONTEXT_FIELDS, tshark_fields


class LocalSensor:
    def __init__(self, zeek, tshark, image=None, state=None):
        self.zeek = zeek
        self.tshark = tshark
        self.state = Path(state).resolve() if state else None
        self.container = None
        self.versions = {
            "zeek": self.version(zeek, "zeek version"),
            "tshark": self.version([tshark], "TShark"),
        }
        if image:
            self.container = subprocess.check_output(
                ["docker", "run", "-d", "--rm", "--network", "none", "--cap-drop", "ALL",
                 "--mount", f"type=bind,source={self.state},target=/work",
                 "--entrypoint", "/bin/sh", image, "-c", "sleep 900"],
                text=True, timeout=90).strip()

    @staticmethod
    def version(command, prefix):
        text = subprocess.check_output([*command, "--version"], stderr=subprocess.STDOUT, text=True, timeout=90)
        return next(line for line in text.splitlines() if line.startswith(prefix))

    def analyze(self, capture, output):
        capture = Path(capture).resolve()
        output = Path(output).resolve()
        command = self.zeek
        capture_path = str(capture)
        if self.container:
            working = "/work/" + output.relative_to(self.state).as_posix()
            command = ["docker", "exec", "-w", working, self.container, "zeek"]
            capture_path = capture.name
        with (output / "zeek.stderr").open("wb") as errors:
            subprocess.run([*command, "-C", "-r", capture_path, "LogAscii::use_json=T"],
                           cwd=output, stderr=errors, check=True, timeout=120)
        with (output / "tshark.stderr").open("wb") as errors:
            for name, args in (("packets.tsv", tshark_fields(capture)),
                               ("dicom-contexts.tsv", tshark_fields(capture, DICOM_CONTEXT_FIELDS, True,
                                                                   "dicom.pdu.type == 1 && dicom.pctx.abss.syntax"))):
                with (output / name).open("wb") as stream:
                    subprocess.run([self.tshark, *args], stdout=stream, stderr=errors, check=True, timeout=120)
        return {"versions": self.versions, "analysis_mode": "local_offline"}

    def close(self):
        if self.container:
            subprocess.run(["docker", "stop", "--time", "1", self.container], check=True,
                           stdout=subprocess.DEVNULL, timeout=30)
            self.container = None


def docker_zeek(image, tshark, state):
    command = ["docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL",
               "--entrypoint", "zeek", image]
    return LocalSensor(command, tshark, image, state)
