"""Bounded offline sensor transport inside the explicitly owned pilot project."""
import base64
import json
from pathlib import Path
import subprocess
import time
import urllib.request

from gns3 import GNS3
from module2.sensor import DICOM_CONTEXT_FIELDS, tshark_fields

WORKER = r'''
import base64,json,os,subprocess,tempfile
from pathlib import Path
from http.server import BaseHTTPRequestHandler,HTTPServer
class API(BaseHTTPRequestHandler):
 def do_POST(self):
  if self.headers.get("Authorization") != "Bearer "+os.environ["PILOT_TOKEN"]:
   self.send_error(403); return
  size=int(self.headers.get("Content-Length","0"))
  if size<1 or size>45*1024*1024:
   self.send_error(413); return
  data=json.loads(self.rfile.read(size))
  with tempfile.TemporaryDirectory(prefix="module4-") as folder:
   p=Path(folder); (p/"input.pcap").write_bytes(base64.b64decode(data["pcap"],validate=True))
   run=subprocess.run(["zeek","-C","-r","input.pcap","LogAscii::use_json=T"],cwd=p,capture_output=True,timeout=120)
   output={"returncode":run.returncode,"stderr":run.stderr.decode(errors="replace"),
           "version":subprocess.check_output(["zeek","--version"],text=True).strip(),
           "files":{name:(p/name).read_text() for name in ("conn.log","weird.log","capture_loss.log") if (p/name).exists()}}
  raw=json.dumps(output).encode(); self.send_response(200); self.send_header("Content-Length",str(len(raw)));self.end_headers();self.wfile.write(raw)
 def log_message(self,*args): pass
HTTPServer(("0.0.0.0",8080),API).serve_forever()
'''


class PilotSensor:
    def __init__(self, manifest_path, tshark):
        self.manifest_path = Path(manifest_path)
        self.manifest = json.loads(self.manifest_path.read_text())
        self.lab = GNS3(self.manifest["server"], self.manifest_path.parent)
        pid = self.manifest["project_id"]
        if "sensor" not in self.manifest["nodes"]:
            encoded = base64.b64encode(WORKER.encode()).decode()
            node = self.lab.api(f"/projects/{pid}/nodes", {"compute_id": "local", "name": "pilot-offline-sensor", "node_type": "docker", "console_type": "http",
                "properties": {"image": "hiot-module2-sensor:1", "adapters": 1, "console_http_port": 8080,
                    "environment": "PILOT_TOKEN=" + self.manifest["token"],
                    "start_command": f'python3 -u -c "import base64;exec(base64.b64decode(\'{encoded}\'))"'}})
            self.manifest["nodes"]["sensor"] = node["node_id"]
            self.manifest_path.write_text(json.dumps(self.manifest, indent=2))
        nid = self.manifest["nodes"]["sensor"]
        self.lab.api(f"/projects/{pid}/nodes/{nid}/start", {})
        node = self.lab.api(f"/projects/{pid}/nodes/{nid}")
        self.url = self.manifest["server"].rsplit(":",1)[0] if self.manifest["server"].count(":") > 1 else self.manifest["server"]
        self.url += ":" + str(node["console"])
        self.tshark = str(tshark)
        self.versions = {"tshark": subprocess.check_output([self.tshark,"--version"],text=True).splitlines()[0]}
        time.sleep(3)

    def analyze(self, capture, output):
        started = time.monotonic()
        raw = Path(capture).read_bytes()
        if len(raw) > 32*1024*1024:
            raise ValueError("Capture exceeds pilot sensor limit")
        request = urllib.request.Request(self.url, data=json.dumps({"pcap": base64.b64encode(raw).decode()}).encode(),
                                         headers={"Authorization": "Bearer " + self.manifest["token"], "Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=150) as response:
            data = response.read(64*1024*1024+1)
        if len(data) > 64*1024*1024:
            raise ValueError("Sensor output exceeds bound")
        result = json.loads(data)
        if result["returncode"]:
            raise RuntimeError(result["stderr"])
        output = Path(output)
        output.mkdir(parents=True, exist_ok=True)
        self.versions["zeek"] = result["version"]
        for name in ("conn.log", "weird.log", "capture_loss.log"):
            if name in result["files"]:
                (output/name).write_text(result["files"][name])
        (output/"zeek.stderr").write_text(result["stderr"])
        with (output/"tshark.stderr").open("wb") as errors:
            for name,args in (("packets.tsv",tshark_fields(capture)),("dicom-contexts.tsv",tshark_fields(capture,DICOM_CONTEXT_FIELDS,True,"dicom.pdu.type == 1 && dicom.pctx.abss.syntax"))):
                with (output/name).open("wb") as stream:
                    subprocess.run([self.tshark,*args],stdout=stream,stderr=errors,check=True,timeout=120)
        return {"versions": self.versions, "analysis_mode": "isolated_gns3_pilot_zeek_local_tshark",
                "analysis_seconds": time.monotonic()-started, "checksum_validation": "disabled for virtual NIC offload (-C)"}
