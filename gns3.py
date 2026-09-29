"""GNS3 2.2 controller adapter. It creates only a new, isolated lab project."""
import base64
import http.client
import ipaddress
import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from config import ROLES

IMAGE = "iomt-live:1"
NODE_POSITIONS = {"workstation": (-480, -160), "pump": (-480, 120), "modality": (-480, 280),
                  "pacs": (420, -160), "ehr": (420, 80), "gateway": (0, 0)}
SWITCH_POSITIONS = {"staff": (-230, -160), "medical": (-230, 180), "services": (220, 0)}


class PCAPStream:
    def __init__(self, connection, transport):
        self.connection, self.transport = connection, transport
        self.response = None
        self.closed = False

    def read1(self, size):
        if self.closed:
            return b""
        if self.response is None:
            response = self.connection.getresponse()
            if self.closed:
                response.close()
                return b""
            self.response = response
            if response.status != 200:
                raise RuntimeError(f"GNS3 capture HTTP {response.status}: {response.read(2000).decode(errors='replace')}")
        return self.response.read1(size)

    def close(self):
        self.closed = True
        # Wake a reader waiting on a quiet network before closing its buffered file.
        try:
            self.transport.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        if self.response is not None:
            self.response.close()
        self.connection.close()


def private_url(value):
    url = urllib.parse.urlparse(value)
    if url.scheme not in ("http", "https") or url.username or url.password or url.path not in ("", "/"):
        raise ValueError("Use a private GNS3 server address, such as http://192.168.56.101:3080")
    if url.hostname != "localhost":
        try:
            ip = ipaddress.ip_address(url.hostname or "")
        except ValueError as error:
            raise ValueError("Use the GNS3 VM's numeric private IP address") from error
        if not (ip.is_private or ip.is_loopback) or ip.is_unspecified:
            raise ValueError("Only a private lab server is allowed")
    return value.rstrip("/")


def request_json(url, data=None, headers=None, timeout=20):
    parsed = urllib.parse.urlparse(url)
    connection_type = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    connection = connection_type(parsed.hostname, parsed.port, timeout=timeout)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    try:
        connection.request("POST" if data is not None else "GET", path,
                           body=json.dumps(data).encode() if data is not None else None,
                           headers={"Content-Type": "application/json", **(headers or {})})
        response = connection.getresponse()
        raw = response.read()
        if response.status >= 400:
            raise RuntimeError(f"HTTP {response.status}: {raw[:2000].decode(errors='replace')}")
        return json.loads(raw) if raw else {}
    finally:
        connection.close()


class GNS3:
    def __init__(self, url, folder):
        self.url = private_url(url)
        self.folder = Path(folder)
        self.headers = {}
        if os.environ.get("GNS3_USER"):
            credential = f"{os.environ['GNS3_USER']}:{os.environ.get('GNS3_PASSWORD', '')}"
            self.headers["Authorization"] = "Basic " + base64.b64encode(credential.encode()).decode()
        self.manifest = None

    def api(self, endpoint, data=None):
        return request_json(self.url + "/v2" + endpoint, data, self.headers)

    def build(self):
        version = self.api("/version")
        if not str(version.get("version", "")).startswith("2.2."):
            raise ValueError("This adapter targets GNS3 2.2.x. GNS3 3.x uses a different API.")
        computes = self.api("/computes")
        candidates = [c for c in computes if c.get("connected") and c.get("capabilities", {}).get("platform") == "linux"
                      and "docker" in c.get("capabilities", {}).get("node_types", [])]
        if not candidates:
            raise ValueError("Connect a GNS3 VM/Linux compute with Docker support first; Windows local compute cannot run this topology.")
        compute = candidates[0]
        manifest_path = self.folder / "gns3-manifest.json"
        saved = None
        if manifest_path.exists():
            saved = json.loads(manifest_path.read_text())
            if saved["server"] == self.url:
                self.manifest = saved
                self.api(f"/projects/{saved['project_id']}/open", {})
                if saved.get("complete"):
                    return saved
            else:
                raise ValueError("A lab already exists for a different server. Keep its manifest; use a separate project folder for another server.")
        if not saved:
            project = self.api("/projects", {"name": "IoMT Live Defense " + time.strftime("%Y%m%d-%H%M%S"), "auto_close": False})
            self.manifest = {"server": self.url, "project_id": project["project_id"], "project_name": project["name"],
                             "nodes": {}, "links": {}, "switches": {}, "gateway_links": {}, "complete": False}
        pid = self.manifest["project_id"]
        self.save()
        try:
            for role, details in ROLES.items():
                if role in self.manifest["nodes"]:
                    continue
                node = self.api(f"/projects/{pid}/nodes", {
                    "compute_id": compute["compute_id"], "name": details["name"], "node_type": "docker",
                    "console_type": "http", "x": NODE_POSITIONS[role][0], "y": NODE_POSITIONS[role][1],
                    "properties": {"image": IMAGE, "adapters": 3 if role == "gateway" else 1,
                                   "start_command": "python /lab/agent.py", "environment": f"LAB_ROLE={role}\nLAB_MODE=gns3",
                                   "console_http_port": 8080},
                })
                self.manifest["nodes"][role] = node["node_id"]
                self.save()
            switches = self.manifest.setdefault("switches", {})
            gateway_links = self.manifest.setdefault("gateway_links", {})
            for i, zone in enumerate(("staff", "medical", "services")):
                if zone not in switches:
                    node = self.api(f"/projects/{pid}/nodes", {"compute_id": compute["compute_id"], "name": zone + " switch",
                                    "node_type": "ethernet_switch", "x": SWITCH_POSITIONS[zone][0], "y": SWITCH_POSITIONS[zone][1],
                                    "properties": {"ports_mapping": [{"name": f"Ethernet{p}", "port_number": p, "type": "access", "vlan": 1} for p in range(8)]}})
                    switches[zone] = node["node_id"]
                    self.save()
                gateway = self.manifest["nodes"]["gateway"]
                if zone not in gateway_links:
                    gateway_links[zone] = self.link(pid, gateway, i, switches[zone], 0)["link_id"]
                    self.save()
            port = {"staff": 1, "medical": 1, "services": 1}
            for role, details in ROLES.items():
                if role == "gateway":
                    continue
                zone = details["zone"]
                if role not in self.manifest["links"]:
                    link = self.link(pid, self.manifest["nodes"][role], 0, switches[zone], port[zone])
                    self.manifest["links"][role] = link["link_id"]
                    self.save()
                port[zone] += 1
            self.manifest["complete"] = True
            self.save()
            return self.manifest
        except Exception as error:
            raise RuntimeError(f"Project {pid} was saved but setup is incomplete. Build {IMAGE} on the Linux compute first. Details: {error}") from error

    def save(self):
        self.folder.mkdir(parents=True, exist_ok=True)
        (self.folder / "gns3-manifest.json").write_text(json.dumps(self.manifest, indent=2))

    def link(self, pid, first, adapter, switch, port):
        return self.api(f"/projects/{pid}/links", {"nodes": [
            {"node_id": first, "adapter_number": adapter, "port_number": 0},
            {"node_id": switch, "adapter_number": 0, "port_number": port}]})

    def start(self):
        if not self.manifest.get("complete"):
            raise ValueError("The saved topology is incomplete. Finish its image/setup in GNS3; do not present it as a working lab.")
        pid = self.manifest["project_id"]
        existing = {n["node_id"]: n for n in self.api(f"/projects/{pid}/nodes")}
        for role in ("gateway", "pacs", "ehr", "workstation", "pump", "modality"):
            node_id = self.manifest['nodes'][role]
            if existing.get(node_id, {}).get("status") != "started":
                self.api(f"/projects/{pid}/nodes/{node_id}/start", {})
        self.nodes = {n["node_id"]: n for n in self.api(f"/projects/{pid}/nodes")}
        self.computes = {c["compute_id"]: c for c in self.api("/computes")}
        for role in ROLES:
            error = None
            for _ in range(30):
                try:
                    self.agent(role, "/state")
                    break
                except Exception as caught:
                    error = caught
                    time.sleep(0.5)
            else:
                raise RuntimeError(f"{role} management service is unavailable: {error}")

    def agent(self, role, endpoint, data=None):
        node = self.nodes[self.manifest["nodes"][role]]
        host = node.get("console_host")
        compute = self.computes[node["compute_id"]]
        if host in (None, "0.0.0.0", "::", "127.0.0.1", "localhost"):
            host = compute.get("host") or urllib.parse.urlparse(self.url).hostname
            controller = urllib.parse.urlparse(self.url).hostname
            if host in ("127.0.0.1", "localhost") and controller not in ("localhost", "127.0.0.1", "::1"):
                host = urllib.parse.urlparse(self.url).hostname
        base = private_url(f"http://{host}:{node['console']}")
        return request_json(base + endpoint, data)

    def stream(self, role):
        pid, link = self.manifest["project_id"], self.manifest["links"][role]
        info = self.api(f"/projects/{pid}/links/{link}")
        if not info.get("capturing"):
            self.api(f"/projects/{pid}/links/{link}/start_capture", {"capture_file_name": f"iomt-{role}.pcap", "data_link_type": "DLT_EN10MB"})
        url = urllib.parse.urlparse(self.url)
        connection_type = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
        connection = connection_type(url.hostname, url.port, timeout=20)
        try:
            connection.request("GET", f"/v2/projects/{pid}/links/{link}/pcap", headers=self.headers)
            transport = connection.sock
            # GNS3 can defer its PCAP headers until the first packet. Only the reader
            # thread waits for them, so a quiet lab can still connect and start traffic.
            transport.settimeout(None)
            return PCAPStream(connection, transport)
        except Exception:
            connection.close()
            raise

    def stop_captures(self):
        for role in ("workstation", "pump", "modality"):
            try:
                self.api(f"/projects/{self.manifest['project_id']}/links/{self.manifest['links'][role]}/stop_capture", {})
            except Exception:
                pass
