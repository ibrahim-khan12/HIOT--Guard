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
from config import CAPTURE_ROLES, NORMAL_ROLES, ROLES
from scenario_profile import IMAGE as SCENARIO_IMAGE, MANIFEST as SCENARIO_MANIFEST, PROFILE, ROLE_IPS

IMAGE = "iomt-hospital:2"
MANIFEST_FILE = "gns3-hospital-v2-manifest.json"
NODE_POSITIONS = {
    "workstation": (-570, -300), "vendor": (-570, -190), "unregistered": (-570, -80),
    "pump": (-570, 30), "modality": (-570, 140), "ultrasound": (-570, 250),
    "monitor": (-570, 360), "lab_analyzer": (-570, 470), "mri": (-570, 580),
    "xray": (-570, 690), "ventilator": (-570, 800), "dialysis": (-570, 910),
    "ecg": (-570, 1020), "pacs": (470, 190), "ehr": (470, 420), "gateway": (0, 260),
}
SWITCH_POSITIONS = {"staff": (-260, -190), "medical": (-260, 530), "services": (240, 300)}


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
    def __init__(self, url, folder, profile=None):
        if profile not in (None, PROFILE):
            raise ValueError("Unknown GNS3 lab profile")
        self.profile = profile
        self.manifest_file = SCENARIO_MANIFEST if profile == PROFILE else MANIFEST_FILE
        self.image = SCENARIO_IMAGE if profile == PROFILE else IMAGE
        self.roles = dict(ROLES)
        if profile == PROFILE:
            self.roles.update({role: {"name": role.replace("_", " ").title(), "zone": "scenario"}
                               for role in ROLE_IPS})
        self.url = private_url(url)
        self.folder = Path(folder)
        self.headers = {}
        if os.environ.get("GNS3_USER"):
            credential = f"{os.environ['GNS3_USER']}:{os.environ.get('GNS3_PASSWORD', '')}"
            self.headers["Authorization"] = "Basic " + base64.b64encode(credential.encode()).decode()
        self.manifest = None

    def api(self, endpoint, data=None):
        return request_json(self.url + "/v2" + endpoint, data, self.headers)

    def attach_imported(self, project_id):
        """Register an imported portable project only after validating its full lab wiring."""
        if (self.folder / MANIFEST_FILE).exists():
            raise ValueError(f"{MANIFEST_FILE} already exists. Keep the current lab; use a fresh runs folder to attach another project.")
        version = self.api("/version")
        if not str(version.get("version", "")).startswith("2.2."):
            raise ValueError("This adapter requires GNS3 2.2.x")
        project = self.api(f"/projects/{project_id}")
        nodes = self.api(f"/projects/{project_id}/nodes")
        links = self.api(f"/projects/{project_id}/links")
        roles, switches = {}, {}
        for node in nodes:
            properties = node.get("properties", {})
            if node.get("node_type") == "docker":
                environment = dict(line.split("=", 1) for line in properties.get("environment", "").splitlines() if "=" in line)
                role = environment.get("LAB_ROLE")
                if (role not in ROLES or role in roles or environment.get("LAB_MODE") != "gns3"
                        or properties.get("image") != IMAGE or node.get("console_type") != "http"):
                    raise ValueError(f"Unexpected or duplicate Docker actor in imported project: {node.get('name')}")
                roles[role] = node["node_id"]
            elif node.get("node_type") == "ethernet_switch":
                name = "".join(character for character in node.get("name", "").lower() if character.isalnum())
                zone = next((zone for zone in ("staff", "medical", "services") if name == zone + "switch"), None)
                if zone is None or zone in switches:
                    raise ValueError(f"Unexpected or duplicate switch in imported project: {node.get('name')}")
                switches[zone] = node["node_id"]
            else:
                raise ValueError(f"Unexpected node type in imported project: {node.get('node_type')}")
        if set(roles) != set(ROLES) or set(switches) != {"staff", "medical", "services"} or len(links) != len(ROLES) + 2:
            raise ValueError("Imported project must contain exactly the 16 hospital actors, 3 switches, and 18 links")

        def matching_link(first, second):
            matches = [link for link in links if {endpoint["node_id"] for endpoint in link.get("nodes", [])} == {first, second}]
            if len(matches) != 1:
                raise ValueError(f"Expected one link between {first} and {second}; found {len(matches)}")
            return matches[0]["link_id"]

        actor_links = {role: matching_link(node_id, switches[ROLES[role]["zone"]])
                       for role, node_id in roles.items() if role != "gateway"}
        gateway_links = {zone: matching_link(roles["gateway"], switch_id) for zone, switch_id in switches.items()}
        if len(set((*actor_links.values(), *gateway_links.values()))) != len(links):
            raise ValueError("Imported project has unexpected or repeated wiring")
        self.manifest = {"server": self.url, "project_id": project["project_id"], "project_name": project["name"],
                         "nodes": roles, "links": actor_links, "switches": switches,
                         "gateway_links": gateway_links, "complete": True}
        self.save()
        return self.manifest

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
        manifest_path = self.folder / self.manifest_file
        saved = None
        if manifest_path.exists():
            saved = json.loads(manifest_path.read_text())
            if saved["server"] == self.url:
                if saved.get("profile") != self.profile:
                    raise ValueError("Saved GNS3 manifest has the wrong profile")
                self.manifest = saved
                self.api(f"/projects/{saved['project_id']}/open", {})
                if saved.get("complete"):
                    return saved
            else:
                raise ValueError("A lab already exists for a different server. Keep its manifest; use a separate project folder for another server.")
        if not saved:
            label = "HIoT Controlled Scenarios v1" if self.profile else "HIoT Mini Hospital Expanded"
            project = self.api("/projects", {"name": label + " " + time.strftime("%Y%m%d-%H%M%S"), "auto_close": False})
            self.manifest = {"server": self.url, "project_id": project["project_id"], "project_name": project["name"],
                             "nodes": {}, "links": {}, "switches": {}, "gateway_links": {}, "complete": False}
            if self.profile:
                self.manifest.update(profile=self.profile, capture_sources=[*CAPTURE_ROLES, *ROLE_IPS])
        pid = self.manifest["project_id"]
        self.save()
        try:
            for role, details in self.roles.items():
                if role in self.manifest["nodes"]:
                    continue
                position = NODE_POSITIONS.get(role)
                if position is None:
                    position = (850, 250 + 125 * list(ROLE_IPS).index(role))
                environment = f"LAB_ROLE={role}\nLAB_MODE=gns3"
                if self.profile:
                    environment += f"\nLAB_PROFILE={self.profile}"
                node = self.api(f"/projects/{pid}/nodes", {
                    "compute_id": compute["compute_id"], "name": details["name"], "node_type": "docker",
                    "console_type": "http", "x": position[0], "y": position[1],
                    "properties": {"image": self.image, "adapters": 3 if role == "gateway" else 1,
                                   "start_command": "python /lab/agent.py", "environment": environment,
                                   "console_http_port": 8080},
                })
                self.manifest["nodes"][role] = node["node_id"]
                self.save()
            switches = self.manifest.setdefault("switches", {})
            gateway_links = self.manifest.setdefault("gateway_links", {})
            zones = ("staff", "medical", "services", "scenario") if self.profile else ("staff", "medical", "services")
            for i, zone in enumerate(zones):
                if zone not in switches:
                    x, y = SWITCH_POSITIONS.get(zone, (1100, 430))
                    node = self.api(f"/projects/{pid}/nodes", {"compute_id": compute["compute_id"], "name": zone + " switch",
                                    "node_type": "ethernet_switch", "x": x, "y": y,
                                    "properties": {"ports_mapping": [{"name": f"Ethernet{p}", "port_number": p, "type": "access", "vlan": 1} for p in range(16)]}})
                    switches[zone] = node["node_id"]
                    self.save()
                gateway = self.manifest["nodes"]["gateway"]
                if zone != "scenario" and zone not in gateway_links:
                    gateway_links[zone] = self.link(pid, gateway, i, switches[zone], 0)["link_id"]
                    self.save()
            port = dict.fromkeys(zones, 1)
            for role, details in self.roles.items():
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
            raise RuntimeError(f"Project {pid} was saved but setup is incomplete. Build {self.image} on the Linux compute first. Details: {error}") from error

    def save(self):
        self.folder.mkdir(parents=True, exist_ok=True)
        path = self.folder / self.manifest_file
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.manifest, indent=2))
        temporary.replace(path)

    def link(self, pid, first, adapter, switch, port):
        return self.api(f"/projects/{pid}/links", {"nodes": [
            {"node_id": first, "adapter_number": adapter, "port_number": 0},
            {"node_id": switch, "adapter_number": 0, "port_number": port}]})

    def start(self):
        if not self.manifest.get("complete"):
            raise ValueError("The saved topology is incomplete. Finish its image/setup in GNS3; do not present it as a working lab.")
        pid = self.manifest["project_id"]
        existing = {n["node_id"]: n for n in self.api(f"/projects/{pid}/nodes")}
        if self.profile:
            self.validate_isolation(existing)
        for role in ("gateway", "pacs", "ehr", *NORMAL_ROLES, "unregistered", *(ROLE_IPS if self.profile else ())):
            node_id = self.manifest['nodes'][role]
            if existing.get(node_id, {}).get("status") != "started":
                self.api(f"/projects/{pid}/nodes/{node_id}/start", {})
        self.nodes = {n["node_id"]: n for n in self.api(f"/projects/{pid}/nodes")}
        self.computes = {c["compute_id"]: c for c in self.api("/computes")}
        for role in self.roles:
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

    def validate_isolation(self, nodes=None):
        pid = self.manifest["project_id"]
        if nodes is None:
            nodes = {node["node_id"]: node for node in self.api(f"/projects/{pid}/nodes")}
        roles = {role: self.manifest["nodes"][role] for role in ROLE_IPS}
        switch = self.manifest["switches"]["scenario"]
        if nodes.get(switch, {}).get("node_type") != "ethernet_switch":
            raise ValueError("The scenario segment must use its dedicated Ethernet switch")
        expected = {self.manifest["links"][role]: {node_id, switch} for role, node_id in roles.items()}
        for role, node_id in roles.items():
            node = nodes[node_id]
            props = node["properties"]
            environment = set(props.get("environment", "").splitlines())
            if (node["node_type"] != "docker" or props.get("image") != SCENARIO_IMAGE or props.get("adapters") != 1
                    or not {f"LAB_ROLE={role}", "LAB_MODE=gns3", f"LAB_PROFILE={PROFILE}"}.issubset(environment)):
                raise ValueError(f"Invalid isolated actor configuration for {role}")
        isolated = {switch, *roles.values()}
        actual = {}
        for link in self.api(f"/projects/{pid}/links"):
            endpoints = {endpoint["node_id"] for endpoint in link["nodes"]}
            if endpoints & isolated:
                actual[link["link_id"]] = endpoints
        if actual != expected:
            raise ValueError("The scenario switch must connect only to its four isolated actors")

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
        return request_json(base + endpoint, data, timeout=2 if endpoint == "/scenario" else 20)

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
        for role in self.manifest.get("capture_sources", CAPTURE_ROLES):
            try:
                self.api(f"/projects/{self.manifest['project_id']}/links/{self.manifest['links'][role]}/stop_capture", {})
            except Exception:
                pass
