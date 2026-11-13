"""Fixed experiment definitions shared by the controller and disposable actors."""
import re

PROFILE = "scenarios-v1"
MANIFEST = "gns3-hospital-scenarios-v1-manifest.json"
IMAGE = "iomt-hospital:scenarios-v1"
ROLE_IPS = {
    "burst_a": "10.77.90.11",
    "burst_b": "10.77.90.12",
    "scenario_service": "10.77.90.20",
    "arp_observer": "10.77.90.30",
}
UDP_PORT = 19000
MQTT_PORT = 1883
MQTT_TOPIC = "hiot/lab/synthetic"
PAYLOAD_SIZE = 128
BASELINE_SECONDS = 5
BURST_SECONDS = 5
UDP_RATE = 25
MQTT_RATE = 10
RECOVERY_SECONDS = 5
REQUEST_ID = re.compile(r"[a-zA-Z0-9_-]{1,80}")
RUN_ID = re.compile(r"[0-9a-f]{32}")
MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")

SCENARIOS = {
    "workstation-recon": {"label": "Workstation reconnaissance", "actors": {"workstation": "recon"},
                          "targets": {"pacs": [445, 3389, 11112, 8081], "ehr": [445, 3389, 11112, 8081]},
                          "captures": ["workstation"], "seconds": 10},
    "pump-to-pacs": {"label": "Unexpected pump-to-PACS traffic", "actors": {"pump": "anomaly"},
                    "targets": {"pacs": [11112]}, "captures": ["pump", "modality"], "seconds": 8},
    "udp-single": {"label": "Single-source UDP burst", "actors": {"burst_a": "udp"},
                   "targets": {"scenario_service": [UDP_PORT]}, "captures": ["burst_a", "scenario_service"],
                   "seconds": BURST_SECONDS},
    "udp-dual": {"label": "Two-source UDP burst", "actors": {"burst_a": "udp", "burst_b": "udp"},
                 "targets": {"scenario_service": [UDP_PORT]}, "captures": ["burst_a", "burst_b", "scenario_service"],
                 "seconds": BURST_SECONDS},
    "mqtt-burst": {"label": "MQTT publish burst", "actors": {"burst_a": "mqtt"},
                   "targets": {"scenario_service": [MQTT_PORT]}, "captures": ["burst_a", "scenario_service", "arp_observer"],
                   "seconds": BURST_SECONDS},
    "arp-conflict": {"label": "Conflicting ARP claims", "actors": {"scenario_service": "arp", "burst_a": "arp"},
                     "targets": {"arp_observer": []}, "captures": ["burst_a", "scenario_service", "arp_observer"],
                     "seconds": 2},
}


def capture_sources(manifest, hospital_sources):
    links = manifest.get("links", {})
    profile = manifest.get("profile")
    expected = set(hospital_sources)
    if profile == PROFILE:
        expected.update(ROLE_IPS)
    elif profile is not None:
        raise ValueError("Unsupported GNS3 profile")
    sources = manifest.get("capture_sources", list(hospital_sources))
    if (not manifest.get("complete") or not isinstance(sources, list)
            or len(sources) != len(expected) or set(sources) != expected or not expected.issubset(links)
            or len({links[source] for source in sources}) != len(sources)):
        raise ValueError("The GNS3 manifest does not identify all required, distinct capture links")
    return tuple(sources)


def payload(run_id, phase, index):
    return f"HIOT1|{run_id}|{phase}|{index:03d}".encode().ljust(PAYLOAD_SIZE, b".")


def parse_payload(raw):
    if len(raw) != PAYLOAD_SIZE:
        return None
    fields = raw.rstrip(b".").decode("ascii", errors="replace").split("|")
    if (len(fields) != 4 or fields[0] != "HIOT1" or not RUN_ID.fullmatch(fields[1])
            or fields[2] not in ("baseline", "burst") or not re.fullmatch(r"[0-9]{3}", fields[3])):
        return None
    return fields[1], fields[2], int(fields[3])
