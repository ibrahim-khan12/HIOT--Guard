"""The authorized lab registry, not a discovered inventory."""
import os

ROLES = {
    "workstation": {"name": "Nurses workstation", "suffix": "10.10", "zone": "staff", "critical": False},
    "pump": {"name": "Infusion pump emulator", "suffix": "20.20", "zone": "medical", "critical": True},
    "modality": {"name": "Imaging modality emulator", "suffix": "20.30", "zone": "medical", "critical": False},
    "pacs": {"name": "PACS verification service", "suffix": "30.30", "zone": "services", "critical": False},
    "ehr": {"name": "EHR telemetry service", "suffix": "30.40", "zone": "services", "critical": False},
    "gateway": {"name": "Inline security gateway", "suffix": "10.1", "zone": "gateway", "critical": False},
}
AGENT_PORTS = {role: 18801 + i for i, role in enumerate(ROLES)}
SERVICE_PORTS = {"dicom": 11112, "hl7": 2575, "http": 8081}


def address(role, mode):
    return ("127.77." if mode == "local" else "10.77.") + ROLES[role]["suffix"]


def registry(mode):
    return {address(role, mode): {"role": role, **details} for role, details in ROLES.items()}


def expected(role, destination, port, mode):
    paths = {
        "workstation": [("ehr", 8081)],
        "pump": [("ehr", 2575)],
        "modality": [("pacs", 11112)],
    }
    return (destination, port) in [(address(target, mode), p) for target, p in paths.get(role, [])]


def tshark_path():
    return os.environ.get("IOMT_TSHARK", r"C:\Program Files\Wireshark\tshark.exe" if os.name == "nt" else "tshark")
