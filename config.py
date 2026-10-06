"""The authorized lab registry, not a discovered inventory."""
import os

ROLES = {
    "workstation": {"name": "Nurses workstation", "suffix": "10.10", "zone": "staff", "critical": False},
    "pump": {"name": "Infusion pump emulator", "suffix": "20.20", "zone": "medical", "critical": True},
    "modality": {"name": "CT imaging emulator", "suffix": "20.30", "zone": "medical", "critical": False},
    "pacs": {"name": "PACS DICOM service", "suffix": "30.30", "zone": "services", "critical": False},
    "ehr": {"name": "EHR telemetry service", "suffix": "30.40", "zone": "services", "critical": False},
    "gateway": {"name": "Inline security gateway", "suffix": "10.1", "zone": "gateway", "critical": False},
    "ultrasound": {"name": "Ultrasound emulator", "suffix": "20.40", "zone": "medical", "critical": False},
    "monitor": {"name": "Bedside monitor emulator", "suffix": "20.50", "zone": "medical", "critical": True},
    "lab_analyzer": {"name": "Laboratory analyzer emulator", "suffix": "20.60", "zone": "medical", "critical": False},
    "vendor": {"name": "Vendor maintenance workstation", "suffix": "10.20", "zone": "staff", "critical": False},
    "unregistered": {"name": "Unregistered laptop emulator", "suffix": "10.90", "zone": "staff", "critical": False},
    "mri": {"name": "MRI scanner emulator", "suffix": "20.70", "zone": "medical", "critical": False},
    "xray": {"name": "Portable X-ray emulator", "suffix": "20.80", "zone": "medical", "critical": False},
    "ventilator": {"name": "Ventilator emulator", "suffix": "20.90", "zone": "medical", "critical": True},
    "dialysis": {"name": "Dialysis machine emulator", "suffix": "20.100", "zone": "medical", "critical": True},
    "ecg": {"name": "ECG monitor emulator", "suffix": "20.110", "zone": "medical", "critical": True},
}
AGENT_PORTS = {role: 18801 + i for i, role in enumerate(ROLES)}
SERVICE_PORTS = {"dicom": 11112, "hl7": 2575, "http": 8081, "maintenance": 8082}
NORMAL_ROLES = ("workstation", "pump", "modality", "ultrasound", "monitor", "lab_analyzer",
                "mri", "xray", "ventilator", "dialysis", "ecg", "vendor")
CAPTURE_ROLES = NORMAL_ROLES + ("unregistered",)


def address(role, mode):
    return ("127.77." if mode == "local" else "10.77.") + ROLES[role]["suffix"]


def registry(mode):
    return {address(role, mode): {"role": role, **details} for role, details in ROLES.items()
            if role != "unregistered"}


def expected(role, destination, port, mode):
    paths = {
        "workstation": [("ehr", 8081)],
        "pump": [("ehr", 2575)],
        "modality": [("pacs", 11112)],
        "ultrasound": [("pacs", 11112)],
        "monitor": [("ehr", 2575)],
        "lab_analyzer": [("ehr", 2575)],
        "vendor": [("pump", 8082)],
        "mri": [("pacs", 11112)],
        "xray": [("pacs", 11112)],
        "ventilator": [("ehr", 2575)],
        "dialysis": [("ehr", 2575)],
        "ecg": [("ehr", 2575)],
    }
    return (destination, port) in [(address(target, mode), p) for target, p in paths.get(role, [])]


def tshark_path():
    return os.environ.get("IOMT_TSHARK", r"C:\Program Files\Wireshark\tshark.exe" if os.name == "nt" else "tshark")
