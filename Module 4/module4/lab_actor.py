"""Launch the existing hospital actor with per-recording lab settings."""
import json
import os
import random
import time

from config import ROLES, address

settings = json.loads(os.environ["MODULE4_SETTINGS"])
for role, number in settings["addresses"].items():
    subnet, _ = ROLES[role]["suffix"].rsplit(".", 1)
    ROLES[role]["suffix"] = f"{subnet}.{number}"

from agent import Agent, main, synthetic_image

normal_once = Agent.normal_once
HL7 = {
    "pump": ("LAB_RATE", 25, "mL/h"),
    "monitor": ("HEART_RATE", 72, "beats/min"),
    "ecg": ("HEART_RATE", 72, "beats/min"),
    "lab_analyzer": ("GLUCOSE", 95, "mg/dL"),
    "ventilator": ("RESPIRATORY_RATE", 16, "breaths/min"),
    "dialysis": ("BLOOD_FLOW", 300, "mL/min"),
}
DICOM = {"modality", "mri", "ultrasound", "xray"}
rng = random.Random(settings.get("seed", 0))


def evaluation_hl7(self, family):
    observation, value, unit = HL7[self.role]
    control = f"TX{time.monotonic_ns()}"
    count = rng.randint(2, settings.get("max_observations", 5)) if family == "eval-burst" else 1
    observations = "".join(f"OBX|{index}|NM|{observation}^Measurement||{value + rng.randint(-2, 2)}|{unit}\r"
                           for index in range(1, count + 1))
    message = (
        f"MSH|^~\\&|TELEMETRY|LAB|INGEST|LAB|20261115000000||ORU^R01|{control}|P|2.5\r"
        f"PID|1||SYNTHETIC\rOBR|1|||OBSERVATION\r{observations}"
    )
    wire = b"\x0b" + message.encode("ascii") + b"\x1c\r"
    with self.connect("ehr", 2575) as connection:
        if family == "eval-fragmented":
            chunk_bytes = settings.get("chunk_bytes", 37)
            for begin in range(0, len(wire), chunk_bytes):
                connection.sendall(wire[begin:begin + chunk_bytes])
                time.sleep(settings.get("chunk_delay", .012))
        else:
            connection.sendall(wire)
        reply = bytearray()
        while len(reply) < 4096 and not reply.endswith(b"\x1c\r"):
            data = connection.recv(4096)
            if not data:
                break
            reply.extend(data)
    return self.record("Evaluation HL7", f"MSA|AA|{control}".encode() in reply,
                       "Synthetic telemetry acknowledged")


def evaluation_dicom(self, family):
    from pynetdicom import AE
    from pynetdicom.sop_class import Verification

    image = synthetic_image(self.role)
    ae = AE(ae_title="LAB_STORAGE")
    ae.add_requested_context(image.SOPClassUID)
    if family in ("eval-fragmented", "eval-ambiguous"):
        ae.add_requested_context(Verification)
    if family == "eval-fragmented":
        ae.maximum_pdu_size = 4096
    ae.acse_timeout = ae.dimse_timeout = ae.network_timeout = 3
    association = ae.associate(address("pacs", self.mode), 11112, ae_title="LAB_PACS",
                               bind_address=(self.ip, 0))
    count = rng.randint(2, settings.get("max_stores", 4)) if family == "eval-burst" else 1
    if not association.is_established:
        return self.record("Evaluation DICOM", False, "Association not established")
    try:
        for index in range(count):
            status = association.send_c_store(image if index == 0 else synthetic_image(self.role))
            if getattr(status, "Status", None) != 0:
                return self.record("Evaluation DICOM", False, "Synthetic store failed")
    finally:
        association.release()
    return self.record("Evaluation DICOM", True, f"{count} synthetic stores")


def probe(self):
    variant = settings["variants"].get(self.role)
    if variant == "generic_hl7":
        message = b"\x0bMSH|^~\\&|LAB|TEST|EHR|LAB|20261114120000||ORU^R01|GENERIC|P|2.5\r\x1c\r"
        with self.connect("ehr", 2575) as connection:
            connection.sendall(message)
            ok = b"MSA|AA|GENERIC" in connection.recv(4096)
        return self.record("Generic HL7", ok, "Synthetic observation report without measurement kind")
    if variant == "verification":
        from pynetdicom import AE
        from pynetdicom.sop_class import Verification

        ae = AE(ae_title="LAB_VERIFIER")
        ae.add_requested_context(Verification)
        ae.acse_timeout = ae.dimse_timeout = ae.network_timeout = 2
        association = ae.associate(address("pacs", self.mode), 11112, ae_title="LAB_PACS",
                                   bind_address=(self.ip, 0))
        ok = False
        if association.is_established:
            try:
                response = association.send_c_echo()
                ok = response is not None and getattr(response, "Status", -1) == 0
            finally:
                association.release()
        return self.record("Verification-only DICOM", ok, "Synthetic C-ECHO")
    family = settings.get("traffic_profile")
    if family and self.role in HL7:
        return evaluation_hl7(self, family)
    if family and self.role in DICOM:
        return evaluation_dicom(self, family)
    return normal_once(self)


Agent.normal_once = probe
main()
