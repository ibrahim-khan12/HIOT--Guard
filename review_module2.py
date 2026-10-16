"""Independent saved-byte checks and repeatable test evidence for a Module 2 review."""
import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from config import tshark_path
from module2.store import Store


def verify_bytes(store, acceptance, tshark):
    scope = acceptance["scope"]
    captures = store.status(scope)["captures"]
    flows = store.flows(scope=scope, limit=2**31)
    fields = ["frame.number", "tcp.seq_raw", "tcp.payload", "dicom.assoc.ae.calling", "dicom.assoc.ae.called"]
    frames, retained = {}, 0
    for capture in captures:
        path = Path(capture["raw_capture"])
        if not capture["raw_retained"]:
            raise AssertionError("Review requires retained original capture bytes")
        assert hashlib.sha256(path.read_bytes()).hexdigest() == capture["sha256"]
        retained += 1
        command = [tshark, "-n", "-2", "-r", str(path), "-d", "tcp.port==11112,dicom",
                   "-T", "fields", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=f"]
        for field in fields:
            command.extend(["-e", field])
        output = subprocess.run(command, check=True, capture_output=True, text=True).stdout
        frames[capture["capture_id"]] = {int(row[0]): row for row in csv.reader(io.StringIO(output), delimiter="\t")}

    dicom = hl7 = 0
    for flow in flows:
        assert flow["capture_ids"] and flow["observation_ids"]
        for event in flow["evidence"]:
            packets = frames[event["capture_id"]]
            row = packets[event["frame"]]
            metadata = event["metadata"]
            if event["protocol"] == "DICOM":
                assert row[3].strip() == metadata["calling_ae"]
                assert row[4].strip() == metadata["called_ae"]
                dicom += 1
            elif event["protocol"] == "HL7/MLLP":
                first = bytes.fromhex(row[2].replace(":", ""))
                offset = event["frame_payload_offset"]
                assert first[offset] == 11
                anchor = (int(row[1])+offset) % 2**32
                observed = {}
                for number in event["supporting_frames"]:
                    packet = packets[number]
                    delta = (int(packet[1])-anchor+2**31) % 2**32-2**31
                    for i, byte in enumerate(bytes.fromhex(packet[2].replace(":", ""))):
                        if 0 <= delta+i < 1024*1024:
                            assert observed.get(delta+i, byte) == byte
                            observed[delta+i] = byte
                message = bytearray()
                while len(message) in observed:
                    message.append(observed[len(message)])
                assert b"\x1c\r" in message
                msh = bytes(message)[1:].split(b"\r", 1)[0].split(b"|")
                assert msh[2].decode("ascii")[:80] == metadata["sender"]
                assert msh[8].decode("ascii")[:40] == metadata["message_type"]
                hl7 += 1
    ct = [f for f in flows if f["source_ip"] == "10.77.20.30" and f["destination_ip"] == "10.77.30.30"
          and f["destination_port"] == 11112 and any(e["protocol"] == "DICOM" for e in f["evidence"])]
    pump = [f for f in flows if f["source_ip"] == "10.77.20.20" and f["destination_ip"] == "10.77.30.40"
            and f["destination_port"] == 2575 and any(e["metadata"].get("sender") == "LAB_PUMP"
            and e["metadata"].get("message_type") == "ORU^R01" for e in f["evidence"])]
    assert ct and pump and dicom and hl7
    with store.connect() as db:
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    return {"retained_hashes_verified": retained, "dicom_events_byte_checked": dicom,
            "hl7_events_byte_checked": hl7, "ct_to_pacs_connections": len(ct),
            "pump_to_ehr_connections": len(pump), "sqlite_integrity": "ok"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True)
    parser.add_argument("--tshark", default=tshark_path())
    args = parser.parse_args()
    state = Path(args.state)
    acceptance = json.loads((state/"acceptance-report.json").read_text())
    if not acceptance["passed"]:
        raise RuntimeError("Complete actual-tool acceptance first")
    report = {"started": time.time(), "tests": {}, "passed": False}
    destination = state/"review-report.json"
    destination.write_text(json.dumps(report, indent=2))
    environment = {**os.environ, "IOMT_INTEGRATION": "1"}
    for suite in ("test_module2", "test_live"):
        run = subprocess.run([sys.executable, "-m", "unittest", suite, "-v"], capture_output=True, text=True, env=environment)
        (state/(suite+".txt")).write_text(run.stdout+run.stderr)
        report["tests"][suite] = {"exit_code": run.returncode, "log": str((state/(suite+".txt")).resolve())}
        destination.write_text(json.dumps(report, indent=2))
        if run.returncode:
            raise AssertionError(suite)
    report["reference_tshark"] = subprocess.run([args.tshark, "--version"], capture_output=True, text=True, check=True).stdout.splitlines()[0]
    report["saved_bytes"] = verify_bytes(Store(state/"monitoring.sqlite3"), acceptance, args.tshark)
    report["source_hashes"] = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                               for path in sorted(Path("module2").glob("*.py"))}
    report.update(passed=True, finished=time.time())
    destination.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
