"""Bounded, provenance-first audit of the author-hosted ICU data candidate.

No archive extraction, model fitting, row merging or download execution.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import urllib.request
import zipfile


def fetch(url, limit):
    if os.name == "nt":
        # Windows curl uses the OS trust store; do not disable TLS validation.
        data=subprocess.check_output(["curl.exe","--fail","--location","--silent","--show-error","--max-time","90","--max-filesize",str(limit),url],timeout=100)
        if len(data)>limit:
            raise ValueError("Download exceeds audit bound")
        return data
    request=urllib.request.Request(url,headers={"User-Agent":"HIoT-Guard-Module4-audit"})
    with urllib.request.urlopen(request,timeout=60) as response:
        data=response.read(limit+1)
    if len(data)>limit:
        raise ValueError("Download exceeds audit bound")
    return data


def main():
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);args=p.parse_args()
    args.output.mkdir(parents=True,exist_ok=True)
    if (args.output/"report.json").exists():
        raise ValueError("Use a fresh output directory")
    api="https://api.github.com/repos/imfaisalmalik/IoT-Healthcare-Security-Dataset"
    commit=json.loads(fetch(api+"/commits/main",1024*1024))["sha"]
    base="https://raw.githubusercontent.com/imfaisalmalik/IoT-Healthcare-Security-Dataset/"+commit
    readme=fetch(base+"/Dataset/IoT%20Healthcare%20Security%20Dataset.md",1024*1024)
    (args.output/"publisher-readme.txt").write_bytes(readme)
    raw=fetch(base+"/Dataset/ICUDatasetProcessed.zip",32*1024*1024)
    (args.output/"ICUDatasetProcessed.zip").write_bytes(raw)
    entries=[]
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for info in archive.infolist():
            entry={"name":info.filename,"bytes":info.file_size,"compressed_bytes":info.compress_size}
            if info.filename.lower().endswith(".csv"):
                with archive.open(info) as source:
                    entry["header"]=source.readline(16384).decode("utf-8-sig",errors="replace").strip()
            entries.append(entry)
    report={"source":base,"commit":commit,"archive_sha256":hashlib.sha256(raw).hexdigest(),"archive_bytes":len(raw),"entries":entries,
            "admitted_to_medical_training":False,
            "reason":"Author documentation describes IoT-Flock simulated MQTT/CoAP ICU traffic. The processed archive does not establish compatible HL7/DICOM physical-device labels and packet-prefix provenance for this experiment.",
            "next_use":"Candidate for Module 5 attack detection or a separately scoped MQTT publisher attribution study; raw captures and per-endpoint ground truth still require verification.",
            "existing_sources":{"CICIoMT2024":"Existing Active.pcap audit observes broker-to-subscriber forwarding; no verified pump publisher. Keep excluded from medical training.",
                                "IoT Sentinel":"Existing 550-capture rejection regression; already inspected, not a fresh final test.",
                                "Medical Devices 2024":"Existing Kardia sample audit is phone/app VPN visibility, not physical ECG endpoint ground truth.",
                                "UNSW-IoTraffic":"Optional access-dependent rejection study; no new data admitted.","CIC IoT-DIAD":"Deferred to Module 5 / separate identification scope."}}
    (args.output/"report.json").write_text(json.dumps(report,indent=2))
    print(json.dumps(report,indent=2))


if __name__=="__main__":main()
