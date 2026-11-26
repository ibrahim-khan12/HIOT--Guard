"""Packet-backed development evidence, frozen-v1 comparison and expansion gate."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time
import tracemalloc

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT),str(ROOT / "Module 3"),str(ROOT / "Module 4")]
from module2.pipeline import Pipeline
from module2.store import Store as Monitor
from module4.evidence_v2 import export_capture
from module4.gns3_pilot_sensor import PilotSensor
from module4.replay import project
from module4.study import load_selected, selected_predictions


def write(path, data):
    with path.open("x",encoding="utf-8") as stream:
        json.dump(data,stream,indent=2)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--folder",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--tshark",default=r"C:\Program Files\Wireshark\tshark.exe")
    parser.add_argument("--study",type=Path,default=ROOT/"runs/module4-learning-study-20261116")
    args=parser.parse_args()
    args.output.mkdir(parents=True,exist_ok=False)
    model,selection=load_selected(args.study)
    sensor=PilotSensor(args.folder/"pilot-manifest.json",args.tshark)
    result={"purpose":"development_only", "new_model_trained":False, "stacks":{},
            "frozen_model_sha256":hashlib.sha256((args.study/"model/model.joblib").read_bytes()).hexdigest()}
    for stack in ("A","B"):
        folder=args.folder/("stack-"+stack)
        manifest=json.loads((folder/"capture.json").read_text())
        target=args.output/stack
        target.mkdir()
        started=time.monotonic()
        tracemalloc.start()
        v2=export_capture(folder/"traffic.pcap",manifest,args.tshark)
        _,peak_bytes=tracemalloc.get_traced_memory()
        tracemalloc.stop()
        extraction_seconds=time.monotonic()-started
        write(target/"workflow-windows.json",v2)
        scope="module4-stage2-pilot-"+stack
        monitor=Monitor(target/"module2/monitoring.sqlite3")
        imported=Pipeline(monitor,target/"module2",sensor).import_file(folder/"traffic.pcap","pilot-direct-link",scope)
        recording=project(monitor,scope,target)
        write(target/"recording.json",recording)
        old=selected_predictions(recording,model,selection)
        write(target/"frozen-v1-predictions.json",old)
        primary=[r for r in v2["rows"] if r["window_seconds"]==120]
        by_ip={r["endpoint"]:r for r in primary}
        comparisons=[]
        for prediction in old:
            ip=prediction["ip"]
            if ip not in manifest["endpoints"]:
                continue
            comparisons.append({"endpoint":ip,"label":manifest["endpoints"][ip],
                                "frozen_rules":prediction["decisions"]["rules"]["category"],
                                "frozen_selected_fallback":prediction["decisions"]["selected_fallback"]["category"],
                                "updated_rules":by_ip[ip]["category"],"workflow":by_ip[ip]["workflows"]})
        projection={"schema_version":"hiot.classification.projection.v1","source_id":recording["source_id"],
                    "scope":scope,"inventory_revision":recording["revision"],"inventory_digest":recording["digest"],
                    "capture_sha256":manifest["sha256"],"records":primary}
        write(target/"classification.json",projection)
        methods={}
        for method in ("frozen_rules","frozen_selected_fallback","updated_rules"):
            methods[method]={"correct":sum(c[method]==c["label"] for c in comparisons),
                             "incorrect":sum(c[method] not in (c["label"],"unknown") for c in comparisons),
                             "abstained":sum(c[method]=="unknown" for c in comparisons),
                             "supporting_false_medical":sum(c["label"]=="other" and c[method]!="unknown" for c in comparisons)}
        result["stacks"][stack]={"capture_bytes":manifest["bytes"],"capture_seconds":manifest["capture_stopped"]-manifest["capture_started"],
                                 "v2_extraction_seconds":extraction_seconds,"module2_seconds":imported["duration_seconds"],
                                 "python_extraction_peak_bytes":peak_bytes,
                                 "observed_endpoints":len(comparisons),"coverage_120s":sum(r["features"].get("coverage_sufficient",0) for r in primary),
                                 "comparisons":comparisons,"methods":methods,
                                 "receipts":manifest["state"]["receipts"],"worker_error":manifest["state"].get("error")}
    result["expansion_gate"]={"passed":False,"reason":"Physical endpoint identity remains indistinguishable from equivalent forwarding/reporting workflows. No independently justified ten-category profiles yet.",
                              "allocation_status":"90-session allocation remains provisional; no final-test collection or new model selection",
                              "required_decision":"Retain the physical-device task and add independently evidenced origin/workflow profiles, or explicitly approve a separate workflow-classification research task."}
    result["limitations"]=["One pilot session per stack is not a held-out evaluation or a confidence-interval sample.",
                           "Four medical categories and three supporting endpoints are present; no ten-class performance claim.",
                           "Synthetic CT object has minimal metadata; B is not clinical IOD conformance validation.",
                           "Forwarding profiles reproduce equivalent traffic; no actual two-hop relay pipeline is implemented.",
                           "Shared receiver/container/scheduler do not establish hardware, vendor or independent-instance transfer."]
    write(args.output/"report.json",result)
    print(json.dumps({"stacks":{s:{k:v for k,v in r.items() if k in ("capture_bytes","observed_endpoints","methods","coverage_120s")} for s,r in result["stacks"].items()},"expansion_gate":result["expansion_gate"]},indent=2))


if __name__=="__main__":
    main()
