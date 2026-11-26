"""Compare whole-file prefix analysis with independently cut PCAP bytes."""
import argparse
import copy
import json
from pathlib import Path
import struct
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT),str(ROOT/"Module 4")]
from module4.evidence_v2 import analyze, packets


def cut(data, cutoff):
    endian,scale={b"\xd4\xc3\xb2\xa1":("<",1e6),b"\xa1\xb2\xc3\xd4":(">",1e6),
                  b"\x4d\x3c\xb2\xa1":("<",1e9),b"\xa1\xb2\x3c\x4d":(">",1e9)}[data[:4]]
    out=bytearray(data[:24]);at=24
    while at+16<=len(data):
        seconds,fraction,length,_=struct.unpack_from(endian+"IIII",data,at)
        if at+16+length>len(data):raise ValueError("Incomplete capture")
        if seconds+fraction/scale<=cutoff:out.extend(data[at:at+16+length])
        at+=16+length
    return bytes(out)


def main():
    p=argparse.ArgumentParser();p.add_argument("--folder",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    p.add_argument("--tshark",default=r"C:\Program Files\Wireshark\tshark.exe");args=p.parse_args()
    checks=[]
    for stack in ("A","B"):
        folder=args.folder/("stack-"+stack);manifest=json.loads((folder/"capture.json").read_text())
        raw=(folder/"traffic.pcap").read_bytes();items=packets(folder/"traffic.pcap",args.tshark)
        observed_end=max(p["time"] for p in items)
        for endpoint in manifest["endpoints"]:
            start=min(p["time"] for p in items if endpoint in (p["src"],p["dst"]))
            for duration in (10,30,60,120):
                expected=analyze(items,endpoint,duration,observed_end,manifest["sha256"])
                with tempfile.TemporaryDirectory() as temp:
                    path=Path(temp)/"prefix.pcap";path.write_bytes(cut(raw,start+duration))
                    actual=analyze(packets(path,args.tshark),endpoint,duration,observed_end,manifest["sha256"])
                # Prefix re-numbering changes frame numbers when later packets
                # interleave. Compare semantic/statistical results and event times.
                for result in (expected,actual):
                    for event in result["evidence"]:event.pop("frames",None)
                if expected!=actual:raise AssertionError((stack,endpoint,duration))
                renamed=copy.deepcopy(items)
                for packet in renamed:
                    packet["src"]="alias-"+packet["src"];packet["dst"]="alias-"+packet["dst"]
                alternate=analyze(renamed,"alias-"+endpoint,duration,observed_end,manifest["sha256"])
                if expected["features"]!=alternate["features"] or expected["category"]!=alternate["category"]:
                    raise AssertionError("Identifier leakage")
                checks.append({"stack":stack,"endpoint":endpoint,"seconds":duration,"byte_prefix_equivalent":True,"identifier_invariant":True})
    report={"checks":checks,"passed":len(checks),"live_limit":"Finite packet-prefix equivalence verified; continuous live window scheduling and automatic projection refresh are not implemented."}
    with args.output.open("x") as stream:json.dump(report,stream,indent=2)
    print(json.dumps({"passed":len(checks)}))


if __name__=="__main__":main()
