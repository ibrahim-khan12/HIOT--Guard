import copy
import struct
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from module4.evidence_v2 import analyze, contiguous, dicom_messages, hl7_messages, packets


def message(control="one", code="LAB_RATE", namespace="99HIOT", ack=None):
    kind = "ACK" if ack else "ORU^R01"
    payload = f"MSH|^~\\&|PRIVATE_NAME||RECEIVER||1||{kind}|{control}|P|2.5\r"
    payload += f"MSA|{ack}|{control}\r" if ack else f"OBX|1|NM|{code}^Private^{namespace}||PRIVATE_VALUE\r"
    return b"\x0b" + payload.encode() + b"\x1c\r"


def packet(frame, time, seq, payload=b"", reverse=False, syn=False):
    return {"frame": frame, "time": time, "seq": seq, "payload": payload, "src": "b" if reverse else "a",
            "dst": "a" if reverse else "b", "stream": "0", "sport": "2" if reverse else "1",
            "dport": "1" if reverse else "2", "syn": syn, "ack": reverse,
            "length": len(payload)+54, "captured": len(payload)+54}


def exchange(status="AA", ack_control="one"):
    return [packet(1,0,100,syn=True), packet(2,.1,200,reverse=True,syn=True),
            packet(3,1,101,message()), packet(4,2,201,message(ack_control,ack=status),reverse=True)]


def pdu(kind, body):
    return struct.pack(">BBI", kind, 0, len(body)) + body


def command(command, ident, status=None):
    def tag(element, data):
        return struct.pack("<HHI",0,element,len(data)) + data
    data = tag(0x100,struct.pack("<H",command))
    data += tag(0x110 if command == 1 else 0x120,struct.pack("<H",ident))
    if status is not None:
        data += tag(0x900,struct.pack("<H",status))
    return pdu(4,struct.pack(">I",len(data)+2)+bytes([1,3])+data)


class EvidenceV2Tests(unittest.TestCase):
    def test_tshark_boolean_formats(self):
        for yes,no in (("True","False"),("1","0")):
            raw="\t".join(("1","0","54","54","a","b","1","2","0","100",yes,no,""))+"\n"
            with patch("module4.evidence_v2.subprocess.run",return_value=SimpleNamespace(stdout=raw)):
                row=packets("unused","tshark")[0]
            self.assertTrue(row["syn"])
            self.assertFalse(row["ack"])

    def test_namespace_and_no_payload_retention(self):
        for namespace, expected in (("99HIOT",["flow_rate"]),("LN",[]),("",[])):
            data=message(namespace=namespace)
            parsed=hl7_messages(data,[(1,0)]*len(data))[0]
            self.assertEqual(parsed["kinds"],expected)
            self.assertNotIn("PRIVATE",str(parsed))
        data=message(code="8867-4",namespace="LN")
        self.assertEqual(hl7_messages(data,[(1,0)]*len(data))[0]["kinds"],["heart_rate"])

    def test_ack_status_and_correlation(self):
        for status,key in (("AA","accepted"),("AR","rejected"),("AE","error")):
            self.assertEqual(analyze(exchange(status),"a",10,130)["features"]["oru_"+key],1)
        result=analyze(exchange(ack_control="unrelated"),"a",10,130)
        self.assertEqual(result["features"]["oru_unacknowledged"],1)
        self.assertNotIn("oru_accepted",result["features"])

    def test_persistent_connection_repeated_messages(self):
        requests=b"".join(message(str(i)) for i in range(3))
        replies=b"".join(message(str(i),ack="AA") for i in range(3))
        rows=[packet(1,0,100,syn=True),packet(2,.1,200,reverse=True,syn=True),
              packet(3,1,101,requests),packet(4,2,201,replies,reverse=True)]
        result=analyze(rows,"a",10,130)
        self.assertEqual(result["features"]["oru_accepted"],3)
        self.assertEqual(result["features"]["connections"],1)

    def test_cutoff_excludes_later_fragment_and_ack(self):
        data=message()
        rows=[packet(1,0,100,syn=True),packet(2,.1,200,reverse=True,syn=True),packet(3,9,101,data[:40]),
              packet(4,11,141,data[40:]),packet(5,12,201,message(ack="AA"),reverse=True)]
        early=analyze(rows,"a",10,130)
        self.assertEqual(early,analyze(rows[:3],"a",10,130))
        self.assertNotIn("oru_messages",early["features"])
        later=analyze(rows,"a",30,130)
        self.assertEqual(later["features"]["oru_accepted"],1)
        self.assertEqual(later["evidence"][0]["frames"],[3,4,5])

    def test_retransmission_not_another_transaction(self):
        rows=exchange()
        repeated=copy.deepcopy(rows[2]); repeated["frame"]=5; repeated["time"]=3
        self.assertEqual(analyze(rows+[repeated],"a",10,130)["features"]["oru_accepted"],1)

    def test_conflicting_overlap_and_missing_syn_fail_closed(self):
        rows=exchange()
        conflict=copy.deepcopy(rows[2]); conflict["payload"]=b"X"+conflict["payload"][1:]
        self.assertEqual(analyze(rows+[conflict],"a",10,130)["features"]["conflicting_overlap"],1)
        limited=analyze(rows[2:],"a",10,130)
        self.assertNotIn("oru_accepted",limited["features"])
        self.assertEqual(limited["features"]["oru_limited_capture"],1)

    def test_gap_does_not_join_later_bytes(self):
        rows=[packet(1,0,100,syn=True),packet(2,1,101,b"abc"),packet(3,2,105,b"def")]
        data,_,quality=contiguous(rows)
        self.assertEqual(data,b"abc")
        self.assertEqual(quality["gap"],1)

    def test_unseen_and_insufficient_coverage(self):
        self.assertEqual(analyze([],"a",120,130)["reason"],"endpoint_unseen")
        self.assertEqual(analyze(exchange(),"a",120,60)["reason"],"insufficient_observation_coverage")

    def test_identifier_renaming_and_forwarding_unknown(self):
        rows=exchange()
        renamed=copy.deepcopy(rows)
        for p in renamed:
            p["src"]={"a":"10.9.1.5","b":"10.9.1.6"}[p["src"]]
            p["dst"]={"a":"10.9.1.5","b":"10.9.1.6"}[p["dst"]]
        first=analyze(rows,"a",10,130); second=analyze(renamed,"10.9.1.5",10,130)
        self.assertEqual(first["features"],second["features"])
        self.assertEqual(first["category"],"unknown")
        self.assertEqual(first["category"],second["category"])

    def test_dicom_command_and_success(self):
        uid=b"1.2.840.10008.5.1.4.1.1.2"
        abstract=bytes([0x30,0])+struct.pack(">H",len(uid))+uid
        context=bytes([1,0,0,0])+abstract
        request=pdu(1,b"\0"*68+bytes([0x20,0])+struct.pack(">H",len(context))+context)
        accept=pdu(2,b"\0"*68+bytes([0x21,0,0,4,1,0,0,0]))
        for status,event in ((0,"store_success"),(0xA700,"store_non_success")):
            rows=[packet(1,0,100,syn=True),packet(2,.1,200,reverse=True,syn=True),
                  packet(3,1,101,request+command(1,7)),packet(4,2,201,accept+command(0x8001,7,status),reverse=True)]
            result=analyze(rows,"a",10,130)
            self.assertEqual(result["features"][event],1)
            self.assertEqual(result["category"],"unknown")
        parsed=dicom_messages(request,[(1,1)]*len(request))
        self.assertEqual([i["type"] for i in parsed],["proposal"])


if __name__ == "__main__":
    unittest.main()
