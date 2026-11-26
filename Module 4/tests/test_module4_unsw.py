import io
import struct
import tempfile
import unittest
from pathlib import Path

from module4.experiment import load_json
from module4.unsw_pilot import prefix, prepare, validate_entry


def capture(payloads, endian="<"):
    magic = b"\xd4\xc3\xb2\xa1" if endian == "<" else b"\xa1\xb2\xc3\xd4"
    header = magic + struct.pack(endian + "HHIIII", 2, 4, 0, 0, 65535, 1)
    return header + b"".join(struct.pack(endian + "IIII", i, 0, len(p), len(p)) + p
                             for i, p in enumerate(payloads))


class UNSWPrefixTests(unittest.TestCase):
    def test_frame_bound_preserves_packet_bytes_and_order_in_both_byte_orders(self):
        for endian in ("<", ">"):
            data, audit = prefix(io.BytesIO(capture([b"first", b"second"], endian)), max_frames=1)
            self.assertEqual(data, capture([b"first"], endian))
            self.assertEqual(audit["frames"], 1)
            self.assertEqual(audit["stop_reason"], "frame_limit")

    def test_byte_limit_never_saves_a_partial_packet(self):
        data, audit = prefix(io.BytesIO(capture([b"first", b"second"])), max_bytes=50)
        self.assertEqual(data, capture([b"first"]))
        self.assertEqual(audit["stop_reason"], "byte_limit")

    def test_incomplete_source_is_rejected_within_selected_window(self):
        for data in (capture([b"first"])[:-1], capture([]) + b"x", b"\x0a\x0d\x0d\x0a"):
            with self.assertRaises(ValueError):
                prefix(io.BytesIO(data))

    def test_empty_capture_and_invalid_limits_fail(self):
        with self.assertRaises(ValueError):
            prefix(io.BytesIO(capture([])))
        with self.assertRaises(ValueError):
            prefix(io.BytesIO(capture([b"first"])), max_frames=0)
        with self.assertRaises(ValueError):
            prefix(io.BytesIO(capture([b"first"])), max_bytes=40)

    def test_oversized_record_is_rejected_without_reading_its_payload(self):
        data = capture([]) + struct.pack("<IIII", 1, 0, 999999, 999999)
        with self.assertRaises(ValueError):
            prefix(io.BytesIO(data))

    def test_prepare_preserves_source_and_marks_identity_as_unreviewed(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "ExampleCamera_001122aabbcc.pcap"
            original = capture([b"first", b"second"])
            source.write_bytes(original)
            output = Path(temp) / "sample"
            prepare(source, output, max_frames=1)
            audit = load_json(output / "source-audit.json")
            self.assertEqual(source.read_bytes(), original)
            self.assertFalse(audit["label_reviewed"])
            self.assertEqual(audit["device_mac_from_filename"], "00:11:22:aa:bb:cc")
            self.assertEqual(audit["sample"]["frames"], 1)
            with self.assertRaises(ValueError):
                prepare(source, output)

    def test_label_review_requires_matching_provenance_and_explicit_rationale(self):
        audit = {"device_mac_from_filename": "00:11:22:aa:bb:cc",
                 "device_name_from_filename": "ExampleCamera", "original_session": "source.pcap"}
        entry = {"target_mac": "00:11:22:AA:BB:CC", "device": "ExampleCamera",
                 "original_session": "source.pcap", "expected": "unknown",
                 "review_status": "out_of_scope_reviewed", "identity_source": "publisher inventory",
                 "mapping_rationale": "Consumer camera is outside the ten hospital categories"}
        validate_entry(entry, audit)
        for key, value in (("expected", "infusion_pump"), ("mapping_rationale", ""),
                           ("device", "InfusionPump"), ("target_mac", "11:22:33:44:55:66"),
                           ("review_status", "unreviewed")):
            with self.assertRaises(ValueError):
                validate_entry(entry | {key: value}, audit)


if __name__ == "__main__":
    unittest.main()
