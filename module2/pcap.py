"""Classic PCAP validation and complete-record snapshots for a growing capture."""
import hashlib
import struct
from pathlib import Path

MAGICS = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
          b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}


def complete_pcap(data, allow_partial=False):
    if len(data) < 24 or data[:4] not in MAGICS:
        raise ValueError("Expected a classic PCAP header; PCAPNG is not yet supported by this collector")
    endian = MAGICS[data[:4]]
    major, minor = struct.unpack_from(endian + "HH", data, 4)
    snaplen = struct.unpack_from(endian + "I", data, 16)[0]
    if (major, minor) != (2, 4) or not 0 < snaplen <= 16 * 1024 * 1024:
        raise ValueError("Invalid PCAP version or snapshot length")
    offset, count = 24, 0
    while offset + 16 <= len(data):
        captured, original = struct.unpack_from(endian + "II", data, offset + 8)
        if captured > snaplen or captured > original:
            raise ValueError("Invalid PCAP packet record length")
        if offset + 16 + captured > len(data):
            break
        offset += 16 + captured
        count += 1
    if offset != len(data) and not allow_partial:
        raise ValueError(f"Truncated PCAP record at byte {offset}")
    return data[:offset], {"frames": count, "bytes": offset, "incomplete_tail_bytes": len(data) - offset,
                           "sha256": hashlib.sha256(data[:offset]).hexdigest()}


def snapshot(path, destination, max_bytes=32 * 1024 * 1024):
    with Path(path).open("rb") as source:
        raw = source.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("Capture size limit reached; analysis refused rather than silently truncating")
    data, info = complete_pcap(raw, allow_partial=True)
    Path(destination).write_bytes(data)
    return info
