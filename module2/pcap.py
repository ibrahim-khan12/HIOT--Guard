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
    offset, count, first_time, last_time = 24, 0, None, None
    while offset + 16 <= len(data):
        captured, original = struct.unpack_from(endian + "II", data, offset + 8)
        if captured > snaplen or captured > original:
            raise ValueError("Invalid PCAP packet record length")
        if offset + 16 + captured > len(data):
            break
        sec, fraction = struct.unpack_from(endian + "II", data, offset)
        precision = 1e9 if data[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1e6
        timestamp = sec + fraction / precision
        first_time = timestamp if first_time is None else min(first_time, timestamp)
        last_time = timestamp if last_time is None else max(last_time, timestamp)
        offset += 16 + captured
        count += 1
    if offset != len(data) and not allow_partial:
        raise ValueError(f"Truncated PCAP record at byte {offset}")
    return data[:offset], {"frames": count, "bytes": offset, "incomplete_tail_bytes": len(data) - offset,
                           "sha256": hashlib.sha256(data[:offset]).hexdigest(),
                           "first_packet_time": first_time, "last_packet_time": last_time}


def snapshot(path, destination, max_bytes=32 * 1024 * 1024):
    with Path(path).open("rb") as source:
        raw = source.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("Capture size limit reached; analysis refused rather than silently truncating")
    data, info = complete_pcap(raw, allow_partial=True)
    Path(destination).write_bytes(data)
    return info


def packet_fingerprints(path):
    """Exact recorded-packet identity, including timestamp; no inferred network identity."""
    data, _ = complete_pcap(Path(path).read_bytes())
    endian, offset, frame = MAGICS[data[:4]], 24, 0
    result = {}
    while offset < len(data):
        captured, original = struct.unpack_from(endian+"II", data, offset+8)
        frame += 1
        # Identical PCAP replay is provable even when TCP SYN or transport ports are absent.
        if captured == original:
            result[frame] = hashlib.sha256(data[offset:offset+16+captured]).hexdigest()
        offset += 16+captured
    return result
