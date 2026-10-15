# Module 2 Passive Network Monitoring and Traffic Processing

Module 2 observes Module 1's GNS3 captures. It does not start hospital nodes, generate traffic, classify physical device models, score threats, or write firewall policies. Module 1 stays on `http://127.0.0.1:8877/`; Module 2 uses `http://127.0.0.1:8878/`.

## Implemented pipeline

```text
Saved PCAP or independent GNS3 actor-link reader
  -> complete-record PCAP validation and bounded spool
  -> pinned Linux sensor (Zeek connection logs + two-pass TShark fields)
  -> DICOM association metadata / TCP-reassembled HL7 MLLP metadata
  -> normalized hiot.monitoring.v1 observations
  -> SYN-fingerprint correlation and canonical observation selection
  -> SQLite WAL history / 60-captured-second summaries / JSONL export
  -> loopback monitoring API and browser view
```

The first offline acceptance uses `modality.pcap` and `pump.pcap` from the original evidence folder. Do not commit PCAPs, databases, SSH credentials or local run manifests. Runtime output is under the existing ignored `runs/` directory.

## Setup and run

Use the repository's Python environment. The sensor host must be the actual private GNS3 VM address. The tested host was `192.168.209.142`; verify it after restarting VMware.

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-module2.txt
# Supply GNS3_SSH_PASSWORD in the process environment, or configure an SSH key.
# For a manual prompt, run launch_module2.py. Credentials are not saved to disk.
.\.venv\Scripts\python.exe -m module2 --sensor-host 192.168.209.142 setup-sensor --trust-first-use
.\.venv\Scripts\python.exe -m module2 import <CT-PCAP> --source modality --scope baseline-01
.\.venv\Scripts\python.exe -m module2 import <PUMP-PCAP> --source pump --scope baseline-01
.\.venv\Scripts\python.exe -m module2 export runs/module2/baseline.jsonl
.\.venv\Scripts\python.exe launch_module2.py --sensor-host 192.168.209.142
```

`--trust-first-use` is only for initial private-VM setup. It records that VM's SSH key in `runs/module2/known_hosts`; subsequent connections reject unknown/changed keys. Review the recorded fingerprint through a trusted VM access path before treating it as authenticated identity. Teammates must create their own known-host record and sensor lock. Do not copy a credential-bearing environment to another machine.

The tracked `module2/toolchain.json` pins the official Zeek image digest and exact Debian TShark package. Setup records the built image ID, tool output and SSH-key fingerprint in the ignored `sensor-lock.json`. If the pinned apt package is no longer available, setup fails; review and explicitly update the toolchain rather than silently installing another version.

Analysis containers have no network, no Linux capabilities, a read-only root filesystem, a bounded temporary filesystem, a 768 MiB memory ceiling and one CPU ceiling. They run as the SSH user's UID/GID. SSH access to the user's Docker-enabled GNS3 account is required for setup and analysis. Zeek uses `-C` for the virtual-NIC checksum-offload testbed; this setting is recorded in every capture manifest.

For live operation, start Module 1's prepared GNS3 session and normal traffic. In Module 2 select **Start monitoring**. The collector attaches to the existing 13 actor links through the saved Module 1 manifest. It can request link capture if absent, but does not stop shared GNS3 captures or control any hospital actor. **Stop monitoring** closes only this service's readers. The service remains running after its browser is closed.

## Data contract

`hiot.monitoring.v1` is the public schema identifier. Timestamps are Unix UTC seconds; display time is local to the browser.

| Record | Required content |
| --- | --- |
| Capture manifest | Scope, observation source, capture ID, original input reference, retained raw path/status, SHA-256, byte/frame counts, tool versions/image ID, processing time and reference checks |
| Flow observation | Stable observation ID, capture ID, source/destination IP, TCP/UDP ports (null for ICMP), transport, start time, duration if available, connection state, directional bytes/packets, missed bytes, Zeek UID and correlation provenance |
| Medical evidence | Capture/observation IDs, supporting frame, timestamp, parser status, DICOM calling/called AE and syntax or HL7 sender/message type |
| Integrity finding | Capture ID, kind, and a frame/line/detail when available; malformed rows, packet truncation, TCP gaps/overlaps, incomplete framing, reassembly limits or rotation boundaries |
| Health record | Capture/analysis state, latest received bytes/time, latest analysis, reconnect count, failure text and whether capture loss can be measured |

Device names, registry roles and clinical criticality are not inferred or included as observed facts. HL7 PID/OBX values are excluded from analytical records. Raw PCAPs retain original packet contents and require separate access/retention handling. Two-pass TShark DICOM decoding and the HL7 reassembler provide protocol evidence, not authenticated device identity.

The 60-second summary groups connections by start time in the last 60 captured seconds. Its byte totals are totals of those selected connection records, not exact per-window packet-rate measurements. Offline summaries are anchored to capture time, not today's clock.

### Correlation and idempotence

Offline capture identity uses scope, source and raw hash. Live segment identity uses recording scope, source and segment number. Observation IDs exclude Zeek's random UID. Identical imports are cached; `--force` reprocesses them with stable IDs.

Overlapping TCP observations correlate only when scope, oriented five-tuple and initial SYN sequence match, with start times within one second. SYN matching to a Zeek record uses a 250 ms window. A canonical record favors complete, zero-missed-byte observations and larger observed packet counts, with a deterministic source tie-breaker. Counters are taken from that observation and are never summed across overlapping links. Evidence retains each capture's provenance.

Without an observed SYN, cross-link correlation is deliberately unavailable. ICMP, UDP and midstream TCP can remain separate observations. Scope separates experiments; select a scope when comparing connection totals. This is a bounded lab correlation rule, not an authenticated-device or adversarial collision guarantee.

## Monitoring API

| Endpoint | Behavior |
| --- | --- |
| `GET /api/status?scope=...` | Versioned capture, health, integrity and canonical/observation counts; scopes list always available |
| `GET /api/flows?scope=...&q=...&protocol=...&transport=...&limit=...` | Search IP/port/source; DICOM or HL7/MLLP filter; TCP/UDP/ICMP filter; 1-1000 rows |
| `GET /api/summary?scope=...` | Per-source 60-captured-second connection/peer/byte summaries |
| `GET /api/export.jsonl` | All matching canonical records using the same filters; no row-limit truncation |
| `POST /api/live` | JSON `{"enabled": true}` or `false`; fixed configured manifest only |

The service binds only to `127.0.0.1`. Control requests reject other origins, non-JSON bodies and oversized requests. The API exposes no arbitrary shell, file-import, traffic-generation, policy or firewall endpoint.

## Live behavior and retention

Live mode performs **periodic cumulative-PCAP analysis**, not continuous stateful Zeek streaming. The default pause between complete analysis cycles is 20 seconds, plus the processing time of all dirty sources. Finalized or timed-out connection records and snapshot processing introduce delay; do not claim instantaneous detection from this module.

Each source keeps two 4 MiB complete-record segments. A segment may be evicted only after successful analysis; analytical history and hashes remain and `raw_retained` changes to false. Reaching the unprocessed-segment budget creates a visible limited state. A 256 MiB raw PCAP budget applies across the service. Old completed live scopes can expire; offline evidence is preserved. SQLite/metadata retention is not yet a production archival system.

Reconnect uses exponential backoff up to 30 seconds and a fresh PCAP segment, preserving raw boundaries instead of concatenating headers. GNS3 may replay earlier bytes; correlation prevents matching TCP observations from inflating canonical totals. Starting a new user recording creates a new scope; an unexpected service restart resumes a persisted enabled scope. SSH credentials/key access must still be available at restart.

Messages or long connections spanning rotation boundaries may be incomplete and are flagged. Classic PCAP is supported; PCAPNG import is explicitly refused by the collector. Capture-drop statistics are unavailable on this GNS3 HTTP feed and are reported as unavailable, not zero. Only observed links are covered; silent endpoints and unmonitored paths have no visibility guarantee.

## Evaluation

```powershell
.\.venv\Scripts\python.exe -m unittest test_module2 -v
.\.venv\Scripts\python.exe verify_module2.py --captures <ORIGINAL-PCAP-FOLDER> --live
```

`verify_module2.py` runs actual Linux Zeek/TShark analysis, checks the independent SYN reference, DICOM CT/PACS evidence, HL7 ORU/ACK evidence, forced-repeat idempotence, overlapping TCP observations, malformed input and provenance. Optional live checks wait for all 12 normal sources with no browser used, interrupt the collector's own pump reader, and check reconnection. It preserves JSON, JSONL and console output under `runs/module2/`. Unit tests use explicit fixtures and do not substitute for these actual-tool checks.

The original Module 1 service receipts are cumulative and are not a per-flow ground truth. Protocol-byte references and fresh Module 1 service checks must be presented separately. See `MODULE2_EVALUATION.md` for the measured run and outstanding limits.

## Primary references

- [Official Zeek image](https://hub.docker.com/r/zeek/zeek)
- [Zeek connection records](https://docs.zeek.org/en/current/reference/logs/conn.html)
- [Zeek JSON logs](https://docs.zeek.org/en/current/tutorial/logs.html)
- [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html)
