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

HL7 evidence additionally records the frame containing the message start, its TCP-payload offset, and all supporting frames. These refer to captured bytes, including multiple messages on one persistent TCP connection. Medical TCP evidence is never attached to a UDP flow sharing the same addresses and port numbers.

Device names, registry roles and clinical criticality are not inferred or included as observed facts. HL7 PID/OBX values are excluded from analytical records. Raw PCAPs retain original packet contents and require separate access/retention handling. Two-pass TShark DICOM decoding and the HL7 reassembler provide protocol evidence, not authenticated device identity.

The 60-second summary groups connections by start time in the last 60 captured seconds. Its byte totals are totals of those selected connection records, not exact per-window packet-rate measurements. Offline summaries are anchored to capture time, not today's clock.

SQLite maintains an indexed canonical view transactionally with observation imports. Queries decode only the requested page, not the complete scope. One serialized writer reuses a bounded 64 MiB page cache; each short-lived reader has a 4 MiB cache. Unchanged completed observations update their volatile Zeek UID without rebuilding their unchanged canonical evidence group. Existing databases migrate this view once at startup; large histories can take several minutes on the first launch. JSONL exports iterate a consistent SQLite read snapshot and stream the response instead of building one large list/body. A slow export can delay WAL checkpointing until its read transaction closes; a stalled HTTP client has a 30-second socket timeout.

### Correlation and idempotence

Offline capture identity uses scope, source and raw hash. Live segment identity uses recording scope, source and segment number. Observation IDs exclude Zeek's random UID. Identical imports are cached; `--force` reprocesses them with stable IDs.

Reanalysis uses a fresh staging directory. A successful snapshot is published under its content hash before the database switches to it; failed analysis leaves the previous committed raw bytes intact. Successful replacement removes the previous raw copy, and database observations removed by reprocessing are replaced transactionally rather than left behind.

Overlapping TCP observations correlate only when scope, oriented five-tuple and initial SYN sequence match, with start times within one second. SYN matching to a Zeek record uses a 250 ms window. A canonical record favors complete, zero-missed-byte observations and larger observed packet counts, with a deterministic source tie-breaker. Counters are taken from that observation and are never summed across overlapping links. Evidence retains each capture's provenance.

Without a SYN, a complete identical set of recorded packets (including original packet timestamps and bytes) can establish exact replay identity. This supports literal duplicate ICMP/UDP/midstream captures without guessing identity from addresses alone. Different timestamps, packet sets or capture truncation remain separate observations. Scope separates experiments; select a scope when comparing totals. `uncorrelated_observations` and `count_semantics` disclose that unmatched records are not proven unique hospital-wide sessions. These rules do not authenticate devices or guarantee correlation under adversarial ambiguity.

## Monitoring API

| Endpoint | Behavior |
| --- | --- |
| `GET /api/status?scope=...` | Versioned capture, health, integrity and canonical/observation counts; scopes list always available |
| `GET /api/flows?scope=...&q=...&protocol=...&transport=...&limit=...` | Search IP/port/source; medical/transport filters; 1-1000 rows; `next_cursor` for `before=[time,id]` keyset pages; optional `offset` |
| `GET /api/summary?scope=...` | Per-source 60-captured-second connection/peer/byte summaries |
| `GET /api/export.jsonl` | All matching canonical records using the same filters; no row-limit truncation |
| `POST /api/live` | JSON `{"enabled": true}` or `false`; fixed configured manifest only |
| `GET /api/ready` | Lightweight readiness probe, independent of history-query cost |
| `GET /api/captures?scope=...&source=...&offset=...&limit=...` | Database-backed capture pages and total; at most 200 rows |
| `GET /api/health-events` | Latest 100 retained state/error transitions; at most 1000 persist |
| `GET /api/metrics?scope=...` | Up to 5000 retained per-analysis timing samples |

The service binds only to `127.0.0.1`. Control requests reject other origins, non-JSON bodies and oversized requests. The API exposes no arbitrary shell, file-import, traffic-generation, policy or firewall endpoint.

The status response includes `collector`: running/stopped/degraded state, expected/active reader-worker counts, analysis-worker liveness, stale sources and errors. The API bounds capture metadata to the latest 200 and findings to 100; `capture_count`/`issue_count` remain full totals. Health transitions persist in a bounded 1000-entry journal. Sources with pending bytes and no analysis progress for 60 seconds are marked stale. A monotonic timer starts when new pending work arrives, rather than counting a quiet link's preceding idle time; committed analysis progress resets it. This is an engineering health threshold, not a supervisor-approved performance guarantee.

Packet reception and status persistence are separate: readers feed every received chunk into their spool, but coalesce ordinary receiving-health updates to at most one per source per second. Errors, transitions and completed analyses remain explicit. Per-stage timing distinguishes raw reservation, normalization and database persistence. Exact replay matching uses indexed endpoint/time lookups rather than scanning every packet for every incomplete flow.

## Live behavior and retention

Live mode performs **bounded rolling-PCAP analysis**, not continuous stateful Zeek streaming. Defaults are a 30-second window, two analysis workers and a five-second polling pause per worker. Each worker reuses its SSH connection, cached pinned-tool versions and an isolated sensor container; its container renews before a 15-minute lease expires. Tool results transfer in one bounded tar bundle with strict member checks. Analysis remains CPU-bound on a small VM; more workers do not create more CPU capacity. Use `serve --workers 1|2|3|4 --window 30 --interval 5` to tune only after measurement.

Each source keeps two segments, each at most 4 MiB. Time rotation bounds the normal reanalysis window; it can be delayed by pending analysis and therefore is not a hard wall-clock latency guarantee. The previous retained segment supplies context to reconstruct exchanges crossing one rotation. Snapshot provenance and `spool_bytes` distinguish combined-context bytes from the source segment's processed watermark. Exchanges exceeding retained context can still be incomplete and are flagged.

A 256 MiB working-PCAP budget reserves headroom before staging. Committed live captures can move to a separately bounded 1 GiB archive: copy, verify SHA-256, publish the database reference, then remove the old working copy. Archived bytes remain traceable and `raw_retained` stays true. Unprocessed spool data and offline evidence are never silently evicted. Archive/full-working-budget pressure remains visible and retryable; the analysis supervisor does not permanently exit. A backpressured reader keeps its pending buffer and retries without deliberately reconnecting/replaying the feed. If the remote connection fails during prolonged backpressure, recovery records the interruption; loss is not assumed absent.

Analytical history has explicit operator-requested archival. `python -m module2 --state runs/module2 archive-history --before-unix <UTC-cutoff>` creates an integrity-checked SQLite backup and SHA-256 manifest before pruning eligible closed live scopes, then compacts the active database. Active recordings and offline scopes are excluded; raw evidence is not deleted by this command. The history archive has a 1 GiB ceiling. Stop monitoring before maintenance and retain the generated backup with its raw-reference files. Backups remain separate queryable SQLite files, not automatically merged into the live dashboard. No automatic destructive age policy is enabled.

Eviction checks the analyzed byte watermark, not just whether the segment was analyzed once: packets appended after its last snapshot must be processed first. Whole-scope expiration checks every spool segment against its successfully imported hash. Backpressured readers retry with bounded backoff while analysis catches up. Temporary analysis staging can require an additional capture-sized working copy; unprocessed evidence is not silently discarded to make room.

Header-only segments contain no packet evidence and cannot permanently block quiet-link reconnection. Storage accounting tolerates another reader retiring a segment concurrently. A disconnected sensor SSH session aborts that analysis cycle; pending snapshots remain for a new connection rather than being retried through an already dead SSH client.

Reconnect uses exponential backoff up to 30 seconds and a fresh PCAP segment, preserving raw boundaries instead of concatenating headers. GNS3 may replay earlier bytes; correlation prevents matching TCP observations from inflating canonical totals. Starting a new user recording creates a new scope; an unexpected service restart resumes a persisted enabled scope. SSH credentials/key access must still be available at restart.

Stopping closes capture readers and waits up to 210 seconds for analysis to finish. Concurrent start/stop requests receive HTTP 409. SSH commands drain stdout/stderr on the owned channel under a wall-clock deadline and a 1 MiB output bound; no detached stderr-reading threads remain. Transfers and tool results are bounded. On disconnection, remote jobs/containers may survive until their lease expires; the service does not stop containers it does not own.

Classic PCAP is supported; PCAPNG import is explicitly refused. Capture-drop statistics are unavailable on the GNS3 HTTP feed, not zero. Only observed links are covered. Per-analysis metrics report first/latest packet timestamp to committed-record availability, as well as tool processing time. The latest-packet distribution is a snapshot-freshness metric, not latency for every packet or a ransomware-detection delay.

## Evaluation

```powershell
.\.venv\Scripts\python.exe -m unittest test_module2 -v
.\.venv\Scripts\python.exe -m unittest test_module2_hardening -v
.\.venv\Scripts\python.exe verify_module2.py --captures <ORIGINAL-PCAP-FOLDER> --live
```

Use `evaluate_module2_service.py --seconds 900 --state <sensor-state> --freshness-target 60` for a sustained lab observation after initial backlog recovery. It saves resource samples, source analysis ages, fresh per-analysis timing samples and an explicit pass/fail result. The 60-second p95 target is provisional and must be agreed with the supervisor. Keep warm-up/failure observations and do not relabel a failed run as passed. The result describes only the measured duration, offered workload and VM resources.

`verify_module2.py` runs actual Linux Zeek/TShark analysis, checks the independent SYN reference, DICOM CT/PACS evidence, HL7 ORU/ACK evidence, forced-repeat idempotence, overlapping TCP observations, malformed input and provenance. Optional live checks wait for all 12 normal sources with no browser used, interrupt the collector's own pump reader, and check reconnection. It preserves JSON, JSONL and console output under `runs/module2/`. Unit tests use explicit fixtures and do not substitute for these actual-tool checks.

The original Module 1 service receipts are cumulative and are not a per-flow ground truth. Protocol-byte references and fresh Module 1 service checks must be presented separately. See `MODULE2_EVALUATION.md` for the measured run and outstanding limits.

`MODULE2_REVIEW.md` records the subsequent code review, fixes, independent packet-byte verification and academic scope assessment. After actual-tool acceptance, run `python review_module2.py --state <acceptance-state-directory>` to save regression transcripts, retained-capture hash checks, independent local TShark frame checks and a review report. The Windows reference TShark version is recorded separately from the pinned Linux sensor version.

For real sensor recovery coverage, add `--sensor-recovery` to `verify_module2.py --live`. It closes only that runner's own SSH connection, requires a recorded failure, and verifies a new connection plus fresh analysis from every normal source. It never stops the VM, changes SSH settings or interrupts the main monitoring service's session.

## Primary references

- [Official Zeek image](https://hub.docker.com/r/zeek/zeek)
- [Zeek connection records](https://docs.zeek.org/en/current/reference/logs/conn.html)
- [Zeek JSON logs](https://docs.zeek.org/en/current/tutorial/logs.html)
- [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html)
