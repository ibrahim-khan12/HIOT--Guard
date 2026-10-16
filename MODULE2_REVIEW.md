# Module 2 Implementation Review

Review date: 15 October 2026. Scope: the current `module-2` worktree, actual saved CT/pump captures, the running GNS3 hospital and the separate monitoring service. This supersedes the earlier 37-test count for the reviewed local code; it does not replace the original evaluation record.

## Verdict

**Recovery follow-up: the functional lab implementation has been restored and recovery verified.** A later check found SSH failures and capture backpressure; at continuation, the GNS3 VM and both local services were stopped. The existing VM/services were restored without discarding the original recording. Review also identified and fixed a storage-accounting race during segment rotation, failed-SSH resource cleanup and quiet-link backpressure. All 13 main-service readers recovered with no current errors. A separate actual-tool test deliberately closed only its own sensor SSH connection, observed the error, opened a new connection and resumed every normal source: 49.72 seconds in the pre-index run and 66.67 seconds in the final repeated run. This is a verified lab milestone, not production completion or a long-running uptime guarantee.

This is a functional, technically substantial **Passive Network Monitoring and Traffic Processing** module for the FYP, not a hard-coded dashboard. It consumes generated network packets, executes Zeek/TShark in the Linux sensor, extracts packet-backed DICOM/HL7 metadata, correlates supported overlapping observations, and stores a versioned output for later modules.

It is a defensible evaluated lab implementation, **not a finished hospital monitoring product or a validated real-time ransomware detector**. Academic acceptance and the final division of modules remain matters for the supervisor. Using established tools is appropriate; the contribution to demonstrate is the integration, evidence handling, normalization, correlation, reliability and evaluation, not an assertion that the project invented Zeek.

## Important Remaining Findings

1. **Live update latency remains the main architectural limitation.** The collector serially reprocesses cumulative PCAP snapshots for 13 links, with a 20-second pause between cycles. One inspected status sample had latest-analysis ages of approximately 41-132 seconds for selected normal sources. Those are status ages, not end-to-end detection-delay measurements or a latency bound. Later detection/containment cannot promise immediate action on top of this implementation. Evaluate shorter bounded windows or continuous stateful sensor output before making a strong real-time claim.
2. **Deduplication has explicit coverage limits.** Matching TCP SYN fingerprints are correlated; UDP, ICMP, midstream TCP and some rotation-spanning exchanges can remain separate or incomplete. Combined totals are not guaranteed to be unique hospital-wide sessions for every transport.
3. **Evaluation is successful within the measured lab windows, not sufficient for deployment claims.** A clean 123.81-second post-recovery stability check passed with 13 samples and every sampled collector state healthy. A separate recovery-period observation preserves initial errors rather than being relabeled a clean pass. These checks do not establish hours-long stability, maximum traffic rate, packet-loss performance or generalization to real medical hardware. Capture-drop counters are unavailable on the GNS3 feed, not zero.
4. **Memory and archival need a defined budget.** The accumulated-history run reached a sampled Windows working set of 852.58 MiB and averaged about 23.8% of one CPU core over the sampled interval. This is much larger than the initial small-history measurement. Indexed reads and a two-scope canonical cache improve interactive response, but scope materialization, export, parser buffers and cached history still consume memory. Latest health state persists, not a complete append-only transition history. Analytical database/log archival and multi-hour memory evaluation remain further work. Raw retention preserves unprocessed evidence and can report a limited state rather than guaranteeing uninterrupted operation at arbitrary offered load.
5. **Protocol and testbed boundaries must stay explicit.** The evaluated medical evidence is DICOM association metadata and HL7 v2/MLLP sender/message metadata. This is not full clinical message validation, BACnet semantic analysis, encrypted-payload decryption, authenticated identity or physical-device model classification. The lab uses emulators, not real patients or medical hardware.

## Defects Fixed During This Review

| Problem found | Correction and regression coverage |
| --- | --- |
| A segment analyzed once could later grow and be evicted with an unprocessed tail | Track successfully analyzed byte watermarks; preserve the tail across rotation and restart |
| Old-scope retention could remove spool files that had never been analyzed | Require a matching imported hash for every spool segment before whole-scope expiration |
| Failed cumulative reanalysis could overwrite bytes referenced by the previous database record | Analyze in a fresh staging directory and publish a content-addressed raw revision only after analysis succeeds |
| Reprocessing could leave old observation rows that were absent from the replacement result | Replace the capture's observation set transactionally while preserving other captures |
| Later HL7 messages on a persistent TCP connection could cite the first message's frame | Preserve contributing byte spans, actual start frame, payload offset and supporting frames |
| TCP medical evidence could match a same-address/port UDP flow | Restrict medical evidence association to TCP records |
| An enabled but unhealthy collector could still display a healthy running badge | Add worker/error-aware collector status and a degraded dashboard indication |
| A five-second stop wait could abandon a still-running analysis during runner teardown | Wait on a shared bounded shutdown deadline, retain an honest failure state on timeout, and bound sensor I/O |
| Rotation could remove another source's file between storage enumeration and `stat`, failing the current import | Shared raw-storage accounting tolerates concurrent retirement; unrelated I/O errors still surface |
| A dead SSH session could cascade errors through the rest of the analysis cycle, and failed initialization could leave resources open | Abort the disconnected cycle, close partial clients safely and reconnect on the next cycle; unit and real SSH-interruption tests |
| Quiet header-only segments could block future reconnects despite containing no packets | Header-only segments can be acknowledged/retired without discarding any packet evidence |
| Browser disconnects during HTTP response headers generated noisy server tracebacks | Guard the header write as well as the response body |
| Dashboard queries repeatedly loaded unrelated scopes and rebuilt the same canonical history | Add capture/canonical indexes, scope-restricted reads and a bounded two-scope cache; an SQLite revision updated transactionally invalidates caches across processes, and consumers receive independent record copies |

The first audit's traffic checks passed but teardown failed; that run was not accepted as a successful complete run. The subsequent real acceptance completed with successful shutdown.

## Verified Evidence

Runtime evidence is local and ignored by Git. The initial review is in `runs/module2-audit-20261015/`; the subsequent recovery and final regression evidence is in `runs/module2-recovery-20261015/`.

| Requirement | Current evidence |
| --- | --- |
| Parser, storage, retention, lifecycle, cache and API behavior | Recovery-folder `test_module2.txt`: 56 tests passed, no skips |
| Preserve Module 1 behavior | `test_live.txt`: 27 tests passed, including real local traffic, no skips |
| Actual pinned Linux tools, not fixtures | Recovery-folder `acceptance-report.json`: ten offline/live checks passed, including browser-independent collection, pump-reader reconnection and deliberate owned sensor-SSH interruption/recovery |
| Saved CT and pump reference totals | 152 CT TCP connections + 216 pump-capture TCP connections = 368; unchanged after duplicate CT observation import |
| Exact clinical paths | Independent byte review confirms 152 CT-to-PACS connections on `10.77.20.30 -> 10.77.30.30:11112`, and 141 pump ORU connections on `10.77.20.20 -> 10.77.30.40:2575` |
| Medical evidence backed by bytes | `review-report.json`: 608 DICOM evidence entries and 282 HL7 entries checked against referenced frames; three retained capture hashes verified; SQLite integrity check `ok` |
| Reference-tool independence | Local reference TShark 4.6.3, recorded separately from Linux sensor TShark 4.4.19 / Zeek 8.0.10 |
| Malformed input and repeat imports | Truncated PCAP visibly rejected; cached and forced imports do not inflate the verified TCP totals |
| Collection without its dashboard | `service-measurements.json`: dashboard was navigated to a blank page during a 125.73-second check; 19 samples; analyses advanced and all 13 sources were analyzed; no unexpected errors |
| Resource observation | Windows sampled working set up to 117.66 MiB; process peak-working-set counter 191.72 MiB; sampled CPU-time delta about 13.88% of one core. Sparse container memory samples are not a peak benchmark |
| Browser behavior | Desktop/mobile inspection, DICOM address/protocol filtering, keyboard-accessible flow evidence, and an actual downloaded JSONL export |
| Final clean stability | Recovery-folder `service-measurements.json`: passed; 123.81 seconds, 13 samples, all sampled collector states healthy and analysis timestamps advancing |
| Accumulated-history query response | `api-timing.json`, at 83,346 observations: warm 200-row history calls 0.027-0.098 seconds, summaries 0.036-0.038 seconds; initial status request 2.149 seconds. The recorded pre-index calls were approximately 7.755 seconds for history and 4.829 seconds for summary. These are lab samples, not latency guarantees |
| Original recording preserved | Graceful service reload resumed the existing `live-fb1b4d168747436c9fb2d6107b82d490` scope; no fresh empty session was substituted for backlog recovery |
| Final console evidence | Recovery-folder `console.jpg`; the separate console remains on port 8878 and Module 1 on port 8877 |

The recovery observation includes initial backlog/stale-error states and must not be described as a clean stability pass. Preserve it separately from the subsequent steady-state measurement. The stopped VM is an external dependency failure; the collector is expected to report unavailable analysis, preserve bounded pending evidence and recover when the dependency returns, not silently substitute generated dashboard data.

The pre-index recovery acceptance is preserved separately in `acceptance-recovery-pre-index.json`; final acceptance was repeated after the query change. Source hashes in the final `review-report.json` identify the assessed implementation. The observed final clean check included source-analysis ages up to about 192 seconds during concurrent acceptance work. That reinforces the snapshot-freshness limitation; a responsive dashboard is not evidence of immediate packet processing or threat detection.

The 608 DICOM entries include evidence from the duplicate observation source and association request/response metadata. They are **not** 608 distinct devices or 608 unique DICOM sessions. The pump capture also contains maintenance/probe traffic; not all 216 TCP connections are HL7 messages. Thirteen capture sources are **not** thirteen medical-device types: Module 1 has ten medical-emulator roles, two normal staff/vendor generators and an additional unregistered actor link.

## Why This Counts as a Core Module

```text
Module 1 generated hospital traffic
    -> raw PCAP observations
    -> Zeek connection processing + packet-backed medical metadata
    -> normalized, correlated, traceable records
    -> SQLite / versioned JSONL contract
    -> later asset identity, classification and threat-detection modules
```

It has an independent input/output contract, persistent service, nontrivial parsing/correlation logic, error handling and measurable acceptance criteria. Removing it leaves later modules without a trustworthy observation layer. Its dashboard is a view of that service, not the module's primary contribution.

## Next Priorities

1. Agree with the supervisor that Module 2 owns observation/processing, while classification, risk decisions and firewall enforcement remain separate.
2. Define an acceptable measured live freshness/detection-delay target; address the snapshot architecture if it cannot meet that target.
3. Run longer and repeated experiments at documented traffic rates. Include interrupted links, restart, overlap, long-lived sessions, rotation, malformed inputs and retention pressure. Preserve failures as well as passes.
4. Freeze the versioned record contract and connect the next identity/classification module to these observed records without converting configured device labels into ground truth.

Suggested presentation statement: "Module 2 passively processes our testbed traffic into verified connection and medical-protocol records. It preserves the source capture and packet evidence, avoids double-counting supported overlapping TCP observations, and supplies structured history to later security modules. The present live implementation is snapshot-based, and we report its processing delay and visibility limits explicitly."

## Reproduce

Follow `MODULE2.md` for sensor setup. Supply credentials through the existing process environment or SSH key, not source files.

```powershell
.\.venv\Scripts\python.exe -m unittest test_module2 -v
$env:IOMT_INTEGRATION='1'
.\.venv\Scripts\python.exe -m unittest test_live -v
.\.venv\Scripts\python.exe verify_module2.py --captures <ORIGINAL-PCAP-FOLDER> --state <AUDIT-STATE> --live --sensor-recovery
.\.venv\Scripts\python.exe review_module2.py --state <AUDIT-STATE>
```

Review fixes are local worktree changes. They have not been committed or pushed as part of this review.

Primary tool references: [Zeek connection records](https://docs.zeek.org/en/current/reference/logs/conn.html), [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html).
