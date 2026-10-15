# Module 2 Evaluation Record

Evaluated on 15 October 2026, Asia/Karachi. This records an initial working passive-monitoring implementation, not hospital deployment readiness or the completed FYP. All runtime evidence referenced below is preserved locally under `runs/module2/`, outside Git.

## Assessed implementation

- Module 1 UI baseline saved separately as commits `df00535` and `118c2f4` on `module-1` before branching.
- Module 2 implementation is on `module-2`; source commits follow the requested one-file-per-commit convention.
- Python 3.13.1 on Windows; separate loopback services on ports 8877 and 8878.
- Existing GNS3 2.2.61 Linux compute at the verified private VM address.
- Zeek 8.0.10 from the official image, pinned base digest `sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3`.
- Linux TShark 4.4.19, Debian package `4.4.19-0+deb13u1`.
- Built sensor image ID `sha256:6b604516bc6da8193fb4ef281a773435d152452a3d0c4c5ad22ed97719af53e0`.

The exact pinned build was repeated successfully. Sensor containers have no network access while analyzing captures. Version/SSH-host-key/build records are in `sensor-lock.json` and `sensor-setup-console.txt`. Credentials are excluded.

## Saved capture acceptance

The original CT and pump PCAPs were read without editing them. Inputs are from the Module 1 evidence session `20261014-195042`.

| Capture | Frames | TCP connections | Additional Zeek records | Evidence |
| --- | ---: | ---: | ---: | --- |
| CT `modality.pcap` | 3,042 | 152 | 47 ICMP | Calling AE `LAB_CT`, called AE `LAB_PACS`; DICOM association metadata |
| `pump.pcap` | 2,241 | 216 | 47 ICMP | `LAB_PUMP`, `ORU^R01`, EHR ACK; also maintenance and prior abnormal-path traffic |
| Total before overlap test | 5,283 | 368 | 94 ICMP | 462 canonical connection records |

The independent reference counts unique initial TCP SYN tuples/sequences from TShark. Both per-capture TCP totals match Zeek. ICMP control records are outside that SYN comparison and have null service ports in the public schema. The pump PCAP includes vendor-to-pump maintenance and earlier pump-to-PACS probes, so its 216 connections are not all successful HL7 exchanges.

Three original CT SYN rows were additionally inspected and matched to stored records:

| Original frame | Source | Destination |
| ---: | --- | --- |
| 37 | `10.77.20.30:39535` | `10.77.30.30:11112` |
| 69 | `10.77.20.30:37149` | `10.77.30.30:11112` |
| 91 | `10.77.20.30:33073` | `10.77.30.30:11112` |

The timestamps and canonical IDs are preserved in `manual-reference.json`. Every medical evidence record includes its original capture ID and supporting frame. HL7 clinical observation values are excluded from the analytical store; raw PCAP contents remain separately retained.

## Functional results

| Check | Observed result |
| --- | --- |
| New deterministic parser/storage/API tests | 37 passed; no skips |
| Existing Module 1 suite with real traffic enabled | 27 passed, including native capture integration; no skips |
| Actual-tool acceptance | Nine checks passed in the saved offline/live acceptance run |
| Repeated import with forced Zeek reanalysis | Canonical IDs and counts unchanged despite fresh Zeek UIDs |
| Duplicate CT capture imported as another observation source | 368 canonical TCP connections remained; 152 TCP connections correlated across links |
| Non-SYN observations | ICMP copies deliberately remained distinct; no unsupported deduplication claim |
| Truncated PCAP | Refused; the expected failure is visible in health history |
| All normal live sources | All 12 normal generators produced analyzed observations with no browser used by the acceptance runner |
| Reader interruption | The collector's own pump stream was closed; it reconnected and analyzed a new segment |
| Service restart | A new process resumed the same persisted recording scope; saved in `restart-check.json` |
| Module 2 UI stop | Module 1 continued with 13 healthy captures and 12 generating actors |
| Fresh Module 1 clinical paths after integration | 12 successful application checks; saved in `module1-clinical-paths.json` |
| Browser filtering and export | CT address plus DICOM filter yielded 212 matching records in the inspected download snapshot |

`acceptance-report.json` contains the original nine checks and live measurements. The final-code offline recheck is saved separately in `offline-final-report.json`, preserving the original live evidence. Unit and Module 1 regression transcripts are saved alongside them. Desktop and mobile screenshots are in `screenshots/desktop.jpg` and `screenshots/mobile.jpg` under the same runtime evidence folder; both layouts were checked for overflowing controls.

## Timing and resources

The actual saved-capture and live acceptance run took approximately 134.27 seconds. Individual first-cycle live sensor analyses took 3.01-4.71 seconds for the tested snapshots. The saved samples' latest medical-flow age at analysis ranged approximately 2.19-12.06 seconds. Those values are not a bound on dashboard freshness: the default 20-second cycle pause plus serial analysis of all dirty sources increases the interval between updates to a particular source.

A separate running-service observation lasted 124.23 seconds and recorded 20 resource samples:

- All 13 capture sources were analyzed during the sampled window.
- Latest analysis timestamps continued advancing; no unexpected errors were recorded.
- Windows service working set reached 81.77 MiB in the sampled snapshots; the process peak-working-set counter reached 113.41 MiB.
- Cumulative service CPU time over the sampled wall-clock interval averaged about 13.85% of one CPU core.
- Two nonzero Linux analysis-container memory samples were 8.238 MiB and 57.68 MiB; another container had already exited and reported zero. These sparse samples do not establish peak sensor memory.
- Docker CPU samples were bursty, including a short-container sample above 100%; they are preserved as raw observations and are not a sustained throughput or CPU-budget guarantee.
- Capture-drop statistics were unavailable from the GNS3 HTTP feed. They were not represented as zero.

See `service-measurements.json` and its console transcript. This is a short lab stability/resource check, not an hours-long soak test or hospital-scale benchmark. Later evaluation needs larger captures, controlled offered load and longer runs.

## Defects found and addressed

The first real-capture run showed TShark boolean fields as `True`/`False`; the initial SYN matcher expected numeric strings. Both encodings are now accepted and tested. Early Windows tests exposed SQLite handles remaining open after transaction contexts; explicit connection closure fixed file locking and resource warnings. Final test output is preserved without replacing failures with PASS labels.

## Remaining limits

Live processing uses cumulative PCAP snapshots rather than a continuous stateful Zeek feed. Connections/messages crossing rotation boundaries can be incomplete and are flagged. Classic PCAP is supported; PCAPNG collection is explicitly refused. Cross-link canonicalization requires a matching TCP SYN fingerprint and time window; UDP, ICMP and midstream TCP are not automatically merged. Raw retention is bounded, but analytical database archival remains further work.

Physical-device identity, trained classification, threat/risk decisions, ransomware identification, authenticated clinical approval and firewall enforcement are outside this module. Module 1's configured medical names and cumulative service receipts are not substituted for protocol evidence or per-flow ground truth. No real patient data or medical hardware was involved.

## Reproduce

Follow `MODULE2.md` for setup and APIs. Run:

```powershell
.\.venv\Scripts\python.exe -m unittest test_module2 -v
$env:IOMT_INTEGRATION='1'
.\.venv\Scripts\python.exe -m unittest test_live -v
.\.venv\Scripts\python.exe verify_module2.py --captures <ORIGINAL-PCAP-FOLDER> --live
.\.venv\Scripts\python.exe evaluate_module2_service.py --seconds 120
```

The sensor requires the pinned image and a verified private VM host key. Keep original PCAPs and run artifacts offline; do not commit secrets or expose the controller publicly.
