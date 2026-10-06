# Mini-Hospital Testbed Evaluation

Measured on 2026-10-06 using GNS3 2.2.61 in the local VMware VM, the `iomt-hospital:2` Docker image, and thirteen streamed actor-link PCAPs decoded by TShark. The seven-phase run completed successfully. The raw local report is `gns3-hospital-v2-verification-report.json`; it is deliberately ignored by Git along with captures and session logs.

| Criterion | Observed result |
| --- | --- |
| Running topology | 16 actor containers, 3 switches, 13 monitored actor links |
| Discovery | 15 endpoint addresses from packets; the gateway is infrastructure, not a traffic source |
| Normal clinical traffic | All 12 source probes succeeded before containment |
| Imaging | CT, ultrasound, MRI, and X-ray C-ECHO/C-STORE reached PACS; final PACS C-STORE count 156 |
| Telemetry | Pump, bedside monitor, analyzer, ventilator, dialysis, and ECG received matching HL7/MLLP ACKs; final EHR HL7 count 228 |
| Maintenance | Vendor read-only pump status succeeded initially; final accepted count 12 |
| Unknown endpoint | A manual request appeared in packet-derived inventory without a registered role |
| Workstation response | Reconnaissance indicators produced risk 85; a new workstation request failed and gateway DROP count increased |
| Critical pump response | Unexpected pump-to-PACS attempts caused restriction; pump-to-EHR telemetry succeeded, while vendor-to-pump maintenance failed |
| Approved isolation | Explicit lab reviewer entry led to full pump isolation; unrelated medical traffic stayed available |
| Recovery | Reset restored all 12 normal-source paths; generators were paused at the end |
| Final capture | 6,117 frames across 13 capture streams |

The automated checks include fresh application requests, service-side receipts, per-device observed protocol evidence, and firewall packet counters; they do not rely on a scripted dashboard state. `test_live.py` additionally passed 26 unit and real-socket integration tests on the Windows host. The saved report is the second run against the same live project, so service counters are cumulative across both evaluations.

This is a bounded evaluation of the **first testbed/monitoring module**, not the final FYP. The authorized registry supplies lab roles and criticality; packet capture supplies presence and DICOM/HL7/HTTP evidence. It does not identify physical device models, prove ransomware, measure real-world detection accuracy, or implement Zeek/ML. Only the original pump has a safety-aware restriction policy; the other critical-role labels do not imply completed containment. The gateway sees cross-zone flows only; same-zone medical traffic can bypass it. No malware, real patient data, manufacturer device protocol, or hospital network was used. Future evaluation should add repeatable benign/abnormal datasets, classification ground truth, false-positive and detection-latency metrics, and a design for same-zone enforcement before claiming deployment readiness.

The prior eleven-container baseline used `iomt-hospital:1`, eight captures, 1,414 frames, 32 PACS stores, and 48 EHR HL7 receipts. Its separate report remains `gns3-hospital-verification-report.json`; it is not evidence for the current expanded topology.
