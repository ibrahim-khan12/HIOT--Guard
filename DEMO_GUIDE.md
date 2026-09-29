# IoMT PoC: Panel Demonstration

## Open These Pages

Keep the GNS3 VM running in VMware. Its file is `D:\FYP\GNS3 VM\GNS3 VM.vmx`, not its former C: location. The following addresses were verified on 2026-09-28. If the VM address changes, use its new information-screen address instead.

- Tool: http://127.0.0.1:8877/
- GNS3 topology: http://192.168.209.142/static/web-ui/server/1/project/520085ba-f5dd-47e8-8254-a3debbd75d46
- Workstation traffic source: http://192.168.209.142:5000/
- Pump traffic source: http://192.168.209.142:5002/
- Imaging traffic source: http://192.168.209.142:5004/

If the tool is not running, open `D:\FYP\iomt-live\run-live-iomt.cmd`. Select **GNS3 routed lab**, enter `http://192.168.209.142`, and select **Start session**. The saved manifest reconnects to the prepared project. Stop a native session first if one is active. Keep all management pages private to this lab computer/network.

## What Is Happening

Three independent containers generate actual traffic:

| Source | Destination | Actual exchange |
| --- | --- | --- |
| Nurses workstation, 10.77.10.10 | EHR, 10.77.30.40:8081 | HTTP health request and response |
| Pump emulator, 10.77.20.20 | EHR, 10.77.30.40:2575 | Synthetic HL7/MLLP telemetry and acknowledgement |
| Imaging emulator, 10.77.20.30 | PACS, 10.77.30.30:11112 | DICOM association and C-ECHO |

All cross-zone traffic passes through the Linux gateway. GNS3 captures the actor links; the tool streams those PCAP bytes to TShark, extracts packet/protocol evidence, and computes explainable risk. A critical workstation decision changes the gateway's real `IOMT_LAB` firewall chain. New application requests and gateway DROP counters establish whether containment worked.

The workstation is a supporting hospital endpoint, not itself a medical device. The pump and imaging nodes emulate IoMT-related workflows. PACS/EHR are supporting services. This is an IoMT protection use case with a compromised adjacent workstation as one possible entry point.

## Demonstrate In This Order

1. **Show the network.** Open the GNS3 topology and identify staff, medical, and service zones plus the inline gateway. Explain that these are isolated emulators with no internet data-plane link.
2. **Show discovery from an empty capture.** Select **Reset policy**, then **Stop session** and **Start session** in the tool. Start/stop only these lab actors. A fresh session has no observed assets until TCP traffic arrives; configured registry names are enrichment, not evidence of discovery.
3. **Generate traffic outside the dashboard.** Open each of the three traffic-source pages and select **Start**. Return to the tool: frame counts increase and five communicating endpoints appear. This proves the tool is observing independent nodes. Its **Start normal traffic** button is a convenient remote control for the same generators.
4. **Show protocol evidence.** Select the imaging asset and inspect DICOM AE titles and Verification SOP Class. Select the pump and inspect HL7 sender/message evidence. Open **Packet Evidence** to show actual source, destination, port, capture, and time. A port number alone is not a device classification.
5. **Establish the baseline.** Select **Verify clinical paths**, then **Response & Verification**. The workstation HTTP check, pump acknowledgement, and imaging C-ECHO should all succeed. Show PACS/EHR receipts.
6. **Demonstrate a compromised workstation.** Select **Recon** on the workstation traffic-source page. It attempts eight bounded TCP connections to the two lab service addresses. The captured service/destination spread and SMB/RDP-port indicators produce a peak risk of 85 and automatic workstation quarantine. This represents post-compromise indicators, not phishing or a ransomware payload.
7. **Prove containment.** Select **Verify clinical paths** again. The workstation should fail, but pump and imaging should succeed. Show the applied gateway rules and nonzero workstation DROP packet counter. Do not use just a red status label as proof.
8. **Demonstrate medical-device safety.** Select **Anomaly** on the pump source page. Unexpected pump-to-PACS attempts cause **restricted**, not isolated, policy. Verify clinical paths: pump telemetry must still succeed. Repeat the pump anomaly and show the unexpected connections now fail plus the pump DROP counter increases. Enter a lab reviewer name in the tool and approve isolation; only then should pump telemetry fail. Imaging remains available. This is a lab approval record, not authenticated clinical authorization.
9. **Preserve evidence and recover.** Export the incident report before resetting. It contains captured indicators, events, receipts, applied policy, and gateway evidence. Select **Reset policy** and **Verify clinical paths**: all three paths should succeed again. Pause traffic when finished; stop the session to close capture and save its report/PCAP files.

Workstation Recon and Pump Anomaly can take several seconds while blocked connection attempts time out. The node page reports a running command and disables its controls until completion; wait for the completion message before resetting. After a long pause, select **Start normal traffic** before continuing. The rolling risk score can fall after 60 seconds, while the incident peak remains until reset. Keep the host computer awake during the demonstration. Host sleep or loss of the VM connection interrupts capture; stop and restart the session after reconnecting.

## Explain The Risk Decision

- Workstation: 30 points for unexpected connections to at least two protected destinations, 30 for SMB/RDP ports, and 25 for at least six unexpected destination/service pairs in a 60-second window. The correlated score of 85 requests quarantine. Retransmitted SYNs do not count as fresh attempts.
- Pump: at least three fresh unexpected connections request restricted communication. Only its EHR HL7 path and established replies remain permitted. The rules never automatically fully isolate the pump.

These are transparent lab rules, not trained ML or conclusive ransomware detection. Network containment limits these routed communications; it does not remove malware, reverse encryption, or implement recovery from backups.

## Evidence And Boundaries

The routed verification measures six phases in `gns3-verification-report.json`, including fresh requests and actual nonzero firewall counters. Twenty-three regression/native integration tests cover the implementation. Session captures and saved reports are under `runs/<session>/`. `gns3-quiet-verification.json` records a measured pause exceeding 120 seconds with three healthy capture streams.

Real: container processes, protocol exchanges, captured packets, parsing, risk calculation, gateway firewall rules, application success/failure, and reports.

Emulated: physical medical equipment, clinical workflows, the initial workstation compromise, and abnormal behavior. No real ransomware, encryption, exploit, patient record, or medical-device command is used.

Not established: make/model identification, broad automatic IoMT classification, accuracy across real hospitals, resistance to evasion, production authentication, clinical approval, legal compliance certification, or safe deployment on patient-connected equipment. Registry role labels are known lab configuration. Explain these limits directly rather than claiming the PoC is a complete production system.
