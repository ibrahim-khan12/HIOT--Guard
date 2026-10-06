# HIoT Mini-Hospital Network Lab

This is separate from the old scripted HTML prototype. It starts real processes, sends real TCP traffic, captures packets using Npcap/TShark, and derives its inventory and incident indicators from those packets. There is no pre-populated discovered inventory and no button that directly sets an incident score.

## Current verification status

The current mini-hospital has **16 GNS3 actor containers plus 3 switches**: 10 medical-device emulators, a nurses workstation, a vendor workstation, an unregistered laptop, PACS, EHR, and the inline gateway. Thirteen actor links are captured independently. On 2026-10-06, all 26 tests passed, including a real Windows loopback PCAP run. The 16-container GNS3 topology also passed its seven-phase routed evaluation with per-device protocol checks: the latest cumulative report records 6,117 captured frames, 15 observed endpoint addresses, 156 PACS C-STORE receipts, 228 EHR HL7 receipts, and nonzero gateway DROP counters. See [HOSPITAL_EVALUATION.md](HOSPITAL_EVALUATION.md) for the measured criteria and limits.

The earlier six-node native Windows and GNS3 routed paths were exercised end-to-end on 2026-09-28. That GNS3 test used server 2.2.61, Docker 29.6.2, six running containers, three switches, and three PCAP streams decoded by TShark. Fresh requests and nonzero gateway DROP counters verified workstation containment and pump-to-PACS restriction. Pump HL7 telemetry continued during restriction; explicit lab approval stopped it, and reset restored the original paths.

Earlier measured phases are saved in `gns3-verification-report.json` and `gns3-hospital-verification-report.json`; the current 16-container run is saved locally in `gns3-hospital-v2-verification-report.json` (ignored by Git because it includes raw lab evidence). These results validate isolated emulators only, not physical medical equipment, clinical deployment, or ransomware identification.

## Current Machine

- Imported VM: `D:\FYP\GNS3 VM\GNS3 VM.vmx`. Open this file in VMware, not its old OneDrive/C: location.
- Last verified controller: `http://192.168.209.142` (port 80). The IP can change after a restart; check the VM information screen.
- Current project: `HIoT Mini Hospital Expanded 20261006-144322`, tracked by `runs/gns3-hospital-v2-manifest.json`. Earlier projects and manifests are retained; the previous hospital's containers were stopped to free VM memory.
- Current image: `iomt-hospital:2`, built inside the GNS3 Linux compute from `gns3-hospital-v2-image-source.zip`.
- Nested virtualization is disabled. This tested topology uses Docker containers, not KVM-accelerated QEMU appliances.
- The VM was moved from C: after that drive filled. Disk/config hashes were checked after the move; stale lock folders were retained under the VM folder rather than deleting disk files.

The GNS3 web interface also displays the topology; the desktop GUI is not required to run this already prepared lab. Keep VMware/GNS3 management on the private host network. Do not expose the controller or node consoles to the internet.

The managed project has `auto_close` disabled so closing/disconnecting its topology page does not stop the nodes. Host sleep still interrupts live capture connections; reconnect the capture session afterward. No Windows power or security settings were changed.

## Share The Topology

The ready-to-import [portable GNS3 project](HIoT-Mini-Hospital-Expanded.gns3project) contains the 16 actors, 3 switches, and 18 links. It is a topology export, not a VM image or a prebuilt Docker image; it has no packet captures. Each teammate needs a GNS3 2.2.x VM/Linux Docker compute and must build `iomt-hospital:2` from `gns3-hospital-v2-image-source.zip` as described below.

1. Build the Docker image on that teammate's GNS3 Linux compute. The project references the exact tag `iomt-hospital:2`.
2. In the GNS3 project list, choose **Import Project** (or **File > Import portable project** in the desktop GUI) and select `HIoT-Mini-Hospital-Expanded.gns3project`. This is a project, not an appliance.
3. Run `run-live-iomt.cmd` once to prepare `.venv` and open the console, but do not start a capture session yet. In a fresh checkout, register the imported project using the name shown by GNS3. Replace the example address with that teammate's private VM IP:

```powershell
.\.venv\Scripts\python.exe attach_topology.py --gns3 http://192.168.56.101 --project-name "HIoT Mini Hospital Expanded 20261006-144322"
```

If GNS3 renamed the project during import, pass its actual name, or use `--project-id` with the ID shown by the GNS3 controller. The command validates every actor, switch, image tag, and link before writing `runs/gns3-hospital-v2-manifest.json`. It refuses to overwrite an existing manifest; keep separate checkouts or runs folders for separate labs.

4. In the console, select **GNS3 routed lab**, enter the same private GNS3 URL, and select **Start session**. The console will reuse the imported project and capture its actor links. **Start normal traffic** to populate packet-derived inventory; use **Verify clinical paths** to check fresh service receipts.

Starting a GNS3 session without importing or registering this archive remains supported: the adapter builds an equivalent new project automatically. The portable export is provided so teammates can see and share the exact topology, not because the builder requires it.

## Run Now: Native Live Capture

1. Open `D:\FYP\iomt-live\run-live-iomt.cmd`. It prepares an isolated Python environment and opens `http://127.0.0.1:8877/`.
2. Select **Native packet-capture lab** and **Start session**. At this point the observed inventory is empty.
3. Select **Start normal traffic**. Separate processes send CT, ultrasound, MRI, and X-ray synthetic DICOM C-ECHO/C-STORE; pump, bedside-monitor, lab-analyzer, ventilator, dialysis, and ECG synthetic HL7/MLLP telemetry; workstation EHR HTTP; and read-only vendor-to-pump HTTP. Assets and protocol evidence appear only when packets are captured.
4. Select an asset to inspect the actual AE titles, Verification SOP Class, HL7 MSH sender/message type, or TCP indicators.
5. Open **Response & Verification** and select **Verify clinical paths**. All twelve normal-source checks should succeed; PACS/EHR/pump receipt counters should increase.
6. Select **Unknown endpoint request**. Its traffic is captured, but its IP has no authorized registry entry. It should remain unregistered, not automatically classified as a medical device.
7. Select **Workstation probes**. Eight harmless TCP connect attempts target only the two configured lab service IPs. The monitor observes them; correlated indicators generate risk 85 and request quarantine.
8. Select **Verify clinical paths** again. The workstation request should fail, while medical traffic and vendor maintenance still succeed.
9. Select **Pump anomaly**. Unexpected pump-to-imaging connections trigger a safety restriction, not isolation. Pump HL7 telemetry should still succeed; vendor maintenance to the pump should fail.
10. Enter a lab reviewer name and approve pump isolation. A fresh verification should now fail for pump telemetry too. The other imaging and telemetry paths remain available.
11. Export the report. Use **Reset policy** to restore access without erasing packet history. Use **Stop session** when finished.

Native enforcement is a peer-IP service ACL at disposable PACS/EHR/pump services. It is NOT routed network isolation, an OS firewall, or GNS3. The browser labels it accordingly. This mode verifies the traffic/capture/parser/detection/response loop while the GNS3 runtime is prepared.

Capture is restricted to `127.77.0.0/16`; other Wi-Fi or user traffic is not monitored. Files go into `runs/<session>/`; stopping a session also saves its measured state and receipts to `report.json`. A session stops capturing at approximately 32 MB. Restart the session after that limit. Pause traffic or stop the session when not demonstrating it.

## GNS3 Runtime Setup

Use GNS3 **2.2.x**, preferably matching GUI and VM versions. This adapter does not support the different GNS3 3.x API.

Official downloads and installation references:

- [GNS3 GUI releases](https://github.com/GNS3/gns3-gui/releases)
- [GNS3 VM download guide](https://docs.gns3.com/docs/getting-started/installation/download-gns3-vm)
- [Windows installation](https://docs.gns3.com/docs/getting-started/installation/windows)
- [VM setup wizard](https://docs.gns3.com/docs/getting-started/setup-wizard-gns3-vm)

VMware Workstation is installed on this machine. The lightweight lab uses containers, not six full Windows/Linux VMs and not licensed Cisco images. A 2-vCPU, 2-GB allocation is a starting point; measure resource usage before increasing it. The successful test on this host used 1 vCPU and 2 GB RAM. The host has around 8 GB RAM. Reserve about 15 GB free disk space as a practical fresh setup/build budget, and store the VM on a drive with adequate free space. Do not delete other project files to make room automatically.

1. Install the GNS3 GUI and import the matching VMware GNS3 VM using the official guide. Complete license/admin prompts yourself. Enable the VM compute in GNS3. Keep management on a private network, not the public internet.
2. Copy `gns3-hospital-v2-image-source.zip` into the GNS3 VM using an authorized VM account, shared folder, or SCP. Extract it into a new working directory in the VM.
3. In that directory, use the VM shell to build the image:

```sh
sudo docker build -t iomt-hospital:2 .
sudo docker image inspect iomt-hospital:2
```

Build the image on the actual GNS3 Linux compute, NOT only in Windows Docker Desktop. The initial build needs internet for the official Python base image, Debian packages, and pinned PyPI libraries. The finished data-plane topology has no cloud/NAT/internet connection.

4. Open the live PoC, stop any native session, select **GNS3 routed lab**, enter the private controller IP/port shown by GNS3, and select **Start session**. A GNS3 VM controller commonly listens on port 80, while a Windows local controller commonly uses 3080. Use the actual address shown in your setup, not a guessed port.
5. The adapter creates a new `HIoT Mini Hospital Expanded <timestamp>` project, adds the containers/switches/links, starts the nodes, and streams thirteen actor-link captures through TShark. It saves project IDs in `runs/gns3-hospital-v2-manifest.json`; reconnecting reuses this project. Setup failures retain the manifest and project so retries can resume missing steps.
6. Open the same generated project in GNS3 to show the panel the topology and running nodes. Each actor uses an HTTP console: open its console in GNS3 to start/stop traffic or run a bounded probe directly from the node, independently of the monitoring dashboard. This is a useful way to prove that traffic drives the tool rather than a scripted incident button.
7. Run the native demonstration sequence above. In this mode, **Gateway Rule Evidence** should contain actual `iptables -nvL IOMT_LAB` output. Verify both blocking and the preserved clinical paths using new application requests, not just green/red icons.

If the controller uses Basic authentication, set `GNS3_USER` and `GNS3_PASSWORD` in the process environment before starting the backend. Do not put credentials in the browser URL or commit them. Keep the controller and its console-forwarding ports on a trusted private lab network.

## Topology

```text
Nurses workstation .10 -- staff switch ------ eth0 10.77.10.1
Vendor workstation .20 --/                          |
Unregistered laptop .90 --/                          |
                                                    Linux gateway
Pump .20 ------------ medical switch -------- eth1 10.77.20.1
CT .30 ----------------/                             |
Ultrasound .40 --------/                             |
Bedside monitor .50 --/                              |
Lab analyzer .60 -----/                              |
MRI scanner .70 ------/                              |
Portable X-ray .80 ---/                              |
Ventilator .90 -------/                              |
Dialysis .100 --------/                              |
ECG monitor .110 -----/                              |
PACS .30 ------------- services switch ------- eth2 10.77.30.1
EHR .40 --------------/
```

The staff, medical, and services networks are `10.77.10.0/24`, `10.77.20.0/24`, and `10.77.30.0/24`. All cross-zone traffic traverses the gateway; **same-zone traffic does not**, so this is not general isolation of every medical-device path. The gateway has no external uplink. Its rules modify only the `IOMT_LAB` chain inside that disposable container. Workstation quarantine blocks traffic to/from its lab IP. Pump restriction allows only its EHR HL7 path and established replies; full isolation blocks both directions after lab approval. Host Windows firewall rules are never changed.

| Actor | Legitimate synthetic traffic | Service-side proof |
| --- | --- | --- |
| CT and ultrasound emulators | Separate DICOM C-ECHO and C-STORE studies to PACS | PACS echo/store counters and receipts |
| Infusion pump emulator | HL7 ORU rate observation to EHR | Matching MLLP ACK and EHR receipt |
| Bedside monitor emulator | HL7 ORU heart-rate observation to EHR | Matching MLLP ACK and EHR receipt |
| Laboratory analyzer emulator | HL7 ORU glucose observation to EHR | Matching MLLP ACK and EHR receipt |
| MRI and portable X-ray emulators | Separate synthetic DICOM C-ECHO and C-STORE studies to PACS | PACS echo/store counters and receipts |
| Ventilator emulator | HL7 ORU respiratory-rate observation to EHR | Matching MLLP ACK and EHR receipt |
| Dialysis machine emulator | HL7 ORU blood-flow observation to EHR | Matching MLLP ACK and EHR receipt |
| ECG monitor emulator | HL7 ORU heart-rate observation to EHR | Matching MLLP ACK and EHR receipt |
| Nurses workstation | HTTP EHR health request | EHR receipt |
| Vendor workstation | Read-only HTTP pump maintenance status | Pump receipt; denied after restriction |
| Unregistered laptop | One manual EHR health request | Captured unknown IP, no authorized role |

All records use invented `LAB_ONLY` identity and fixed synthetic values; no patient data or device control commands are present. Source labels come from the lab configuration, while protocol evidence comes from captured packets and service receipts. The PACS counts C-STORE success but does not persist studies. The extra critical-role labels do not imply that all critical devices have containment policies yet. This testbed does not claim genuine manufacturer fingerprinting.

## What Is Measured

- Inventory: source/destination addresses actually observed in captured TCP frames.
- Protocol classification: TShark's real DICOM dissector plus HL7 MLLP/MSH or HTTP payload evidence. Port numbers alone do not establish DICOM or HL7.
- Registry enrichment: expected role and safety criticality come from the authorized lab registry in `config.py`. These are not inferred device-model claims. A pump emulator's synthetic HL7 is not a vendor infusion-pump control protocol.
- Workstation rule, 60-second window: 30 points for unexpected connections to at least two destinations, 30 for SMB/RDP ports, and 25 for at least six unexpected destination/service pairs. All three together produce 85 and request quarantine. Retransmitted SYNs are not separate attempts. These are explainable lab heuristics, not a trained ML model or proof of malware.
- Pump rule: at least three fresh unexpected connections request restriction. They never automatically request full isolation.
- Outcome: fresh protocol success/failure, PACS/EHR/pump service receipts, applied-policy audit, and (in GNS3) gateway rule/counter output.
- Risk history: the incident peak is retained until policy reset, even when new normal traffic reduces the rolling-window score. The detection audit records the observed counts at the decision time.

Phishing, credential theft, SMB authentication/exploitation, encryption, and ransomware payloads are NOT implemented. The demonstration represents post-compromise reconnaissance/lateral-movement indicators only. No arbitrary target IP, exploit, malware, patient data, or real medical equipment is used.

## Tests

From this directory, using the isolated environment:

```powershell
$env:IOMT_INTEGRATION='1'
.\.venv\Scripts\python.exe -m unittest test_live -v
```

Stop an existing native session first: integration tests deliberately refuse to take over occupied management ports. The integration test starts real services, captures real packets, checks DICOM/HL7 parsing, observes detection, verifies ACL effects and pump safety, and stops its processes afterward. Unit tests additionally check quiet networks, expected clinical flows, retransmission handling, and scoped gateway rule construction.

To evaluate the expanded routed lab against the running local console after rebuilding the new GNS3 image:

```powershell
.\.venv\Scripts\python.exe verify_gns3.py --gns3 http://192.168.209.142 --output gns3-hospital-v2-verification-report.json
```

Use the VM's current address. This command creates/reuses only the current managed project, checks thirteen packet streams, all twelve legitimate paths, unknown-endpoint discovery, service receipts, gateway DROP counters, and policy preservation, then saves measured phases. It refuses to take over a different active capture session. **Do not present earlier project reports as evidence for the current topology.** Zeek, trained ML classification, physical IoMT hardware, and hospital deployment are outside this first testbed module.
