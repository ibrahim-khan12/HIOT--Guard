# IoMT Live Network PoC

This is separate from the old scripted HTML prototype. It starts real processes, sends real TCP traffic, captures packets using Npcap/TShark, and derives its inventory and incident indicators from those packets. There is no pre-populated discovered inventory and no button that directly sets an incident score.

## Current verification status

Both the native Windows path and the GNS3 routed path were exercised end-to-end on 2026-09-28. The GNS3 test used server 2.2.61, Docker 29.6.2, six running containers, three switches, and three actual PCAP streams decoded by TShark. Fresh requests and nonzero gateway DROP counters verified workstation containment and pump-to-PACS restriction. Pump HL7 telemetry continued during restriction; explicit lab approval stopped it, and reset restored all three clinical paths.

The measured phases are saved in `gns3-verification-report.json`. Twenty-three native/regression tests cover real-socket capture, control-response integrity, quiet capture streams, pause/resume without duplicate generators, node command retry handling, cancellation, and reset retransmission handling. These results validate this isolated emulator lab, not physical medical equipment, clinical deployment, or ransomware identification. See `DEMO_GUIDE.md` for the panel demonstration sequence.

## Current Machine

- Imported VM: `D:\FYP\GNS3 VM\GNS3 VM.vmx`. Open this file in VMware, not its old OneDrive/C: location.
- Last verified controller: `http://192.168.209.142` (port 80). The IP can change after a restart; check the VM information screen.
- Created project: `IoMT Live Defense 20260928-183011`. The saved manifest reconnects to this project.
- Container image: `iomt-live:1`, built inside this GNS3 VM from `/home/gns3/iomt-live`.
- Nested virtualization is disabled. This tested topology uses Docker containers, not KVM-accelerated QEMU appliances.
- The VM was moved from C: after that drive filled. Disk/config hashes were checked after the move; stale lock folders were retained under the VM folder rather than deleting disk files.

The GNS3 web interface also displays the topology; the desktop GUI is not required to run this already prepared lab. Keep VMware/GNS3 management on the private host network. Do not expose the controller or node consoles to the internet.

The managed project has `auto_close` disabled so closing/disconnecting its topology page does not stop the nodes. Host sleep still interrupts live capture connections; reconnect the capture session afterward. No Windows power or security settings were changed.

## Run Now: Native Live Capture

1. Open `D:\FYP\iomt-live\run-live-iomt.cmd`. It prepares an isolated Python environment and opens `http://127.0.0.1:8877/`.
2. Select **Native packet-capture lab** and **Start session**. At this point the observed inventory is empty.
3. Select **Start normal traffic**. Separate processes send DICOM C-ECHO, synthetic HL7/MLLP telemetry, and workstation HTTP health requests. Assets and protocol evidence appear only when packets are captured.
4. Select an asset to inspect the actual AE titles, Verification SOP Class, HL7 MSH sender/message type, or TCP indicators.
5. Open **Response & Verification** and select **Verify clinical paths**. All three checks should succeed; independent PACS/EHR counters should increase.
6. Select **Workstation probes**. Eight harmless TCP connect attempts target only the two configured lab service IPs. The monitor observes the connections; correlated indicators generate risk 85 and request quarantine.
7. Select **Verify clinical paths** again. The workstation request should fail, while pump telemetry and modality C-ECHO should succeed.
8. Select **Pump anomaly**. Unexpected pump-to-imaging connections trigger a safety restriction, not isolation. Pump HL7 telemetry should still succeed.
9. Enter a lab reviewer name and approve pump isolation. A fresh verification should now fail for the pump too. The imaging modality remains available.
10. Export the report. Use **Reset policy** to restore access without erasing the recorded packet history. Use **Stop session** when finished.

Native enforcement is an actual peer-IP service ACL at the disposable PACS/EHR services. It is NOT routed network isolation, an OS firewall, or GNS3. The browser labels it accordingly. This mode verifies the traffic/capture/parser/detection/response loop while the GNS3 runtime is being prepared.

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
2. Copy `gns3-image-source.zip` into the GNS3 VM using an authorized VM account, shared folder, or SCP. Extract it into a working directory in the VM.
3. In that directory, use the VM shell to build the image:

```sh
sudo docker build -t iomt-live:1 .
sudo docker image inspect iomt-live:1
```

Build the image on the actual GNS3 Linux compute, NOT only in Windows Docker Desktop. The initial build needs internet for the official Python base image, Debian packages, and pinned PyPI libraries. The finished data-plane topology has no cloud/NAT/internet connection.

4. Open the live PoC, stop any native session, select **GNS3 routed lab**, enter the private controller IP/port shown by GNS3, and select **Start session**. A GNS3 VM controller commonly listens on port 80, while a Windows local controller commonly uses 3080. Use the actual address shown in your setup, not a guessed port.
5. The adapter creates a new `IoMT Live Defense <timestamp>` project, adds the containers/switches/links, starts the nodes, and streams three actor-link captures through TShark. It saves project IDs in `runs/gns3-manifest.json`; reconnecting reuses this project. Setup failures retain the manifest and project so retries can resume missing steps.
6. Open the same generated project in GNS3 to show the panel the topology and running nodes. Each actor uses an HTTP console: open its console in GNS3 to start/stop traffic or run a bounded probe directly from the node, independently of the monitoring dashboard. This is a useful way to prove that traffic drives the tool rather than a scripted incident button.
7. Run the native demonstration sequence above. In this mode, **Gateway Rule Evidence** should contain actual `iptables -nvL IOMT_LAB` output. Verify both blocking and the preserved clinical paths using new application requests, not just green/red icons.

If the controller uses Basic authentication, set `GNS3_USER` and `GNS3_PASSWORD` in the process environment before starting the backend. Do not put credentials in the browser URL or commit them. Keep the controller and its console-forwarding ports on a trusted private lab network.

## Topology

```text
Workstation 10.77.10.10 -- staff switch ---- eth0 10.77.10.1
                                              |
Pump     10.77.20.20 --- medical switch ---- eth1 10.77.20.1
Modality 10.77.20.30 ----/                     |
                                       Linux inline gateway
                                              |
PACS 10.77.30.30 ------- services switch --- eth2 10.77.30.1
EHR  10.77.30.40 -------/
```

All cross-zone traffic traverses the gateway. The gateway has no external uplink. Its rules modify only the `IOMT_LAB` chain inside that disposable container. Workstation quarantine blocks traffic to/from its lab IP. Pump restriction allows only its EHR HL7 path and established replies; full isolation blocks both directions after the lab approval step. Host Windows firewall rules are never changed.

## What Is Measured

- Inventory: source/destination addresses actually observed in captured TCP frames.
- Protocol classification: TShark's real DICOM dissector plus HL7 MLLP/MSH or HTTP payload evidence. Port numbers alone do not establish DICOM or HL7.
- Registry enrichment: expected role and safety criticality come from the authorized lab registry in `config.py`. These are not inferred device-model claims. A pump emulator's synthetic HL7 is not a vendor infusion-pump control protocol.
- Workstation rule, 60-second window: 30 points for unexpected connections to at least two destinations, 30 for SMB/RDP ports, and 25 for at least six unexpected destination/service pairs. All three together produce 85 and request quarantine. Retransmitted SYNs are not separate attempts. These are explainable lab heuristics, not a trained ML model or proof of malware.
- Pump rule: at least three fresh unexpected connections request restriction. They never automatically request full isolation.
- Outcome: fresh protocol success/failure, server-side receipts, applied-policy audit, and (in GNS3) gateway rule/counter output.
- Risk history: the incident peak is retained until policy reset, even when new normal traffic reduces the rolling-window score. The detection audit records the observed counts at the decision time.

Phishing, credential theft, SMB authentication/exploitation, encryption, and ransomware payloads are NOT implemented. The demonstration represents post-compromise reconnaissance/lateral-movement indicators only. No arbitrary target IP, exploit, malware, patient data, or real medical equipment is used.

## Tests

From this directory, using the isolated environment:

```powershell
$env:IOMT_INTEGRATION='1'
.\.venv\Scripts\python.exe -m unittest test_live -v
```

Stop an existing native session first: integration tests deliberately refuse to take over occupied management ports. The integration test starts real services, captures real packets, checks DICOM/HL7 parsing, observes detection, verifies ACL effects and pump safety, and stops its processes afterward. Unit tests additionally check quiet networks, expected clinical flows, retransmission handling, and scoped gateway rule construction.

To repeat the routed verification against the running local PoC:

```powershell
.\.venv\Scripts\python.exe verify_gns3.py --gns3 http://192.168.209.142
```

Use the VM's current address. This command creates/reuses only the PoC's managed project, generates bounded lab traffic, checks actual gateway DROP counters, saves all measured phases, and ends with normal policy and paused generators. It refuses to take over a different active capture session. The current GNS3 verification passed; rerun it after VM, image, gateway, or capture changes before presenting new results.
