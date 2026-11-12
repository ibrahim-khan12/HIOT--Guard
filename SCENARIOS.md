# Controlled GNS3 scenarios

This Module 1 profile runs alongside the hospital's normal DICOM, HL7 and supporting traffic. Module 2 records the same experiment from its own capture readers. Each scenario has a separate ground truth log with its recording scope, scheduled window, actual agent results and receipts.

## Start the experiment

1. On the GNS3 Linux compute, build the existing hospital base image if it is missing. Copy the source files to the compute and run these commands from that source directory.

   ```sh
   docker build -t iomt-hospital:2 -f Dockerfile .
   docker build -t iomt-hospital:scenarios-v1 -f Dockerfile.scenarios .
   ```

2. Start Module 1 as usual and open [the traffic console](http://127.0.0.1:8877/). Choose **GNS3 controlled scenarios**, enter the private GNS3 address, and click **Connect lab**. The first connection creates a new project and writes `runs/gns3-hospital-scenarios-v1-manifest.json`. Click **Start normal traffic**.
3. Configure the Module 2 sensor for a separate state directory using [the Module 2 setup](MODULE2.md). An existing sensor lock and verified known-host file for the same compute can be reused. Start the server with the scenario manifest.

   ```powershell
   .\.venv\Scripts\python.exe -m module2 --state runs/module2-scenarios-v1 --sensor-host 192.168.209.142 serve --manifest runs/gns3-hospital-scenarios-v1-manifest.json
   ```

4. Open [the monitoring console](http://127.0.0.1:8878/) and click **Start monitoring**. Wait for all 17 readers. Back in Module 1, select a scenario and click **Run scenario**. The scheduled run includes baseline, activity and recovery. **Cancel scenario** stops the experiment while normal hospital traffic continues.
5. Save the log with **Download run log**. The controller also saves it under `runs/<session>/scenarios/<run-id>.json`. Inspect the recording with the scope shown in the run log. Stop Module 2 monitoring before ending the Module 1 session.

The original **GNS3 routed lab** profile still uses the 13 hospital capture links and supports the existing containment verifier. The scenario profile uses observe-only policy and verifies that its new switch has exactly four isolated Docker actors. They have fixed addresses on `10.77.90.0/24`, one interface each and no default route. The hospital workstation and pump use their existing routed segment and synthetic services.

| Scenario | Traffic and evidence |
| --- | --- |
| Workstation reconnaissance | Eight TCP connection attempts to PACS and EHR. The log records ephemeral source ports so the verifier can match each SYN and distinguish connection success from a refused or unanswered attempt. |
| Unexpected pump-to-PACS traffic | Four TCP connections to PACS on 11112. The verifier correlates pump ORU control IDs to EHR ACKs seen during the active window. |
| Single-source UDP burst | One sender transmits a five-second baseline at 1 datagram/s and a five-second burst capped at 25 datagrams/s and 125 datagrams. Each payload is 128 bytes. |
| Two-source UDP burst | The two senders share the same scheduled window and each uses the single-source limits. Check that both sources appear in overlapping one-second buckets. |
| MQTT publish burst | An isolated broker forwards messages on the fixed synthetic topic. Baseline is 1 publish/s. The five-second burst is capped at 10 publishes/s and 50 messages of 128 bytes. Subscriber counts and decoded MQTT PUBLISH frames are evaluated. |
| Conflicting ARP claims | One legitimate reply precedes three conflicting replies. All target the isolated observer. Check the two source MAC claims and compare the observer's permanent neighbor entry before and after. |

## Verify and hand off

```powershell
.\.venv\Scripts\python.exe verify_scenarios.py --state runs/module2-scenarios-v1 --output runs/scenario-acceptance --repeats 3
.\.venv\Scripts\python.exe -m module2.scenario_evidence <run-log.json> --state runs/module2-scenarios-v1 --output <evidence.json>
```

The acceptance runner checks request validation, request idempotency, concurrency and cancellation. It saves an independent Module 1 PCAP check and a Module 2 retained PCAP check for each run, then records clinical path verification. Keep the monitor running until analysis has committed the recording windows. The runner keeps the verified Module 2 revisions in its output folder. For a manual export, `--evidence-folder` preserves those PCAP revisions and `--module1` selects the independent Module 1 capture.

For the scenario profile, Module 2 keeps committed PCAP snapshots after their spool segments rotate. The working storage and archive limits still apply. Use a separate recording state and export the evidence before retiring it.

The evidence report includes capture IDs for Module 2, PCAP hashes, link sources, timestamps and frame numbers. It shows sender, receiver and capture counts separately, with one-second packet buckets for bursts. The normal connection summary remains a flow summary. Keep the scenario log and its synthetic payload tags in the evaluation harness when developing Module 5. Detection rules should use packet and connection behavior.

Module 2 can also export unlabeled, timestamped UDP datagrams, MQTT message metadata and standalone ARP records as JSON Lines. Supply a recording scope, a single observation link and an explicit capture time window. Use `scenario_service` for UDP ingress, `arp_observer` for MQTT delivery or ARP claims, and `burst_a` for the MQTT publisher. Counting one observation link avoids counting the same packet again at a second link.

```powershell
.\.venv\Scripts\python.exe -m module2 --state runs/module2-scenarios-v1 packet-observations --scope <scope> --source scenario_service --begin <unix-seconds> --end <unix-seconds>
```

The UDP and MQTT scenarios test rate changes. The ARP case tests evidence for conflicting claims while the observer retains its legitimate mapping. For containment, use the original routed profile and its verifier to demonstrate workstation quarantine and pump restriction with continued HL7 telemetry. Preserve the original PCAPs for independent analysis and keep captures, runtime manifests, local state and credentials out of version control.
