# Module 4 forwarding experiment

The 26 November repeat completed both stacks with offline dependencies. See [FYP evaluation readiness](FYP_EVALUATION_READINESS.md) for the latest results. The Python-only result and dependency failure below describe the 24 November run.

The experiment tests two observation layouts for the same synthetic transactions. A downstream capture sees the endpoint that talks to the receiver. An upstream capture can add evidence linking that transaction to a sender on the other side of an intermediary. Physical device category requires additional evidence.

Each pair has a direct recording and a forwarded recording. The direct link connects the sender to the receiver. The forwarded path traverses two separately captured links. The HL7 relay reads complete MLLP messages, opens its own downstream TCP connection and carries the receiver's reply back. The DICOM workstation accepts C-STORE, opens a separate association, stores the received dataset and returns the downstream status. The ground-truth sender addresses come from the topology and are only used during scoring. The runner uses the same synthetic intermediary and receiver for both sender stacks.

The analysis uses successfully acknowledged transactions. It matches complete HL7 messages by transient byte digest and DICOM storage commands by transient SOP Instance UID digest and storage class. A match must be unique on both links and respect request and reply order. The report retains timestamps, packet references and observed endpoint addresses. The linkage keys stay in memory during analysis. DICOM linkage identifies the claimed instance in the command and leaves image contents unexamined. [DICOM PS3.7 C-STORE message fields](https://dicom.nema.org/medical/dicom/2023a/output/html/part07.html#table_9.3-1)

## Python results

Two direct/forwarded recording pairs produced six PCAPs. Both direct paths and both forwarded paths carried the expected pump and CT workflows. The downstream viewpoint observed ten successful forwarded transactions across the two trials.

| Capture view | Correct upstream senders | Wrong upstream senders | Unresolved |
| --- | ---: | ---: | ---: |
| Receiver side only | 0 | 0 | 10 |
| Both links | 10 | 0 | 0 |

With both links, all six HL7 observations and four DICOM stores matched the expected upstream sender. The unrelated direct recordings produced zero matches to the forwarded downstream recordings. Two analyses of the same six PCAPs produced byte-identical reports. The broader regressions passed 176 tests, including new cases for missing evidence, timing, and ambiguous repeated identifiers.

The packet and frame references are in `runs/module4-forwarding-pilot/python-report.json`. The capture files and their manifests are in the four Python session directories alongside it. These are short, synchronous development trials on a shared capture clock. Physical categories remain unknown in the attribution output. A transformed HL7 message, rewritten DICOM UID, batched delivery, or asynchronous reply can prevent these matching rules from linking the hops.

## Independent sender status on 24 November

The HAPI/DCMTK sender remains pending for this topology. The disposable actor's APT update timed out while transferring the signed Debian Bookworm package index, including via HTTPS and an alternate Debian mirror. The setup-link diagnostic showed DNS replies, an established TLS connection, and package transfer activity. The blocker occurred before installation and before stack B recordings. The earlier independent-stack pilot used a different topology and does not establish a result for these two forwarding paths.

`saved-command-verification.json` records verification of the final saved GNS3 commands and the last setup outcome. The lab manifest retains the earlier worker hashes associated with the completed Python runs. The worker changes between the Python recordings and the later attempts concern dependency setup.

## Implications for the ten-category evaluation

The bedside and ECG profiles report the same normalized heart-rate observations. The portable and fixed X-ray controls store the same DICOM class. These controls test equality of the observed workflow and transaction counts. They do not establish identical traffic distributions across physical devices. Capturing both sides of a relay still cannot resolve a category difference that the observed workflow does not express.

Preserve the ten medical classes and include intermediaries and fixed X-ray as supporting controls. Add near-device capture where the topology permits it, keep a downstream-only view for comparison, and score source attribution separately from physical category. Require independent ground truth on the physical or emulated actor. Record both observation views under the same session ID so neither can fall into a different split. Exclude this development experiment from all final test cohorts.

The larger study requires independently justified evidence profiles for the unresolved categories. Verify those profiles with matched controls before freezing the split and capture layout. With valid profiles, compare Random Forest and gradient boosting against updated evidence rules on untouched familiar and cross-stack sessions. Report macro F1 across all ten classes and the number of extra correct and wrong assignments made by the model after rules abstain. The experiment here scores transaction attribution, so it provides neither a new ten-class macro F1 nor a basis for promoting a trained classifier.

## Reproduce

The runner creates a separate GNS3 project and uses `iomt-hospital:2`. The independent sender installs a verified offline bundle on the disposable actor. The setup interface stays disabled during installation and capture. Assemble the bundle on a host with Docker, project Python, and Maven Central access. In PowerShell from the repository root:

```powershell
$packages = New-Item -ItemType Directory runs/new-toolchain/packages
$stage = 'apt-get update && apt-get install --download-only -y --no-install-recommends default-jdk-headless dcmtk && cp /var/cache/apt/archives/*.deb /bundle/'
docker run --rm --mount ('type=bind,source=' + $packages.FullName + ',target=/bundle') python:3.12.10-slim-bookworm sh -ec $stage
python 'Module 4/tools/prepare_stack_b_bundle.py' --packages $packages.FullName --output runs/new-toolchain/stack-b.tar
```

The staging APT checks Debian repository signatures and archive hashes. The packaging utility verifies the pinned Maven JAR hashes and records each input and the archive hash. The lab verifies the archive hash before installing the local Debian package files. The saved 26 November archive and its manifest are in `runs/module4-stack-b-20261126/`.

With GNS3 running and TShark available:

```powershell
python 'Module 4/tools/run_forwarding_pilot.py' setup --folder runs/new-forwarding-pilot
python 'Module 4/tools/run_forwarding_pilot.py' record --folder runs/new-forwarding-pilot --offline-bundle runs/new-toolchain/stack-b.tar
python 'Module 4/tools/run_forwarding_pilot.py' controls --folder runs/new-forwarding-pilot
python -m module4.forwarding_study --folder runs/new-forwarding-pilot --output runs/new-forwarding-pilot/report.json
python -m module4.specificity_study --folder runs/new-forwarding-pilot --output runs/new-forwarding-pilot/specificity-report.json
python 'Module 4/tools/run_forwarding_pilot.py' close --folder runs/new-forwarding-pilot
```

Use `--stack A` on both recording and analysis to reproduce only the Python portion. Each `session.json` records capture hashes and send receipts. Keep `manifest.json` local because it contains the workers' management credential.
