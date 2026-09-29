# Full FYP Pipeline: IoMT Discovery, Classification, Threat Detection and Safety-Aware Containment

Prepared: 2026-09-29

This is the proposed end-to-end FYP architecture with containment included. It is not a claim that every module is already implemented or approved by the supervisor. The current live PoC implements a smaller, functional subset. ML classification, learned anomaly detection, vulnerability/recall correlation, and production controls must remain explicitly labeled as planned until built and evaluated.

## 1. Project Purpose

Help a hospital security operator answer four connected questions:

1. Which endpoints are actually communicating on the monitored network?
2. What protocol evidence and trustworthy inventory information describe them?
3. Is an endpoint exhibiting suspicious behavior that threatens IoMT services?
4. Which network response can reduce that threat while preserving approved clinical communication?

The main use case is a compromised hospital workstation attempting unexpected connections to protected services, with a second scenario involving abnormal communication from a safety-critical medical-device emulator. A workstation is a supporting hospital endpoint, not itself an IoMT medical device.

Containment addresses specified network communications. It does not remove malware, decrypt files, reverse damage, or prove that ransomware is present.

## 2. End-to-End Architecture

```text
Authorized hospital-network lab
    |
    +-- IoMT-related traffic: imaging -> PACS; pump -> EHR
    +-- Supporting traffic: workstation -> EHR
    |
    v
Passive packet capture + timestamping + flow extraction
    |
    +----------------------------+--------------------------------+
    |                            |                                |
    v                            v                                v
Observed asset discovery     Protocol/metadata parsing        Behavioral monitoring
    |                        DICOM / HL7 / HTTP              Known AND unknown assets
    v                            |                                |
Authorized registry match <------+                                |
    |                                                             |
    v                                                             |
Evidence-based asset profile                                      |
    |                                                             |
    +-- Observed protocol                                         |
    +-- Registry-confirmed role / safety policy                    |
    +-- Inferred category OR unknown [planned classifier]          |
    |                                                             |
    +-- Verified identity available?                               |
    |      +-- CVE/CVSS correlation [planned, if retained]          |
    |      +-- Separate recall/advisory context [planned]           |
    |                                                             |
    +-----------------------------+-------------------------------+
                                  |
                                  v
                     Evidence correlation + risk decision
                                  |
                                  v
                     Safety-aware response-policy gate
                                  |
         +------------------------+-------------------------+
         |                        |                         |
         v                        v                         v
    Log / alert          Noncritical endpoint       Safety-critical / unknown
                         Scoped quarantine         Approved-path restriction
                                                   Review before full isolation
         |                        |                         |
         +------------------------+-------------------------+
                                  |
                                  v
                 Firewall / segmentation enforcement point
                                  |
                                  v
            Verify blocked paths AND preserved clinical paths
                                  |
                                  v
                  Audit trail + incident report + evidence
                                  |
                                  v
              Operator investigation + approved policy rollback
                                  |
                                  +--> Continuous monitoring
```

This is a continuous loop, not a one-time scan. The behavioral branch starts as soon as traffic is observed; it must not wait for ML classification or an external vulnerability lookup.

## 3. Pipeline Stages

### Stage 0: Define Scope, Policy and Authorization

Configure the authorized lab networks, monitored links, asset registry, expected communication paths, and supported enforcement points. Record which assets are safety-critical and which clinical paths must be preserved. An uncertain device category must not automatically be treated as noncritical.

Define what "quarantine" covers: cross-zone flows, same-subnet flows, external routes, and any management exceptions. The claim must match the enforced and tested paths.

The existing PoC has a coverage limitation: the pump and modality share one subnet/switch. Their direct communication can bypass the routed gateway. That path needs segmentation or another enforcement mechanism before claiming complete isolation. Until then, describe the implemented response as routed/inter-zone containment.

Output: an authorized scope, communication allowlist, safety policy, and containment-boundary diagram.

### Stage 1: Capture Actual Traffic

Observe packets from GNS3 link captures in the PoC. In a future authorized deployment, an appropriate mirror/TAP or monitored gateway interface would supply the observation feed.

Capture does not generate an attack or a discovered inventory. The PoC's independent nodes generate normal traffic and bounded suspicious connection attempts; the monitoring tool observes the resulting packets.

Separate observation from enforcement: monitoring can be passive, while changing a firewall rule is an active response.

Output: capture source, timestamps, packet/flow records, and capture-health status.

### Stage 2: Normalize Packets and Discover Assets

Parse source/destination addresses, ports, TCP flags, payload lengths, and timestamps. Track last-seen activity and reject malformed records. Deduplicate retransmitted connection attempts.

Create an observed asset only when its address appears in captured traffic. A configured registry entry is not proof that its endpoint was observed. Silent endpoints can remain undiscovered through passive monitoring.

The current implementation uses IPv4 TCP traffic. Broader discovery coverage must be added and tested if included in the final scope.

Output: an observed inventory and time-windowed connection/flow records.

### Stage 3: Correlate With the Authorized Registry

Match observed assets against administrator-maintained inventory information. Keep the provenance of each field explicit:

| Field | Meaning |
| --- | --- |
| Observed address | Appeared in an actual packet |
| Observed protocol | Supported by parsed protocol evidence |
| Registry role | Supplied by the authorized asset inventory |
| Inferred category | Estimated by a separately evaluated classifier |
| Safety criticality | Authorized policy information, not guessed from a port |
| Unknown | Insufficient evidence; not automatically malicious |

Current role matching is configured by IP address. It is not authenticated device identity and does not demonstrate resistance to IP spoofing.

Output: an enriched asset profile with known, unregistered, and unresolved states.

### Stage 4: Parse Medical Protocol Evidence

For DICOM, extract association evidence such as calling/called AE titles and negotiated abstract syntax. The current PoC sends DICOM C-ECHO; this tests a protocol exchange, not image transfer or exact modality identification.

For HL7/MLLP, identify framing and selected MSH metadata such as sender and message type. The current pump sends synthetic telemetry; HL7 alone does not establish that an endpoint is a physical infusion pump. Sender labels and AE titles can also be user-controlled.

Keep clinical payload values out of the analytical inventory. The current simple HL7 payload parsing has not established comprehensive handling of all fragmented or malformed messages; robust stream parsing is a further implementation/evaluation task.

Additional protocols, including BACnet, should be included only if explicitly retained in the revised scope. Building-automation endpoints are supporting infrastructure, not automatically medical devices.

Output: parsed protocol evidence, parser status, and cautious protocol classifications such as "DICOM-speaking endpoint" or "HL7 sender; device category unresolved."

### Stage 5: Classify Unresolved Device Categories

For the basic PoC, show observed protocols, registry roles, and an unregistered/unknown endpoint without fabricating a device category.

For the full FYP, if ML classification remains an approved objective, add a separately evaluated flow-feature classifier. The earlier proposed Random Forest is a candidate, not an implemented module. Features could include packet-size statistics, inter-arrival statistics, communication patterns, and protocol/flow characteristics.

Offline work must precede live inference:

```text
Labeled captures -> flow features -> device/session-separated train/test sets
                 -> training -> evaluation -> calibrated acceptance policy
                 -> versioned classifier -> live inference
```

Verify that the dataset contains the intended device-category ground truth. Attack labels alone are not device-category labels. Avoid leaking configured IPs, emulator names, or ground-truth role labels into training features. Emulator results do not establish accuracy on physical hospital devices.

Keep low-confidence or unsupported categories as unknown. A predicted category must not invent manufacturer, model, firmware, or clinical criticality.

Output: category estimate, evidence source, model version, evaluated confidence where available, or unknown.

### Stage 6: Add Identity-Dependent Context Separately

If retained in the full scope, perform CVE correlation only when sufficiently trustworthy product/component/version information is available. A broad label such as "pump" or "DICOM endpoint" is not enough to assert a device-specific vulnerability. Report candidates and matching uncertainty rather than claiming confirmed exploitability. The [NVD vulnerability interface](https://nvd.nist.gov/developers/vulnerabilities) is a reference for the planned data integration.

Keep recall/advisory information in a separate branch from CVEs and behavioral detections. A recall is not evidence of a live cyberattack. The [openFDA device-recall documentation](https://open.fda.gov/apis/device/recall/) describes the data and warns against using it for medical-care decisions; it must not automatically trigger clinical disconnection.

Unknown identity, an unavailable API, or stale data must produce an explicit unavailable/uncertain status, not a clean bill of health. External lookups must not block local detection or containment.

Output: dated vulnerability candidates and separate recall/advisory context, including provenance and uncertainty. These integrations are not implemented in the current live PoC.

### Stage 7: Detect Suspicious Behavior

Monitor both known and unknown assets. Compare actual communication with approved paths and time-windowed indicators such as unexpected destinations, unusual service spread, administrative-service probes, and repeated abnormal clinical-device connections.

Current PoC rules:

- Workstation: 30 points for at least two unexpected protected destinations, 30 for SMB/RDP-port attempts, and 25 for at least six unexpected destination/service pairs within 60 seconds. A score of 85 requests quarantine.
- Pump: at least three fresh unexpected connections request restricted communication, not automatic full isolation.
- Retransmitted SYNs are not fresh attempts. Reset retains retry identities to avoid treating old retries as a new incident.

These are transparent heuristics, not a trained ransomware detector. Connections to ports 445 or 3389 do not prove SMB/RDP exploitation, authentication, or successful lateral movement. Legitimate maintenance can resemble these patterns and must be evaluated.

If a learned anomaly model remains in the full scope, build and test it separately against suitable normal and abnormal data. The earlier proposed Isolation Forest is not currently implemented.

Output: observed indicators, rule/model provenance, timestamps, and uncertainty.

### Stage 8: Correlate Evidence and Decide Risk

Combine observed behavior with asset context, detection confidence, and trustworthy vulnerability context where available. Keep clinical safety impact separate from attack likelihood: safety criticality should influence how a response is selected, not imply that an attack occurred.

Record the exact evidence and score components behind a decision. CVSS severity alone is not a live ransomware probability. A missing identity or unavailable external feed must not suppress strong local behavioral evidence.

Keep threshold calibration and false-positive evaluation explicit. The current score of 85 is a lab rule, not an experimentally established universal threshold.

Output: an explainable incident/risk decision and a proposed response.

### Stage 9: Apply the Safety-Aware Response Gate

| Situation | Proposed response |
| --- | --- |
| Expected behavior | Log and continue monitoring |
| Inconclusive or moderate concern | Alert and investigate; do not claim containment |
| High-confidence suspicious behavior from an authorized noncritical endpoint | Scoped quarantine according to the approved policy |
| Suspicious behavior from a known safety-critical device | Restrict unauthorized paths while preserving reviewed clinical communication |
| Device role/safety uncertain | Escalate for review; do not assume clinical isolation is safe |
| Full isolation of a safety-critical device | Require the designated authenticated authorization and record its rationale |

This is a proposed operational policy, not advice for disconnecting real medical equipment. Clinical allowlists and approvals require the relevant clinical/biomedical and security authorities.

The current PoC has a lab reviewer-name entry. It records an approval interaction but does not authenticate a clinician or establish production authorization.

The response component follows the broad detect/respond/recover framing in [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final). [CISA's ransomware guide](https://www.cisa.gov/stopransomware/ransomware-guide) also addresses isolation of impacted systems and critical-service dependencies; this does not establish that the lab policy is clinically validated.

Output: a permitted response, an approval request, or a decision to defer action with a stated reason.

### Stage 10: Enforce and Confirm the Policy

Send the permitted action to the supported enforcement point. In the current GNS3 PoC this is the disposable Linux gateway's scoped `IOMT_LAB` firewall chain. Native Windows mode instead uses lab-service ACLs and must not be described as a routed firewall.

Record requested policy, applied policy, rule acknowledgement, scope, and any error. Do not display "contained" simply because the tool requested a rule. Same-subnet, alternate-interface, and other bypass paths must be covered or explicitly excluded.

Production-oriented controls such as authenticated management, least privilege, operator roles, failure handling, and rollback safeguards remain further work.

Output: applied-policy evidence or an honest enforcement-failed status.

### Stage 11: Verify Security and Service Outcomes

In the isolated lab, issue fresh synthetic application checks after enforcement:

- Is the prohibited workstation/service connection actually blocked?
- Do gateway DROP counters increase for the tested source/path?
- Does permitted pump HL7 telemetry still receive an acknowledgement under restriction?
- Does modality DICOM C-ECHO still succeed?
- Does the isolated pump fail on all paths claimed to be isolated?
- Does an authorized lab reset restore intended communication?

Rule presence alone is not proof of successful blocking. The current verification exercises routed service paths, not every possible medical-network path. Do not reuse these lab probes on patient-connected devices without separate authorization and validation.

Output: security outcome, preserved-service outcome, measured timings, and any unverified boundary.

### Stage 12: Report, Investigate and Restore Approved Access

Produce a report containing scope, asset/protocol provenance, incident timeline, observed indicators, score explanation, requested/applied policy, approval record, firewall evidence, service-check outcomes, limitations, and capture references.

The current PoC exports JSON and saves session PCAP/report files. Readable HTML/PDF incident reports are a planned presentation improvement, not currently implemented. Export before policy reset to preserve the incident snapshot.

The lab reset restores normal policy and verifies connectivity. In a future operational workflow, release from containment must follow authorized investigation and remediation. Network access restoration does not prove that an endpoint is malware-free; eradication, backup restoration, and decryption are outside this PoC.

Output: an auditable incident record and an approved policy-restoration record, followed by continued monitoring.

## 4. Threat Model Summary

| Element | Defined scope |
| --- | --- |
| Adversary | An attacker already controlling a supporting workstation; a separate scenario assumes compromise/abnormal behavior of a registered pump emulator |
| Possible initial entry | Phishing, stolen credentials, or another workstation compromise; assumed, not performed by this PoC |
| Demonstrated capability | Bounded TCP connection attempts to configured lab destinations/services |
| Protected assets | IoMT-related service availability, imaging/PACS communication, pump/EHR telemetry, and network policy/evidence |
| Demonstrated vectors | Unexpected discovery/service probing and lateral-movement-related network indicators, not completed exploits or ransomware encryption |
| Trust assumptions | The controller/gateway is not compromised; lab addressing and registry are controlled; capture is available; protected paths traverse the claimed enforcement point |
| Important exclusions | Real malware, credential theft, SMB/RDP exploits, encryption, physical device control, and real hospital deployment |

State that containment cannot guarantee recovery from local encryption or pre-existing damage. The justification for ransomware is limiting relevant propagation-related communications and protecting service availability, not claiming these indicators are unique to ransomware.

## 5. Evaluation Pipeline

Keep functional PoC validation separate from model accuracy and real-world generalization.

| Evaluation area | Evidence to measure |
| --- | --- |
| Discovery | Expected communicating endpoints versus actually observed endpoints; time to first observation |
| Protocol parsing | Correct DICOM/HL7 evidence, unknown traffic, malformed/fragmented input, and port-only negative tests |
| Category classification, if implemented | Per-class precision/recall/F1, confusion matrix, unknown handling, and device/session-separated evaluation |
| Behavioral detection | Detection rate and false positives for labeled injected indicators, including benign maintenance and slower probes |
| Response | Time from relevant captured indicator to applied rule, then time to measured blocking |
| Containment coverage | Routed, same-subnet, and alternative paths within the claimed boundary |
| Clinical-path preservation | Fresh synthetic HL7/DICOM outcomes before/after each policy transition |
| Reliability | Capture interruption, quiet-network behavior, command retries, reset, and reconnect |

Repeat scenarios and report run count, measured distribution/range, failures, and resource conditions. Do not call successful emulator scenarios "ransomware detection accuracy." Do not present a desired acceptance target as an already measured result.

Saved tests on 2026-09-28 included 23 regression/native integration tests and six routed GNS3 verification phases. These establish controlled functionality, not broad classifier accuracy, complete isolation coverage, or real-hospital safety.

## 6. Data, Legal and Safety Boundaries

The current lab uses synthetic data and owned/authorized emulators. Passive monitoring does not automatically make packet storage privacy-free: a full PCAP can contain payloads. In any future real-data study, obtain the required approvals and define data minimization, access, encryption, retention, and deletion controls before capture.

Determine the actual jurisdiction, institution, data handling, and intended deployment before claiming regulatory applicability. US HIPAA applies to defined covered entities and business associates, as described by [HHS](https://www.hhs.gov/hipaa/for-professionals/covered-entities/index.html). It is not a universal label for every student healthcare project.

[FDA's February 2026 cybersecurity guidance](https://www.fda.gov/regulatory-information/search-fda-guidance-documents/cybersecurity-medical-devices-quality-management-system-considerations-and-content-premarket) addresses device cybersecurity design and premarket-submission content. A monitoring/reporting prototype must not claim FDA certification or compliance merely because it references that guidance or queries recall data.

Reports may explain relevant security/safety controls and evidence. They must not pronounce a hospital, device, or project compliant from a network observation.

## 7. Implementation Status and Friday's PoC Boundary

| Module | Current live PoC | Full-FYP work, if retained |
| --- | --- | --- |
| Actual traffic and capture | Implemented for isolated GNS3/native labs | Broader authorized capture coverage and reliability evaluation |
| Observed discovery | Implemented for captured IPv4 TCP endpoints | Coverage evaluation and additional traffic types as scoped |
| Registry correlation | Configured IP-based roles/criticality | Stronger inventory correlation, provenance and identity handling |
| Medical protocol evidence | Actual DICOM and synthetic HL7/MLLP evidence | Broader message/reassembly validation and scoped protocols |
| Device-category classification | Protocol labels plus registry roles; not trained ML | Functional unknown-device demo, then evaluated classifier if required |
| Vulnerability/recall context | Not implemented | Identity-qualified, separately sourced integrations if approved |
| Threat detection | Explainable connection-based rules | False-positive/missed-case evaluation; learned model if required |
| Risk scoring | Implemented lab heuristics | Calibration and context/confidence evaluation |
| Safety-aware containment | Routed gateway rules; telemetry-preserving restriction | Close same-subnet bypass and validate the claimed full boundary |
| Approval | Lab reviewer-name record | Authenticated authorization and operational safety workflow |
| Outcome verification | Fresh synthetic checks and actual firewall evidence | Repeated timing and coverage measurements |
| Reporting | JSON export, saved session report/PCAP | Readable report and stronger evidence/retention controls |
| Recovery | Lab policy reset and connectivity checks | Authorized release workflow; malware eradication remains external |

For Friday, demonstrate the implemented observation -> evidence -> decision -> containment -> verification -> report loop. Prioritize containment coverage, honest classification/unknown handling, and a small measured evaluation table. Present other full-FYP modules as planned, not as secretly completed by the dashboard.

## 8. Suggested Project Description

The project develops an IoMT-focused security monitoring and safety-aware network-containment system. It passively discovers communicating endpoints, extracts medical-protocol and flow evidence, correlates assets with an authorized registry, and supports evidence-based device classification. It analyzes suspicious communication patterns, produces explainable risk decisions, and applies approved network restrictions or quarantine while accounting for clinical communication requirements. Containment is verified using measured network and service outcomes, and the system produces an auditable incident report. The current proof of concept demonstrates this loop in an isolated GNS3 emulator network; learned classification, external risk enrichment, and broader deployment controls are separately identified implementation tasks.
