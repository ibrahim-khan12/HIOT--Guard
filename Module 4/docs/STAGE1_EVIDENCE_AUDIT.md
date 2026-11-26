# Module 4 Stage 1: evidence and feasibility audit

Completed 23 November 2026. Module 4 remains device-category inference; attack detection remains Module 5.

## Decision

**Proceed to a bounded Stage 2 pilot, not to full dataset collection or retraining yet.** The current implementation provides reproducible predictions of ten lab actor roles. Its strongest features describe measurement types and proposed image-storage capabilities. Those features do not uniquely identify the physical sender's category when forwarding applications, gateways, and overlapping device functions are admitted.

The next experiment is feasible as a study of evidence attribution, implementation transfer, and selective classification. A substantial advantage of ML over stronger rules is still unproven. A second software stack alone will not remove the lab's category-to-code shortcuts.

The immediate priorities are namespace-aware observation mapping, actual transaction semantics, repeated messages on persistent connections, and time-correct observation windows. Adding more copies of the current traffic does not address these issues.

This stage changed no parser, classifier, model, threshold, emulator, or inventory behavior. It added this report and a reproducible audit utility. No new network capture, model fitting, or external dataset download was performed. Proposed scenarios below have not been run on a live network.

## Evidence basis and reproducible checks

Repository HEAD at audit: `4005bcdd580b363ba0b5775aea3c1590b1a8a509`. Pre-existing uncommitted work was preserved. The audit JSON pins the actual source-file bytes and six frozen model/selection artifacts, rather than treating HEAD as a description of the entire working tree.

Local evidence:

- [Parser and lab-code allowlist](../../module2/parsing.py): `MEASUREMENT_KINDS`, `hl7_messages`, `normalize`.
- [Module 3 recording export](../../Module%203/module3/store.py): `recording`.
- [Current features and rules](../module4/classifier.py): `endpoint_rows`, `add_initiated_evidence`, `rule`.
- [Lab traffic generator](../module4/lab_actor.py), [forest decision](../module4/experiment.py), and [selected-policy study](../module4/study.py).
- [Historical learning study](../../runs/module4-learning-study-20261116/REPORT.md), [traffic comparison](../../runs/module4-traffic-comparison-20261116/REPORT.md), and [existing medical-public-data audit](MEDICAL_DEVICES_2024.md).
- [Stage 1 machine-readable audit](../../runs/module4-stage1-audit-20261123/audit.json). This local artifact is under ignored `runs/`; the source utility and this report are the portable reproduction materials.

The utility read all three existing split manifests and checked all 780 original PCAPs against their saved SHA-256, record counts, byte counts, and first/last packet timestamps. It validated complete classic-PCAP record structure. These checks do not prove zero network packet loss, full clinical workflows, or the correctness of previously extracted labels. It did not rerun Zeek/TShark or evaluate newly trained models.

| Audited item | Result |
| --- | --- |
| Sessions | 52: 30 training, 10 validation, 12 historical test |
| Labelled endpoint-session rows | 780: 450 training, 150 validation, 180 historical test |
| Medical support | 52 examples per category; 12 per category in historical test |
| Supporting endpoint rows | 260 total; 60 in historical test |
| Original capture files | 780, totalling 11,667,906 bytes |
| Duplicate source/scope or endpoint-instance IDs across manifests | None in this audit; this does not establish independent emitter implementations |
| Heart-pair semantic sets | Equal in all 52 sessions: protocols, measurement kinds, proposed UIDs, candidate categories |
| Actual observed traffic span across each session's captures | Minimum 4.225 s; median 9.032 s; maximum 24.115 s |
| Saved collector elapsed time | Minimum 28.370 s; median 50.837 s; maximum 130.085 s |
| Frozen artifacts and audited production sources | Hashes unchanged before/after audit |
| In-memory diagnostic cases | 13 current-behavior results reproduced |

The heart comparison excludes counts, packet statistics, and timing. It does not claim all feature vectors or packet bytes are identical. The lab source supplies the same heart-rate message construction and sampling policy for both actors.

The observed traffic span is distinct from collector elapsed time. The existing files do not demonstrate sustained 30/60/120-second operation. A longer observation experiment needs a new recorded observation horizon and genuine ongoing or deliberately sparse traffic. Padding the existing traces with assumed silence is not evidence of real idle behavior.

Historical test rules reproduce 90 correct assignments, zero wrong assignments and 90 abstentions: 12 each for ventilator and portable X-ray; 11 each for pump, CT, MRI, ultrasound, lab analyzer and dialysis; zero for both heart-rate categories. All 60 supporting endpoints abstain. These are results against lab labels. The previously reported selected fallback adds one correct pump assignment; this stage did not rerun forest inference or turn the old test into a fresh test.

## Ten-category evidence table

"Candidate additional evidence" means a hypothesis for a later profile, not an implemented feature or proven discriminator. The same evidence may be relayed. Clinical values and image/waveform payloads remain excluded. Physical identity is not required to be cryptographically proven for a probabilistic classification, but claims must be validated against the relevant confounders.

| Category | Current emitted/recognized signal | What the current evidence supports | Confounders and required unknown cases | Candidate additional evidence and feasibility |
| --- | --- | --- | --- | --- |
| Infusion pump | Local `LAB_RATE` becomes `flow_rate`; ORU plus responder ACK on at least two flows | A sender reports the allowlisted rate observation | Pump gateway, HL7 relay, other rate-reporting application; rate alone does not establish a pump endpoint | IHE IPEC-style infusion-event workflow is independently documented [S6]. Its intermediaries must also be represented. Feasible bounded workflow pilot; physical-pump discrimination unproven. |
| CT | A-ASSOCIATE-RQ proposes `1.2.840.10008.5.1.4.1.1.2` | CT Image Storage capability proposed | Workstation, archive or router proposing/sending CT objects; proposal without transfer | Actual C-STORE class/status and, later, acquisition-workflow evidence such as MPPS [S1-S3,S7]. Feasible storage-role pilot; device origin unresolved by storage alone. |
| MRI | Proposal of `1.2.840.10008.5.1.4.1.1.4` | MR Image Storage capability proposed | Forwarding workstation/archive; enhanced-MR-only device outside the current mapping | Record classic versus enhanced storage classes and actual operations [S1-S3]. Include MR-forwarding control; do not equate image class with physical scanner. |
| Ultrasound | Proposal of `1.2.840.10008.5.1.4.1.1.6.1` | Ultrasound Image Storage capability proposed | Workstation/archive; multi-frame/enhanced ultrasound outside the one-UID mapping | Validate additional documented US storage classes and transaction roles [S1-S3]. Multi-frame is an interoperability test, not proof of hardware origin. |
| Portable X-ray | Proposal of `1.2.840.10008.5.1.4.1.1.1.1` | Digital X-Ray Image Storage - For Presentation capability proposed | Fixed X-ray equipment and forwarding software can share this class; portability unobserved | No portable/fixed discriminator was established in this audit. Preserve the ground-truth category; use `unknown` where only generic DX evidence is available in the expanded task. |
| Bedside monitor | `HEART_RATE` becomes `heart_rate`; shares candidates with ECG | Heart-rate observation reporting | ECG, wearable, gateway or relay; shared heart-rate-only profile | Multiparameter reporting is a candidate workflow, not a unique bedside identity. Require an independently specified profile and overlapping ECG/gateway controls before using it as a discriminator. |
| Lab analyzer | `GLUCOSE` becomes `glucose` | Glucose observation reporting | Point-of-care glucometer, laboratory information system, HL7 relay | Specimen/order/result structure and multiple test kinds may support an analyzer-associated workflow [S4,S5]. No manufacturer-specific pattern was verified. Additional parser/profile work would be needed. |
| Ventilator | `RESPIRATORY_RATE` becomes `respiratory_rate` | Respiratory-rate observation reporting | General vital-signs monitor, sensor, or relay | Ventilation settings, mode/state and measurement-kind combinations are candidates requiring a verified device/profile specification. Respiratory rate is a general observation [S9]; rate alone must not establish a ventilator. |
| Dialysis machine | `BLOOD_FLOW` becomes `blood_flow` | Local blood-flow observation reporting | Gateway, relay, other blood-flow-related application | Treatment-state and dialysis-specific metric-kind combinations require a verified specification. IHE DEC includes dialysis systems [S5], but that does not validate this lab's one-code mapping. Exact expanded-task discrimination remains unproven. |
| ECG monitor | `HEART_RATE` becomes `heart_rate`; shares candidates with bedside monitor | Heart-rate observation reporting | Bedside monitor, wearable, relay; identical heart-rate-only profile | ECG acquisition/report or waveform-type metadata could support an ECG-associated workflow without retaining signal values. No such profile is implemented or established here; intermediaries remain confounders. |

The four current DICOM mappings are verified names of storage classes [S1], not a complete catalogue of imaging protocols. Enhanced CT/MR and multi-frame US must be treated as explicit coverage tests, rather than silently assuming that the four allowlisted UIDs cover all implementations.

IHE DEC describes both device and intermediary reporting arrangements [S5]. IPEC explicitly allows pump controllers/intermediaries to originate reports [S6]. Thus, adding a richer workflow may improve inference, but does not by itself resolve the network-sender versus originating-device distinction. The confounders and conservative unknown requirements above are audit conclusions, not claims that a standards document mandates this classifier policy.

## Reproduced implementation limitations

These results come from existing source inspection and in-memory diagnostics. A fixture with a forwarding interpretation is not a captured physical workstation or relay. No fixture enters model training or accuracy denominators.

| ID | Finding and diagnostic result | Consequence for the next stage |
| --- | --- | --- |
| E1 | `MEASUREMENT_KINDS` recognizes six literal local strings, producing five kinds. `8867-4^Heart rate^LN` and `9279-1^Respiratory rate^LN` produce no recognized kind and rule `unknown`. | HAPI interoperability cannot be assessed using only copied lab strings. Validate a small versioned mapping of `(coding system, code)` against authoritative definitions [S8,S9]. Unknown codes remain unrecognized. |
| E2 | The parser ignores OBX-3's coding-system component. `LAB_RATE^Rate^LN` still becomes `flow_rate` and yields `infusion_pump` after two flows. | Legacy lab codes need an explicit legacy interpretation; a mismatched declared namespace must not acquire lab semantics. Do not infer mappings from display text. |
| E3 | Any responder `ACK` message counts; MSA acknowledgement code and message-control correlation are not exported. Both an `AR` response and an unrelated control-ID response still support a pump rule decision. | Distinguish observed response from accepted/matched transaction. MSA-1 describes disposition and MSA-2 associates an acknowledgement with a request [S10]. A rejected request may still reveal a measurement kind, but must not be described as accepted delivery. |
| E4 | `supported[category]` increases once per canonical flow, using a set of kinds. Three ORU/ACK pairs on one connection count as one and return `fewer_than_two_bidirectional_exchanges`. | Define and count distinct matched message transactions, without counting retransmissions or duplicate capture observations. A persistent connection must not inherently have less evidence than equivalent short connections. |
| E5 | For each of the four imaging categories, two proposed-class flows with responder DICOM metadata trigger a category without any C-STORE command/status evidence in the recording. | Keep proposed capability, accepted context, attempted operation and successful response distinct. Association negotiation advertises capabilities [S2]. It is not evidence that an image was transferred. |
| E6 | A rate-reporting relay fixture and a pump fixture with the same exported evidence receive the same pump decision. Image-forwarding confounding follows the same missing-attribution problem. | Include matched positive/forwarder pairs. Where permitted evidence is identical, correct discrimination cannot be demanded. Do not pass ground-truth roles into inference to make the test succeed. |
| E7 | Bedside/ECG semantic sets match in every existing session; the selected policy intentionally abstains. | Keep the matched heart-rate-only case as an ambiguity control. A richer profile is a new experimental condition, not a retroactive fix to the old results. |
| E8 | Module 3 exports whole-flow totals and timestamps for evidence attributed to its first frame. Fragmented messages can have later supporting frames. | For a cutoff, reconstruct only prefix bytes and require completion before using a message. Filtering a finished recording by flow start or first-frame time is insufficient. Future flow totals and later fragments must not leak into early predictions. |
| E9 | Current counters are aggregate flow statistics; the corpus's observed session traffic spans 4.225-24.115 seconds. | Packet IAT/distribution features and longer windows require new extraction and recording work. Collector elapsed time is not a 120-second observation. |

For E3, E4 and E5 the evidence distinction matters even before introducing any new ML algorithm. Treating a parser result marked `confirmed` as full HL7/IHE conformance or successful DICOM storage would overstate the parser's actual checks.

The DICOM standard does not assign a study boundary to association closure or impose one storage operation order [S3]. Consequently, connection duration/count and operation ordering are empirical features to evaluate under varied implementations, not universal device-category rules.

## Revised Stage 2 scenarios

All rows below are planned pilot scenarios, not completed packet tests. Reuse A (existing Python stack) and B (HAPI HL7v2/DCMTK) for independent construction. Fix versions and message/profile definitions before collection. A library's presence is not proof that the generated workflow conforms to an IHE profile.

| Scenario | Construction | Required observable outcome / assertion |
| --- | --- | --- |
| P01 Pump baseline and relay | Two or more local rate transactions; replay the same observation types through a separately labelled relay, with direct-link and relay-only visibility recorded separately | Attribute the observed transmitter correctly. Do not claim a physical pump distinction from identical endpoint evidence. Show both the legacy lab prediction and the unresolved expanded-task case. |
| P02 Standard versus legacy codes | Independently constructed ORU messages with LOINC heart/respiratory codes, legacy local codes, unknown codes, and deliberately mismatched namespaces | Known equivalent kinds normalize consistently after any later mapping fix; unknown/mismatched codes do not become known by display name. Both heart codes remain shared evidence. |
| P03 Persistent connection | The same three distinct ORU/ACK transactions over one versus three TCP connections | Equivalent transaction counts despite connection packaging; byte retransmissions do not create new exchanges. Current implementation's limitation is expected until addressed. |
| P04 Acknowledgement semantics | Matched AA, matched AR/AE, unrelated MSA-2, and no response | Distinct outcomes for response visibility, correlation and acceptance. No successful-delivery claim for rejection or unrelated ACK. |
| P05 CT negotiation and storage | CT context proposed without C-STORE; context refused; actual C-STORE with success/failure responses; equivalent workstation forwarding | Retain negotiation/operation distinctions and identify the network sender; do not label a forwarding workstation as a scanner merely because it stores CT objects. |
| P06 Bedside/ECG matched pair | Identical kinds, packet construction and sampling distributions under separate ground truth | Ambiguous category is `unknown`; keep both categories in metrics. Do not impose a category-specific timing cue. |
| P07 X-ray portability control | Portable-labelled and fixed-labelled DX actors with matched permitted evidence | Both show DX-related evidence; portability remains unresolved. Fixed equipment is a hard negative for the portable category. |
| P08 Other-category overlap | MRI/US forwarding, enhanced/multi-frame storage variants, glucose reporting from an alternate source, respiratory-only monitoring and blood-flow relay | Map only verified observation/storage semantics. Record which extra device profiles remain unspecified; no invented physical-device ground truth from filenames or payload values. |
| P09 Cutoff and fragmentation | Message starts before a cutoff and ends after it; later ACK; connection persists across cutoff; duplicate link captures | No early access to later bytes or final flow totals. A known incomplete item is not a completed observation. Deduplicate captured observations. |
| P10 Observation horizon | At least 120 seconds of recorded observation after the endpoint's first observed packet; scripted active, sparse and idle intervals | Evaluate prefixes at 10/30/60/120 s. Keep capture end times as coverage evidence even if no late packets exist. Report insufficient coverage instead of inventing an idle tail. |
| P11 Visibility loss | Missing direction, absent SYN, capture gaps and encrypted medical transport | Unknown/limited-evidence reasons; no inferred plaintext. Differentiate a fully silent/unseen endpoint from an observed endpoint with unknown category. |

The six primary pilot actors remain pump, CT, bedside monitor, ECG monitor, image-forwarding workstation and HL7 relay. P07/P08 are additional controls/extension specifications; they are not a reason to implement all ten independent profiles before the primary pilot is viable. Order work P01-P06 and P09-P10 first; carry the unresolved all-category cases into the expansion decision.

Physiological values, images, waveform values and real patient identifiers are not required for these checks. Device/message identifiers can support within-capture correlation, using scoped or opaque representations as appropriate, but do not become learned category features or physical-identity guarantees. Profile event codes, field presence and message types are metadata; any future parser addition must document exactly what it retains.

## Unsupported distinctions and expansion gates

Unsupported today:

1. Physical scanner versus an application proposing or forwarding the same modality objects.
2. Portable versus fixed X-ray equipment from the mapped storage class.
3. Bedside versus ECG from the present shared heart-rate profile.
4. Physical pump/analyzer/ventilator/dialysis device versus an intermediary reporting the same single kind.
5. Real clinical hardware, vendor or firmware generalization from the current one-generator-per-role collection.
6. Learned unknown-device recognition established merely by refusing all non-HL7/DICOM endpoints.
7. Sustained or early-time behavior inferred from completed short recordings.

Do not change the ten-category denominator to hide these limits. As a mathematical illustration, abstaining on every bedside, ECG and portable-X-ray example makes the maximum ten-class macro F1 0.70 even if all seven other categories have perfect F1. This is a conditional scoring ceiling, not a measured new result or proof that all future profiles are inseparable. It shows why the existing target and stricter identity interpretation cannot be assumed jointly attainable.

Full collection is not approved by evidence from Stage 1 alone. Before expansion, Stage 2 must produce:

- Packet-backed examples from A and B with documented versions, observation coverage, direct/mediated visibility, label provenance and evidence references.
- A resolution or explicit limitation for E1-E5 and E8-E9 in the chosen pipeline. Preserve the frozen v1 for historical comparisons; do not silently change its feature meaning.
- A revised feature/label specification that separates observed workflow from inferred category and states which claims are lab-scoped. Identical-evidence pairs must remain explicit uncertainty cases.
- Measured collection and processing costs before confirming the provisional 90-session/1,350-row allocation. More messages/windows do not become independent devices.
- A decision on the expanded task's achievable target, documented before any final test is inspected. If physical ten-category discrimination is required but remains unsupported, take that evidence to the supervisor rather than narrowing labels silently.

The appropriate next action is the bounded pilot and its evidence-contract work. A larger model, more protocol lookups, or another consumer-IoT download is not a substitute for these gates. The CCP contribution remains a hypothesis to test against updated rules, including additional correct assignments and additional errors.

## Reproduction and validation

From the repository root, using the project Python environment or the bundled Python runtime:

```powershell
python "Module 4/tools/audit_stage1.py" --output runs/module4-stage1-repro/audit.json
```

The utility requires the existing local study, its original captures, and frozen comparison artifacts. It reads them without invoking Docker, GNS3, network tools, or model deserialization. It refuses to overwrite its output. The JSON includes source/model hashes, capture/recording hashes, per-category summaries, examples with evidence references, and all thirteen diagnostic results. A diagnostic reproduction is not a declaration that the behavior is correct.

The final audit was reproduced into a second fresh output file and compared byte-for-byte. Source/model integrity and original capture hashes were checked again. No broad regression suite was necessary because no production implementation changed; the audit's assertions and deterministic reproduction validate this report's local findings.

## Sources and interpretation

Accessed 23 November 2026. Summaries below are paraphrases. Current DICOM pages identify edition 2026e; pin an edition and the chosen HL7/IHE profiles in the later pilot manifest. HL7 v2+ pages are reference material, not proof that the current v2.5 lab messages conform to a full device integration profile.

- **S1:** [DICOM PS3.4 B.5: Standard SOP Classes](https://dicom.nema.org/medical/dicom/current/output/chtml/part04/sect_B.5.html). Defines the image-storage class names and UIDs; it does not encode portable/fixed equipment in the mapped DX class.
- **S2:** [DICOM PS3.4 B.3: Association Negotiation](https://dicom.nema.org/medical/dicom/current/output/chtml/part04/sect_B.3.html). Supports the distinction between requested capabilities and an observed storage operation.
- **S3:** [DICOM PS3.4 B.4: Conformance](https://dicom.nema.org/medical/dicom/current/output/chtml/part04/sect_B.4.html). Explains limits on interpreting operation order and association boundaries.
- **S4:** [HL7 OBX observation/result reference](https://hl7.eu/refactored/segOBX.html). Observation identifiers describe observations; equipment-origin context has separate fields and is not equivalent to the network sender. Such IDs are not proposed ML inputs.
- **S5:** [IHE Device Enterprise Communication overview](https://wiki.ihe.net/index.php/DEC). Documents device-data reporting, supported device families, and gateway arrangements.
- **S6:** [IHE Infusion Pump Event Communication](https://wiki.ihe.net/index.php/Infusion_Pump_Event_Communication). Supports investigating infusion workflows while retaining intermediary-origin ambiguity.
- **S7:** [DICOM PS3.4 F.7.2: MPPS Operations](https://dicom.nema.org/medical/dicom/current/output/chtml/part04/sect_F.7.2.html). Identifies N-CREATE/N-SET procedure-step operations. These are a future workflow candidate, not present v1 features or a mandatory Stage 2 implementation.
- **S8:** [LOINC 8867-4: Heart rate](https://loinc.org/8867-4). Confirms the standard heart-rate code used in the compatibility diagnostic.
- **S9:** [LOINC 9279-1: Respiratory rate](https://loinc.org/9279-1). Confirms the respiratory-rate observation code; it does not label a ventilator.
- **S10:** [HL7 MSA acknowledgement reference](https://hl7.eu/refactored/segMSA.html). Separates acknowledgement disposition from request correlation.

The category-confounder table, unknown policy, statistical ceiling and expansion gates are project-specific analysis drawn from the source behavior and these references. They are not external endorsements of the classifier or guarantees of FYP/CCP acceptance.
