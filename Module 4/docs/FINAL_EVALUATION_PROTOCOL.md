# Module 4 final GNS3 evaluation protocol

The unit of prediction is a labelled endpoint within a synthetic GNS3 session. The ten labels describe the configured emulator profiles. The study tests whether evidence can recover those roles under the specified conditions and when the classifier should abstain. Physical device and vendor generalization would require separately sourced and labelled recordings.

## Collection and split

| Dataset use | Sender | Logical sessions | Capture batches |
| --- | --- | ---: | ---: |
| Model fitting | Python | 40 | 4 |
| Probability calibration | Python | 10 | 1 |
| Threshold and policy selection | Python | 10 | 1 |
| Familiar test | Python | 10 | 1 |
| Transfer test | HAPI HL7v2 and DCMTK | 20 | 2 |

Each session has ten medical endpoints and five supporting endpoints. Every session, endpoint instance, capture batch and observation-window derivative belongs to one split. Each batch may contain up to ten sessions on disjoint address segments with separate traffic schedules. Shared containers and captures create dependence within a batch. Report both logical session counts and capture batch counts. Keep the transfer cohort untouched during fitting, calibration and threshold selection. The historical 52-session study and earlier forwarding and waveform controls are development evidence.

Use isolated sender, intermediary and receiver links. The two observation points support transaction attribution when the same exchange appears on both sides. Validate the observed sender from packets and keep the configured node labels in the ground-truth manifest. The Python and HAPI/DCMTK senders use different libraries. Both cohorts still use scripted medical roles, a shared GNS3 environment and common intermediary and receiver implementations.

For each labelled endpoint, form features from packet prefixes of 10, 30, 60 and 120 seconds measured from that endpoint's first observation. Require recorded coverage at each window. A message or response provides a completed-transaction feature only when the necessary packets are already visible. Keep capture hashes and frame references so the evidence can be checked. Include persistent and repeated connections, variation across session schedules, matched workflow confounders and supporting endpoints.

## Device evidence and ambiguity

| Label or control | Permitted evidence and interpretation |
| --- | --- |
| Infusion pump | Accepted flow-rate reporting supports the configured pump workflow. A matching onward relay exchange is evidence for intermediation. |
| CT, MRI and ultrasound | A successful C-STORE for the corresponding storage class supports the observed image-storage workflow. The association proposal alone supplies a capability clue. A matched forwarding transaction is a competing explanation. |
| Portable X-ray and fixed X-ray | Both can store digital X-ray images and use the tested acquisition sequence. Portability remains unresolved from those signals. |
| Bedside monitor and ECG monitor | Heart-rate observations and the matched waveform control are shared. These require `unknown` when no further distinguishing evidence is available. |
| Lab analyzer, ventilator and dialysis machine | Accepted glucose, respiratory-rate or blood-flow reporting supports the corresponding configured Lab workflow. Those observations can also be reported by other systems. Claims apply to the tested profiles. |
| Supporting endpoints | Include relay and workstation forwarding as hard controls, along with fixed X-ray and generic supporting services. Count a medical assignment to a supporting endpoint as an error. |

The evidence table guides the rule contract. Features may describe acknowledged transactions, protocol semantics, captured forwarding paths, packet timing and size, and coverage or quality. Addresses, host identifiers, labels, session IDs, raw UID or message identifiers, registry names and payload values stay outside the feature vector. Synthetic timing and display names should never be chosen to encode the answer. Keep the ambiguity cases in every evaluation denominator. [Stage 1 evidence audit](STAGE1_EVIDENCE_AUDIT.md), [forwarding and specificity results](FYP_EVALUATION_READINESS.md)

## Model and metrics

Compare the updated evidence rule, Random Forest, histogram gradient boosting and rules with an ML fallback on the same eligible endpoints. Use capture groups for cross-validation during fitting. Fit calibration on its own split and retain it only when validation supports it. Freeze the extractor, feature contract, model, probability treatment, abstention threshold and input file hashes before scoring either test cohort. Include an explicit reason when an older model lacks the fields or recording format required to make a compatible prediction.

Report familiar and transfer results separately. Use macro F1 across all ten medical classes with `unknown` contributing to missed recall. Report confusion matrices, per-class support, coverage, and the counts of correct, incorrect and unresolved assignments. Report the rates of false medical assignments on supporting endpoints and how many extra correct and incorrect decisions ML makes after rules abstain. The target is macro F1 at least 0.70. The fallback contribution is an empirical result, and a zero or negative gain is a valid outcome. Preserve safety reasons and unknown decisions where the tested semantics are shared.

The small number of independent capture batches limits uncertainty estimates. Report the actual batches and within-cohort results. Separate descriptive variation across logical sessions from claims about independent implementations or deployments. Evaluate the 120-second window as primary and show shorter-window results as a secondary comparison. Record fitting, extraction and collection costs as separate measurements.
