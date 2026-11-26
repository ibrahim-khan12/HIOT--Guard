# Module 4 independent-stack pilot and continuation status

24 November 2026. Attack detection remains Module 5.

## Decision

**The pilot exposes a real classification failure, but does not establish a better ten-category classifier.** Both implementations produce usable packet evidence. The existing rules and selected Random Forest fallback label the forwarding workstation as CT and the HL7 reporting intermediary as an infusion pump. The new conservative policy preserves the observed workflows but abstains on physical device category, including the actual medical actors.

The 90-session experiment remains provisional. No new forest or gradient boosting classifier was trained, no calibration or threshold was selected, and no fresh final test was scored in this continuation. Adding more repetitions of these profiles would not supply the missing evidence that distinguishes physical origin. The existing frozen model remains available and unchanged; the new policy is an optional development assessment, not its replacement.

This is a bounded feasibility result for the CCP evidence package, not proof that the complete CCP or final FYP evaluation is sufficient. In particular, zero wrong assignments from an all-unknown policy does not establish useful classification accuracy.

## What was run

Two fresh GNS3 development recordings were collected in an isolated project. Each contains six endpoint profiles—pump, CT, bedside monitor, ECG monitor, image-forwarding workstation and HL7 intermediary—plus the receiving service. They use six IP aliases in one actor container and a separate receiver container. These are **14 endpoint-session observations across two sessions**, not 14 independent devices. The four observation windows are correlated derivatives, not extra training samples.

| Property | Stack A | Stack B |
|---|---:|---:|
| Capture wall time | 131.27 s | 131.32 s |
| PCAP size | 46,926 bytes | 38,511 bytes |
| Labelled IPv4 endpoint profiles | 7 | 7 |
| Endpoints with packet-backed 120 s coverage | 7 | 7 |
| v2 extraction, all four windows | 1.55 s | 0.81 s |
| Module 2 import/replay | 1.70 s | 1.66 s |
| Peak traced Python allocation during v2 extraction | 704,850 bytes | 562,818 bytes |

Memory figures are `tracemalloc` Python allocations, not total process RSS, TShark/Zeek memory, or VM memory. Times are one measured development run, not benchmark distributions. Capture duration includes explicit sparse/idle intervals and late traffic; the model did not train during these timings. Observation coverage uses the last observed IP packet, avoiding an assumed silent tail or reliance on host/VM clock agreement.

The normal inventory for A also retains two link-local IPv6 addresses and one IPv6 multicast group; B contains only the seven labelled addresses. A's background addresses are outside the seven labelled IPv4 profiles and are not included in the diagnostic assignment counts. The v2 pilot extractor currently handles IPv4 only.

A uses the existing Python/pynetdicom image and a separate bounded pilot sender. B uses HAPI 2.5.1 typed `ORU_R01`/OBX construction and Java socket sending, plus the native DCMTK 3.6.7 `dump2dcm` and `storescu` executables. HAPI JAR SHA-256 values, Java version and DCMTK version are saved with each capture. B's proposal-only control deliberately uses Python and is identified as such. Both stacks use the same Python acknowledgement/storage receiver and scheduler.

DCMTK's nonzero exits for refused storage and rejected presentation contexts are expected negative controls; they are retained as failed-send receipts rather than misrepresented as successful operations. The B dataset is a minimal synthetic CT object for protocol testing, not a clinical CT IOD conformance example. No patient data was used.

The VM's actual NAT subnet was discovered for dependency setup. The actor's setup network interface was disabled before capture. The management plane is token-protected; only the direct lab link was captured. The local pilot manifest contains that token and stays in ignored `runs/`, outside the source changes.

Final provenance review found that `refresh` had not persisted its updated worker-source hash. The runner now saves that hash and checks each node's command before a future capture. Original pilot manifests are preserved with a separate `runtime-provenance-correction.json`. After briefly restarting the stopped VM, both saved GNS3 node commands were independently inspected and matched the preserved worker source SHA-256 `7277b1cb4fc028f33bb183b4068798616052cd16f8411a9786237f9f217765c7`. The successful follow-up is `runtime-provenance-verified.json`; use it alongside the original manifests, whose worker hash remains stale. No new capture or worker refresh occurred during this check. PCAP hashes, package versions and send receipts are verified separately.

## Packet-backed findings

The separate `module4.evidence_v2` extractor leaves the historical Module 2/3 recording format and v1 classifier semantics intact. It adds:

- Namespace-aware local-code mapping (`99HIOT`) and the documented LOINC heart/respiratory codes. `LAB_RATE` incorrectly marked `LN` is unmapped.
- Actual MLLP message counting on persistent connections, and ACK correlation using MSA-2 with distinct AA/AR/AE dispositions.
- DICOM association proposals and acceptance results separately from C-STORE requests and correlated success/non-success responses.
- Directional packet-length and inter-arrival summaries, idle intervals, connection counts and capture-quality indicators.
- TCP sequence reassembly with retransmission suppression and fail-closed handling of conflicting overlap, gaps and missing SYN evidence.
- Per-endpoint 10/30/60/120 s packet prefixes, completed-evidence frame references, protocol/workflow, version, reason and a null model score for rules.

For the Python pump profile, the 120 s prefix contains 16 ORUs: 7 with matched AA, 3 with AR, 3 with AE, and 3 without a matching ACK. The seven AA outcomes include the deliberately unmapped-code messages; an accepted message is not automatically category evidence. The CT profile shows two successful stores and one failed store. The workstation shows the same CT storage workflow. The pump and intermediary both show flow-rate reporting; bedside and ECG both show heart-rate reporting.

Whole-recording profiles have different numbers of diagnostic exchanges. They are not rigorously matched traffic-distribution experiments, and those differences must not become invented category cues. The intermediaries emulate the same outward reporting/storage behavior; an actual two-hop relay or forwarding pipeline has not been built.

The new parser is bounded development code, not a complete HL7/DICOM implementation. Unmapped namespaces, other character sets, IPv6, broader storage variants, all ten independent profiles, transport encryption and extensive malformed-input behavior still require work before a production feature contract is frozen.

## Frozen baseline comparison

Full-capture frozen-v1 predictions were reproduced through the normal Module 2 normalization and Module 3 recording export, using Zeek 8.0.10 and TShark 4.6.3. The new assessment uses the 120 s prefix. Consequently this is a **diagnostic comparison with different evidence horizons**, not a fair final model ranking at matched windows.

Counts below are identical in A and B:

| Method, per seven-endpoint session | Correct category assignments | Wrong category assignments | Unknown | Supporting endpoints assigned a medical category |
|---|---:|---:|---:|---:|
| Frozen rules | 2 | 2 | 3 | 2 of 3 |
| Frozen selected Random Forest fallback | 2 | 2 | 3 | 2 of 3 |
| Conservative workflow policy | 0 | 0 | 7 | 0 of 3 |

The four medical profiles are pump, CT, bedside and ECG; six medical categories are absent. No ten-category macro F1, confidence interval, calibration improvement or transfer accuracy is claimed from these two development sessions. All medical abstentions would reduce recall in a final evaluation. Assigned-category precision is undefined when there are no assignments. The selected fallback adds no correct or wrong decisions over rules in this pilot.

The existing model SHA-256 remains:
`4a2dc7247902510ad96aa5579f34b537ade9d9ecfb6849fa24f09d13b68db893`.

## Validation and inventory integration

The final full regression run passed **174 Module 2/3/4 tests in 35.01 seconds**. Real packet replay had revealed TShark's `True`/`False` flag rendering; the adapter now accepts both that format and `1`/`0`, with a dedicated regression. The focused evidence/inventory suite also passed all 16 tests after that correction.

All **56** endpoint/window combinations were also checked by independently cutting the actual PCAP bytes and re-running TShark. Their features, semantic events, completion times and decisions match prefix analysis of the complete capture. Identifier renaming leaves features and decisions unchanged. Frame numbers are excluded from this comparison because a cut file can renumber them; original captures retain the reviewable references. This verifies finite prefix equivalence, not a continuously running live scheduler.

Module 3 can now attach an optional classification projection to the endpoint view. It shows `unknown`, observed workflow, reason, observation duration, method/version and packet references. It never edits registry facts. Source, scope, inventory revision/digest and capture hash must match; stale or mismatched results are hidden. Only the reviewed conservative projection is currently accepted. Continuous refresh and a supported physical-category live demonstration are not implemented.

All **seven browser checks passed**, with no runtime errors. Desktop and mobile screenshots were visually inspected and are stored under the evaluation's `browser/` directory, alongside `browser-checks.json`. The check starts and stops its own loopback demo server.

The repeated historical audit is byte-for-byte identical to the Stage 1 audit, confirming preservation of its 52 sessions, 780 captures, source files and six protected model/selection artifacts. `verification.json` records the final checks. The previously stopped VM was briefly restarted for the saved-command check, and only the owned pilot project was opened and then closed. The VM was then gracefully stopped, restoring its prior state.

## Public-data decision

A fresh bounded audit downloaded the 16,213,153-byte author-hosted **IoT Healthcare Security Dataset** archive, pinned at commit `feb6f9050d42b9bd4f473cacb40121a68469dd5e`. It contains three processed CSVs: environment monitoring, patient monitoring and attacks. Their headers include MQTT fields, identifiers and payload fields; the archive contains no raw PCAPs. No rows were merged or fitted. The author's paper describes IoT-Flock simulated MQTT/CoAP traffic; this does not establish compatible physical-device labels or packet-prefix provenance for the present HL7/DICOM experiment. It remains a Module 5 or separately scoped MQTT-study candidate. [Author repository](https://github.com/imfaisalmalik/IoT-Healthcare-Security-Dataset), [author paper](https://www.mdpi.com/1424-8220/21/9/3025).

Existing CICIoMT2024, Kardia and Sentinel findings remain in their earlier reports. The reviewed CICIoMT Active capture does not establish the needed pump publisher, Kardia samples expose app/VPN traffic rather than verified physical ECG endpoints, and Sentinel is an already-inspected rejection regression. No new medical training examples were admitted. UNSW remains optional; CIC IoT-DIAD remains deferred to Module 5/separate scope. This audit stayed within the two-day cap.

## Status of the approved seven stages

| Stage | Actual status after this run |
|---|---|
| 1. Evidence audit | Complete in the previous stage; artifacts preserved. |
| 2. Independent-stack pilot | Core six-profile pilot, transaction evidence and costs completed. Full scenario matrix, repeated sessions and actual two-hop forwarding remain incomplete. Expansion gate not passed. |
| 3. New 90-session dataset | Not collected. Allocation/split specification remains provisional; no final-test data was created or inspected. |
| 4. Features and model comparison | Packet/transaction features and diagnostic frozen-baseline comparison implemented. New RF/HGB fitting, grouped CV, calibration, ablations and fallback selection not performed. |
| 5. Public-data audit | Bounded candidate audit complete; no compatible medical examples admitted. |
| 6. Final evaluation | Development robustness checks complete as described. Fresh holdout metrics, grouped intervals, matched-window comparisons and leave-one-category-out evaluation not performed. |
| 7. Integration/demo/package | Optional read-only workflow projection and reproducible pilot package implemented. Full live refresh and supported physical-category demonstration remain incomplete. |

The remaining stages have not been relabeled as complete. A final CCP defense should not present the old macro F1 or these development checks as evidence of a newly validated classifier.

## Concrete next experiment

Keep the ten medical categories and `unknown`. Before freezing Stage 3, define and independently justify the additional observable workflow profiles for every category, and implement matched direct/intermediary controls in both stacks. Start with the pump/intermediary and CT/workstation failures demonstrated here. Candidate profile work includes richer device-event sequences and acquisition-workflow evidence, but none is automatically proof of physical origin or a justified feature merely because it can be generated.

Test whether those profiles actually distinguish the intended classes under realistic missing evidence. If they do not, keep the distinctions unresolved and reassess the achievable target with the supervisor. A separate workflow-recognition evaluation is feasible, but would be an explicit scope addition—not a silent replacement of the ten-device task. Do not manufacture class-specific timing, identifiers or packet lengths to make ML appear useful.

After that evidence decision, freeze the split and label contract, collect the new cohorts, fit RF/HGB only on training with grouped CV, evaluate calibration/thresholds on their designated splits, and then score the untouched A/B tests. The macro F1 ≥0.70 target and proposed error/coverage targets remain research objectives, not achieved results.

## Artifacts and reproduction

Run from the repository root with the existing Module 2/3/4 Python dependencies and local TShark. The pilot uses the private GNS3 controller, installed `iomt-hospital:2` and `hiot-module2-sensor:1` images, and internet access only during dependency setup. Use fresh run/output folders for a new experiment.

```powershell
python "Module 4/tools/run_stage2_pilot.py" setup --folder runs/new-pilot
python "Module 4/tools/run_stage2_pilot.py" status --folder runs/new-pilot
# Wait for both workers to report ready=true and busy=false.
python "Module 4/tools/run_stage2_pilot.py" capture --folder runs/new-pilot --stack A
python "Module 4/tools/run_stage2_pilot.py" capture --folder runs/new-pilot --stack B
python "Module 4/tools/evaluate_stage2_pilot.py" --folder runs/new-pilot --output runs/new-pilot-evaluation
python "Module 4/tools/verify_pilot_windows.py" --folder runs/new-pilot --output runs/new-pilot/window-verification.json
python "Module 4/tools/run_stage2_pilot.py" close --folder runs/new-pilot
python "Module 4/tools/audit_public_candidates.py" --output runs/new-public-audit
```

For the saved offline demonstration:

```powershell
python -m module3 --state runs/module4-stage2-evaluation-20261124/A serve --offline --port 8894 --classification runs/module4-stage2-evaluation-20261124/A/classification.json
```

- Captures, manifests, versions and send receipts: `runs/module4-stage2-pilot-20261124/`.
- Evidence windows, normal Module 2/3 replay, frozen predictions and decision report: `runs/module4-stage2-evaluation-20261124/`.
- Public archive, pinned metadata and admission decision: `runs/module4-public-audit-20261124/`.
- Previous audit: [Stage 1 evidence audit](STAGE1_EVIDENCE_AUDIT.md).

Source changes and local artifacts have not been committed or pushed to GitHub.
