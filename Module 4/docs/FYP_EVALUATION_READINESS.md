# Module 4 readiness for the FYP evaluation

The [final evaluation results](FINAL_EVALUATION_RESULTS.md) supersede the interim estimate below. The 90-session study and the live assessment are complete. The actual Module 5 detector handoff remains to be exercised.

26 November 2026. **Estimated completion of the revised Module 4 plan is 75%.** This is a project readiness estimate based on deliverables and carries no official grading weight. It covers Module 4. Module 5 readiness needs its own verification.

| Module 4 deliverable | Points complete | Evidence and remaining work |
| --- | ---: | --- |
| Passive evidence, classification and abstention | 25 / 25 | The Module 2/3 recording pipeline, evidence rules, Random Forest and `unknown` decision are reproducible. |
| Original ten-category lab evaluation | 20 / 20 | The frozen study contains 52 GNS3 sessions, including 12 held-out sessions with 180 labelled endpoint observations. |
| Independent sender and ambiguity checks | 20 / 20 | The paired Python and HAPI/DCMTK forwarding trials and two matched waveform/acquisition recordings passed their development checks. |
| Evaluation demonstration and integration | 10 / 15 | Recorded evidence, saved predictions and the Module 3 assessment view can be demonstrated. Automatic refresh and a demonstrated Module 4 to Module 5 handoff still need verification. |
| Revised classifier and fresh evaluation | 0 / 20 | Train and compare new models after the evidence profiles are ready, then score fresh familiar and independent-stack sessions. |
| **Total** | **75 / 100** | **A demonstrated lab classifier and evidence pipeline, with the revised final study pending.** |

## Results to present

1. Show a saved Module 3 recording, the Module 4 device prediction or `unknown`, and the supporting packet references. The inventory's conservative assessment also exposes the observed workflow separately from the physical category.
2. Show the frozen held-out result from the 52-session study. Evidence rules scored **0.774 macro F1** and rules with the selected forest fallback scored **0.778**. The fallback added **one correct decision and zero errors** on the 180 labelled observations. Keep the result scoped to the sampled GNS3 emulator profiles. [Historical study report](../../runs/module4-learning-study-20261116/REPORT.md)
3. Show the forwarding comparison. Across four direct/forwarded pairs and eight GNS3 recordings, the downstream view left **20 of 20 upstream senders unresolved**. With both captures, the analyzer traced **20 of 20** to the expected upstream sender with **zero wrong matches**. Python and HAPI/DCMTK each contributed 10 of those transactions. The receivers and intermediaries were shared across stacks. [Packet-backed forwarding report](../../runs/module4-forwarding-20261126-r1/forwarding-report.json)
4. Show why `unknown` matters. In two synthetic recordings both heart-rate profiles reported a waveform with a matched acknowledgement. Both X-ray profiles completed a successful MPPS N-CREATE, DX C-STORE and MPPS N-SET sequence, with the create and set referring to the same procedure step. These workflows can occur in both members of each control pair, so the tested evidence leaves the physical categories unresolved. [Control report](../../runs/module4-forwarding-20261126-r1/specificity-report.json), [HL7 v2.5 waveform reporting](https://www.hl7.eu/HL7v2x/v25/std25/ch07.html), [DICOM MPPS operations](https://dicom.nema.org/medical/dicom/current/output/chtml/part04/sect_F.7.2.html)

The broader suite passed 178 tests. Independent replays of the forwarding and control captures produced byte-identical JSON reports. The existing classifier artifact was preserved. The 20 matched transactions measure upstream attribution in the test lab. The original macro F1 measures ten-category classification on the earlier held-out sessions.

## Protocol for the remaining evaluation

Use direct links and paired ingress/egress links when a relay is present. Keep every view and observation window from a session in the same split. Keep all ten medical classes in the denominator, include the relay, image-forwarding workstation and fixed X-ray as supporting controls, and count an `unknown` decision on a labelled medical endpoint against recall. Capture source and deployment labels belong in the audit or ground truth. The new forwarding and specificity recordings are development material.

The agreed planning allocation is 40 Python training, 10 Python calibration, 10 Python validation, 10 Python familiar test and 20 HAPI/DCMTK transfer test sessions. Freeze the actual manifests and independently justified endpoint profiles before final collection. The tested waveform and acquisition features can support workflow recognition. Further evidence is needed to support the physical distinctions. The final comparison should report ten-category macro F1, supporting endpoint errors, and the number of additional correct and wrong decisions after the rules abstain.

For a reproducible Module 4 demo with the saved inventory, use the project's Python environment from the repository root:

```powershell
python -m module3 --state runs/module4-stage2-evaluation-20261124/A serve --offline --port 8894 --classification runs/module4-stage2-evaluation-20261124/A/classification.json
```

Open the forwarding endpoint `10.88.0.15` at the local inventory. It shows **CT image storage** and device category **Unknown** with frame references. Use the saved historical predictions to demonstrate the ten-category classifier, and introduce Module 5 as the attack detection module separately.
