# Final Module 4 GNS3 evaluation

The Module 4 lab study and inventory demonstration are complete. The earlier end-to-end readiness estimate reaches **98/100**. The remaining two points require connecting the verified context interface to the actual Module 5 detector and rehearsing that downstream demo. No Module 5 detector was found in the current checkout. The interface passed verification with a consumer fixture. [Original readiness rubric](FYP_EVALUATION_READINESS.md)

## Final ten-category results

All **90** planned synthetic sessions were recorded in nine split-local capture batches. The corpus has 27 PCAPs and 1,350 labelled endpoint-session examples. An independent audit checks 5,400 feature rows at the four observation windows, 34,429 evidence-reference entries, group and split ownership, and the saved predictions against the metric report. Simultaneous logical sessions share lab workers and capture batches. This design measures configured GNS3 roles under the tested scenarios. [Protocol](FINAL_EVALUATION_PROTOCOL.md), [corpus and scoring audit](../../runs/module4-final-20261126/final-audit.json)

| 120-second test cohort | Sessions | Capture batches | Correct | Wrong | Unknown | Rules macro F1 | Rules with ML fallback macro F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Familiar Python | 10 | 1 | 70 | 0 | 80 | 0.700 | 0.700 |
| HAPI/DCMTK transfer | 20 | 2 | 140 | 0 | 160 | 0.700 | 0.700 |

Both cohorts reached the 0.70 point-estimate target. No supporting endpoint received a medical class in either cohort. Bedside monitor, ECG monitor and portable X-ray remain unresolved under the tested evidence. Every abstention on a medical endpoint counts against recall.

Random Forest and histogram gradient boosting were fit using semantic, traffic, and combined features. Grouped fitting, separate calibration and validation, and the final freeze happened before holdout scoring. Validation selected histogram gradient boosting with semantic inputs and the workflow guard. The fitting pipeline, including selection and diagnostics, took **34.47 seconds**. Scoring took **4.09 seconds**. [Frozen selection](../../runs/module4-final-20261126/fitted/selection.json)

At 120 seconds the fallback added **zero correct decisions and zero errors** in each cohort after the rules abstained. The five percentage point ML coverage improvement target was missed. Use the updated rules as the default for this lab result. The evaluation report also shows class counts, confusion matrices, ablations, calibration diagnostics, and results at 10, 30 and 60 seconds. With one and two capture batches in the test cohorts, it reports per-batch results and leaves paired confidence intervals unset. [Metrics](../../runs/module4-final-20261126/scored/report.json), [predictions](../../runs/module4-final-20261126/scored/predictions.json)

## Demonstration and handoff

The live Module 4 assessment is shown in the Module 3 endpoint view. It includes category, observed workflow, explanation, method/version, observation window and packet references. The verification compares all seven labelled playback endpoints with their saved offline assessment and exercises current, pending, unavailable and restored revisions. The browser check passed all seven checks. [Dashboard screenshot](../../runs/module4-final-20261126/browser/inventory-workflow.png), [handoff verification](../../runs/module4-final-20261126/live-handoff-verification.json)

The Module 4 side of the handoff is `GET /api/assets/{asset_id}/module4-handoff`. The route provides revision-bound context on loopback. The final lab classifier and the conservative live workflow assessment are distinct demo views. The participant can show the final scorecards first, then use the image-forwarding endpoint to explain why the live workflow panel displays CT image storage with category `unknown`. [Module 3 live setup](../../Module%203/docs/MODULE3.md)

## Reproduction commands

Run from the repository root with the project dependencies and an authorized local GNS3 controller. The offline bundle is prepared according to the forwarding experiment. Supply fresh output paths for a new run. To repeat the saved evaluation, reuse the captured `batches` and choose new fitting and scoring directories. [Offline bundle preparation](FORWARDING_EXPERIMENT.md)

```powershell
$root = 'runs/module4-final-20261126'
python 'Module 4/tools/run_final_corpus.py' --output $root --bundle runs/module4-stack-b-20261126/stack-b.tar
python 'Module 4/tools/export_final_corpus.py' --folder $root --split train --split calibration --split validation
python -m module4.final_study fit --dataset "$root/dataset" --output "$root/repro-fit"
python 'Module 4/tools/export_final_corpus.py' --folder $root --split familiar --split transfer
python -m module4.final_study score --dataset "$root/dataset" --fitted "$root/repro-fit" --output "$root/repro-score"
python 'Module 4/tools/verify_final_corpus.py' --rows "$root/dataset" --raw "$root/batches" --scored "$root/repro-score" --output "$root/repro-audit.json"
python 'Module 3/tools/verify_live_assessment.py' --output "$root/repro-live.json"
```

The broader regression suite passed 183 tests. The historical 52-session audit and saved demo predictions reproduced exactly. The final study is a separate evidence set from that historical benchmark.
