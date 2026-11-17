# Module 4 device classification

Module 4 reads passive Module 3 evidence and assigns one of ten emulator categories
or `unknown`. The categories are infusion pump, CT, MRI, ultrasound, portable X-ray,
bedside monitor, lab analyzer, ventilator, dialysis machine and ECG monitor.
Attack detection belongs to Module 5.

## Reproduce the experiment

From the repository root, install `requirements-module2.txt` and
`Module 4/requirements-module4.txt` in the project Python environment. Use the private
address of the GNS3 Linux compute, the expanded hospital Docker image
`iomt-hospital:2`, and the existing Module 2 sensor setup. The collector provisions
and closes dedicated session projects and never needs to open the original
acceptance project.

```powershell
python -m module4.replay --output runs/module4-replay-fresh

$server = 'http://192.168.209.142'
$root = 'runs/module4-study'
$sensor = 'runs/module3-live-20261112-233505/module2'
python -m module4.collect --server $server --output $root --sensor-state $sensor --split pilot
python -m module4.collect --server $server --output $root --sensor-state $sensor --split training
python -m module4.collect --server $server --output $root --sensor-state $sensor --split validation
```

The replay defaults to the saved pinned Zeek logs plus local TShark and checks
the classification evidence against an independent TShark read. Supply
`--sensor-host` and `--sensor-state` to regenerate it with the pinned Linux sensor.
For replay with the same offline tooling as the evaluation, pass `--zeek-image`.
For live GNS3 recordings processed offline, pass `--zeek-image <digest>` in place
of `--sensor-state`. This uses a network-disabled local Docker container for Zeek
and the installed TShark. `--capture-only` and `--analyze-existing` run the two
steps separately. See [GNS3's project file endpoint](https://api.gns3.net/en/stable/api/v2/controller/project.html).

The local Docker image used for this evaluation was
`zeek/zeek@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3`.
The installed decoder was TShark 4.6.3. The replay and pilot reports record the
tool versions used and the evidence test results.

```powershell
python -m module4 train --train "$root/training.json" --validation "$root/validation.json" --output "$root/model"
python -m module4.collect --server $server --output $root --sensor-state $sensor --split holdout
python -m module4 evaluate --holdout "$root/holdout.json" --model "$root/model/model.joblib" --output "$root/evaluation"
python -m module4 predict --recording "$root/session-10/recording.json" --model "$root/model/model.joblib" --output "$root/prediction.json"
```

Use only model artifacts from a trusted local training run. To export a recording
already in Module 3, use
`python -m module3 --state <folder> export-recording <new-output.json> --source-id <id> --scope <scope>`.
The separate split manifest has a `recordings` list. Each entry names a
recording path and contains `endpoints` with the evaluation IP, category and
emulator instance ID. Supporting endpoints use ground-truth `other`.

## Decisions and scoring

The protocol baseline reports a protocol group and abstains on the exact device
category. Rules use at least two distinct canonical exchanges, a category-specific
outbound signal, and parser-confirmed return traffic. A DICOM request shows a
proposed storage class. Its presence alone does not show that an image was stored.
The two heart-rate observation codes deliberately map to one `heart_rate` kind.

The seeded, class-balanced Random Forest learns from the ten medical categories
and labeled supporting endpoints. It uses protocol/measurement/storage counts,
reply counts, packets, peer counts, and relative timing. The selected threshold
maximizes ten-category macro F1 on validation, with fewer wrong decisions and
then greater abstention as tie-breakers. A score is the forest's maximum class
probability and has not been calibrated. A maximum score for `other` produces
`unknown`. The fallback method uses a rule decision when available and the forest
otherwise. The evaluator measures additional correct and wrong fallback assignments.

Evaluation treats unknown predictions on medical devices as misses for recall
and medical predictions on supporting endpoints as false positives. The target
is macro F1 of at least 0.70 across all ten medical classes on the held-out
GNS3 recordings. The report includes per-class support, precision, recall, F1,
coverage, a confusion matrix, separate correct/incorrect/unknown counts, and
identifier-renaming checks. Captures, local models, and split labels live in
ignored `runs/`. The scope is the synthetic GNS3 emulators.

## 14 November 2026 result

The pump and CT replay matched all four expected packet frames, including
direction. The separate full-hospital pilot exposed usable evidence for all ten
medical endpoints. Both heart-rate actors showed the same normalized measurement
kind and the rules abstained on both. The pilot is excluded from training and
scoring.

The experiment used six training, three validation and three holdout sessions
with fifteen labeled endpoint instances each. The frozen validation threshold
was 0.449233. The held-out denominator is 30 labeled medical endpoints and 15
labeled supporting endpoints. An additional 36 observed unicast address records
without ground truth are present in the predictions and excluded from the metrics.

| Method | Macro F1 | Coverage | Correct | Incorrect | Unknown |
| --- | ---: | ---: | ---: | ---: | ---: |
| Protocol group only | 0.000 | 0.0% | 0 | 0 | 45 |
| Evidence rules | 0.730 | 46.7% | 21 | 0 | 24 |
| Random Forest | 0.827 | 60.0% | 24 | 3 | 18 |
| Rules with forest fallback | 0.827 | 60.0% | 24 | 3 | 18 |

The fallback added three correct assignments and three errors. Every error was
a bedside-monitor/ECG-monitor swap. All 15 supporting endpoints received
`unknown`. Two sparse pump cases and one sparse CT case remained unresolved.
The model met the 0.70 macro F1 target in this study. With three held-out
instances per medical category and one emulator implementation per category,
the result measures this lab setup. It leaves the heart-rate pair unresolved as
a reliable operating distinction.

The local study folder is `runs/module4-gns3-v1/`. See
`session-00/pilot-report.json`, `model/training.json` and `evaluation/report.json`
for the pilot, model fit and full metrics. `evaluation/predictions.json` provides
the decision and evidence details.

## Expanded evaluation of the frozen model

The original six training sessions and three validation sessions produce the
model used here. A second test set uses twelve new GNS3 projects with fresh
actors, varied addresses, startup order and traffic timing. Each project has one
endpoint from each medical category and five supporting endpoints. Four profiles
contribute three sessions each.

| Profile | Traffic change |
| --- | --- |
| Alternate | HL7 uses neutral sender fields and coded OBX identifiers. DICOM clients use a common AE title and send storage-only associations. |
| Fragmented | HL7 messages are written in small chunks. DICOM includes the category storage context followed by Verification. |
| Burst | An HL7 message carries multiple observations. Each DICOM association stores multiple images. |
| Ambiguous | In each session one medical HL7 actor omits its category-specific measurement kind and one imaging actor sends Verification only. |

The bedside and ECG actors share the same heart-rate code, message structure and
sampling policy in every profile. The workstation sends Verification-only DICOM
and the unregistered endpoint sends generic HL7. These supporting cases exercise
the ability to abstain on legitimate protocol traffic from outside the target
categories. The expanded set uses the same GNS3 service implementations and
therefore measures transfer across these emitter and traffic changes.

```powershell
$root = 'runs/module4-expanded-evaluation'
$image = 'zeek/zeek@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3'
foreach ($profile in 'eval-alternate','eval-fragmented','eval-burst','eval-ambiguous') {
    python -m module4.collect --server $server --output $root --zeek-image $image --split $profile
    if ($LASTEXITCODE -ne 0) { throw "Collection failed for $profile" }
}
python -m module4.evaluate_expanded --dataset $root --model 'runs/module4-gns3-v1/model/model.joblib' --output "$root/evaluation"
```

The report gives a separate scorecard for each profile and for the full test set.
The model artifact hash and prediction records allow the evaluation to be audited
and repeated.

### 15 November 2026 result

The twelve sessions contributed 120 labeled medical endpoints and 60 labeled
supporting endpoints. Each medical class had 12 examples. The reported metrics
exclude 154 observed unicast address records without ground truth.

| Method | Macro F1 | Coverage | Correct | Incorrect | Unknown |
| --- | ---: | ---: | ---: | ---: | ---: |
| Protocol group only | 0.000 | 0.0% | 0 | 0 | 180 |
| Evidence rules | 0.774 | 50.0% | 90 | 0 | 90 |
| Frozen Random Forest | 0.853 | 59.4% | 99 | 8 | 73 |
| Rules with forest fallback | 0.853 | 59.4% | 99 | 8 | 73 |

| Profile | Evidence rules F1 | Frozen forest F1 |
| --- | ---: | ---: |
| Alternate | 0.800 | 0.907 |
| Fragmented | 0.800 | 0.840 |
| Burst | 0.800 | 0.917 |
| Ambiguous | 0.680 | 0.733 |

The fallback resolved nine additional endpoints correctly and added eight errors.
All errors were bedside-monitor/ECG-monitor swaps. All 60 supporting endpoints
received `unknown`. The forest passed the 0.70 macro F1 target in the expanded
test. The approximate 95% interval from resampling whole sessions within each
profile was 0.812–0.887 for the forest. This interval describes variation across
the sampled sessions under the chosen profiles.

The frozen model hash matched the original artifact. All 12 identifier-renaming
checks passed, and a second scoring run reproduced the report and predictions
byte for byte. The local artifacts are under
`runs/module4-expanded-evaluation/evaluation/`.

## Dataset-size experiment

The larger study collects 30 new training sessions, ten new validation sessions
and twelve fresh test sessions. Every session includes one instance of each
medical category and five supporting endpoints. Train and validation sessions
cover ordinary, alternate, fragmented, burst and ambiguous traffic. The test
recordings are collected after the model and decision policy are frozen.

```powershell
$study = 'runs/module4-learning-study-20261116'
# Each shard owns a distinct set of sessions. Run shards in separate terminals
# to collect concurrently, or run this loop sequentially.
foreach ($shard in 0,1,2) {
    foreach ($split in 'training','validation') {
        python -m module4.study --root $study collect --server $server --split $split --shard $shard
        if ($LASTEXITCODE -ne 0) { throw "Collection failed" }
    }
}
python -m module4.study --root $study fit
foreach ($shard in 0,1,2) {
    python -m module4.study --root $study collect --server $server --split test --shard $shard
    if ($LASTEXITCODE -ne 0) { throw "Collection failed" }
}
python -m module4.study --root $study evaluate
python -m module4.study_report --root $study
python -m module4.study --root $study predict --recording "$study/session-300/recording.json" --output "$study/prediction.json"
```

The learning curve fits 5, 10, 20 and 30 complete training sessions with three
subset orderings at each size. Every fit uses the same ten validation sessions.
The curve reports raw training/validation macro F1, validation macro F1 with
heart-rate abstention, and elapsed training pipeline time. Validation also chooses
the abstention threshold, so the final fresh test is the independent evaluation.
The selected study policy returns `unknown` for shared bedside/ECG measurement
evidence. The final test compares that policy, the raw larger forest, the original
six-session model, and evidence rules on exactly the same endpoints.

The generated `REPORT.md`, learning-curve PNG/CSV, selection metadata and full
evaluation JSON are saved inside the chosen study folder. Rendering the chart
requires Matplotlib. The original Module 4 CLI continues to expose its raw forest
methods. Use the study's `predict` command to apply the selected study policy.

### 16 November 2026 result

The study completed 30 training sessions (450 endpoint rows), ten validation
sessions (150 rows), and twelve fresh test sessions (180 rows). All ten medical
categories have 30 training, ten validation and twelve test examples. The three
splits use distinct recordings and emulator instances.

Mean raw validation F1 was 0.873 at five training sessions, 0.882 at ten,
0.859 at twenty, and 0.847 at thirty. The curve shows no consistent gain from
adding sessions within these traffic families. The final model uses all thirty
sessions. Its training pipeline took 2.006 seconds and saved a 3.15 MB artifact.

| Method on the same fresh test | Macro F1 | Correct | Incorrect | Unknown |
| --- | ---: | ---: | ---: | ---: |
| Original six-session forest | 0.842 | 99 | 11 | 70 |
| Evidence rules | 0.774 | 90 | 0 | 90 |
| Larger raw forest | 0.870 | 101 | 8 | 71 |
| Larger forest with shared heart-rate abstention | 0.764 | 88 | 0 | 92 |
| Rules with selected forest fallback | 0.778 | 91 | 0 | 89 |

All eight raw-forest errors were bedside/ECG swaps. The selected policy returns
`unknown` for both categories when they share heart-rate evidence, including all
24 such test endpoints. Both categories remain in the macro F1 denominator.
The selected fallback adds one correct assignment after the rules abstain and
adds zero errors. This is a small measured contribution in this study.

The report, learning curve, model, full predictions and verification record are
under `runs/module4-learning-study-20261116/`. A GNS3 connection interruption
occurred while three test projects were starting. Those projects were resumed
using the original settings before capture. The six completed test recordings
were retained.

## Traffic statistics and public-data readiness

See [CICIOMT2024.md](CICIOMT2024.md) for the separate feature comparison and
the importer for a downloaded public profiling sample. On the same twelve
test sessions, statistics alone scored macro F1 0.633 and combined features
scored 0.838, compared with 0.870 for the existing larger raw forest. The
comparison did not replace the existing selected policy. Actual CICIoMT2024
files remain pending the publisher's registration/download process.


## Repository layout

| Path | Contents |
| --- | --- |
| module4/ | Classification, dataset collection, training and evaluation commands |
| tests/ | Module 4 regression tests |
| docs/ | Public dataset compatibility notes |
| requirements-module4.txt | Module 4 Python dependencies |

Run commands from the repository root. The root module4 package forwards imports
to this folder, preserving python -m module4 and the existing subcommands.
Shared observation and export changes live with Modules 2 and 3.

```powershell
python -m pip install -r "Module 4/requirements-module4.txt"
python -m unittest discover -s "Module 4/tests" -v
```
