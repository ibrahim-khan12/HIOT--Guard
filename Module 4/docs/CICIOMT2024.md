# CICIoMT2024 compatibility and traffic experiment

The new comparison evaluates the existing GNS3 splits. CICIoMT2024 files have
not been downloaded or evaluated. The existing classifier and selected
shared-heart-rate abstention policy remain unchanged.

## Reproduce the comparison

Use `Module 4/requirements-module4.txt`, with `Module 3` on `PYTHONPATH`. Choose fresh
output directories because fitted artifacts and evaluation files are preserved.

```powershell
$study = 'runs/module4-learning-study-20261116'
$comparison = 'runs/module4-traffic-comparison-20261116'
python -m module4.traffic_study fit --root $study --output "$comparison/models"
python -m module4.traffic_study evaluate --root $study --models "$comparison/models" --output "$comparison/evaluation"
python -m module4.traffic_report --root $comparison --study $study
```

`fit` reads thirty training and ten validation sessions. It trains three
200-tree forests using protocol evidence, traffic statistics and combined
features. Validation chooses thresholds and a candidate family. `evaluate`
checks separate recordings/instances, hashes, canonical-flow alignment and
identifier/time invariance before scoring twelve existing test recordings.
That test set was previously inspected, so further design changes need a fresh
final test. No comparison model is promoted to the selected policy.

`traffic.py` defines shared statistics. Bytes mean canonical Zeek transport
payload bytes, not Ethernet frame lengths. Flow initiation timing is not packet
IAT. Statistics and combined candidates can score endpoints without HL7/DICOM.
Published CSV features need matching definitions before any merging.

## Obtain a profiling sample

Use the [official dataset page](https://www.unb.ca/cic/datasets/iomt-dataset-2024.html)
and [download link](https://cicresearch.ca/IOTDataset/CICIoMT2024/). On
16 November 2026 registration was required and the linked browse page returned
HTTP 403. Complete registration with your own details.

Choose original **WiFi_and_MQTT profiling PCAPs**, beginning with a small power
recording. Keep publisher device/MAC metadata and the original directory
structure. One camera and one SOS device in separate recordings are a useful
initial test of rejection outside our ten categories. The authors' profiling
inventory does not establish all ten hospital labels. An infant monitor does
not establish a bedside monitor label. A heart-rate band is not automatically
an ECG monitor. BLE files need a separate Bluetooth ingestion path.

## Import one session after downloading

Substitute the actual downloaded filename into this template:

```powershell
python -m module4.traffic_study import-pcap `
  --pcap 'PATH_TO_DOWNLOADED_PROFILING_CAPTURE.pcap' `
  --models 'runs/module4-traffic-comparison-20261116/models' `
  --output 'runs/ciciomt2024-first-sample'
```

The importer uses pinned offline Zeek and TShark through Module 2, projects a
Module 3 recording and writes `sample-audit.json` with hashes, sensor versions,
endpoint statistics and optional candidate predictions. Each input is limited
to 32 MiB by Module 2. Split larger recordings into bounded chunks and supply
all chunks together in the same session. Keep all chunks in the same split.
Unrelated recordings need separate output directories. The importer does not
infer truth from filenames, train models or report accuracy.

Verify the target endpoint using publisher identity metadata. Maintain a
separate ground-truth manifest with original dataset path, session, device
instance, endpoint, reviewed category/out-of-scope status, mapping rationale
and source. Exclude background and unverified endpoints from labelled metrics.
Attack labels cannot substitute for device categories. Medical devices outside
the verified target mapping must not be automatically labelled `other`.

Report public results separately. For verified out-of-scope targets, report
correct rejections and false hospital-category assignments. Ten-class public
macro F1 needs compatible labels and independent recordings, both unverified.

## 16 November result

The twelve GNS3 test sessions gave macro F1 0.870 for the existing raw forest,
0.871 for a protocol-evidence forest, 0.633 for statistics only and 0.838 for
combined features. Protocol evidence added four wrong assignments compared
with the existing model. Statistics fitted training F1 1.000 but validation
F1 0.678. These results do not justify replacing the existing selected policy.

The report, per-category scores, confusion matrices, fallback contribution,
model hashes and predictions are in `runs/module4-traffic-comparison-20261116/`.
The importer passed a saved GNS3 capture smoke check; this is not public-data
validation.
