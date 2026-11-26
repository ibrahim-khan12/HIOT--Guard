# CICIoMT2024 compatibility and traffic experiment

The feature comparison evaluates the existing GNS3 splits. On 17 November,
two user-supplied CICIoMT2024 Power captures completed a separate external
rejection pilot. Neither capture was used for training or threshold selection.
The existing classifier and selected shared-heart-rate policy remain unchanged.

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

## 17 November public pilot

The supplied `Blink_Mini_Camera_Power.pcap` (568 frames) and
`Singcall_Power.pcap` (506 frames) imported successfully into separate sessions.
Table 3 of the [authors' preprint](https://www.preprints.org/manuscript/202402.0898/v1/download)
lists the target device MACs. Packet evidence matched those MACs to
192.168.137.7 and 192.168.137.235 respectively. Those identifiers are evaluation
metadata and never enter the feature vectors.

The current selected policy and all comparison candidates returned `unknown`
for both reviewed devices. There were two correct out-of-scope rejections and
zero medical-category assignments among the two labelled targets. Eighteen
other exported endpoint entries remain unlabelled and outside target metrics.
The statistics candidate assigned `infusion_pump` to background endpoint
192.168.137.1 in the Blink recording; this concern is retained in the report.

The current protocol guards reject these devices because neither has confirmed
HL7/DICOM. These results do not establish learned camera/SOS classification,
ten-category macro F1, or broad real-device accuracy. The Blink canonical Zeek
counters also report 9,425 missed payload bytes, despite zero TShark lost-segment
markers. Capture quality signals are preserved without a zero-loss claim.

The reviewed manifest, imported records and full report are under
`runs/module4-ciciomt2024-pilot-20261117/`. Reproduce the evaluation into a fresh
directory using:

```powershell
python -m module4.external_pilot `
  --manifest runs/module4-ciciomt2024-pilot-20261117/reviewed-manifest.json `
  --models runs/module4-traffic-comparison-20261116/models `
  --study runs/module4-learning-study-20261116 `
  --output runs/module4-ciciomt2024-pilot-reproduction
```

The manifest includes source hashes, original recording/device identities,
reviewed MAC/IP bindings, publisher source, mapping rationale and expected
out-of-scope status. The evaluator validates those bindings, preserves every
background prediction, verifies model hashes and checks identifier/time
invariance. It does not train or tune.

Next inspect the **Active** file listing and metadata. Table 2 includes a
simulated infusion pump and Section 4.4.3 says Active captures include simulated
MQTT traffic. Its presence in a particular capture must be verified before
mapping any rows to `infusion_pump`. The remaining Power files can expand
out-of-scope tests, but cannot supply missing CT/MRI/etc. labels.

## Active capture audit

The user supplied the combined `Active.pcap` on 17 November: 406,062,940 bytes
and 1,040,643 complete packet records. The full scan found 61,885 MQTT-bearing
frames. `infusion_data` appeared in 116 PUBLISH frames and fifteen SUBSCRIBE
frames; `EKG_data` appeared in 908 PUBLISH frames and fifteen SUBSCRIBE frames.
These are frame counts, not independent device examples.

The medical-topic PUBLISH traffic comes from 192.168.137.250:1883 and is
delivered to the publisher-identified iPad MAC E6:AA:E4:09:FC:8A. The simulated
pump address 10.0.0.13 is absent. The original publisher is not identifiable
as a separate pump endpoint on this observed broker-to-subscriber hop. Neither
the broker nor the tablet was assigned a medical-device ground-truth label.

A bounded 20.65 MB first-block extract passed the existing importer and
produced 169 canonical flows and twenty endpoint entries. The selected policy
returned unknown for every entry. Statistics alone made ten unsupported medical
assignments on unreviewed entries. All decisions are retained without reporting
a ten-class accuracy or counting the extract as an independent session.

No model fitting or threshold changes occurred. Full audit, hashes, frame
references and decisions are in `runs/module4-ciciomt2024-active-20261117/`.
Inspect **profiling/PCAP/Broker** next for publisher-side recordings and mapping
metadata. That directory's contents remain unverified.
