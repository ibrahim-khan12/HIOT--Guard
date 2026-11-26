# IoT Sentinel external rejection pilot

Completed 17 November 2026 with the user-supplied `captures_IoT_Sentinel.zip`.
The [publisher](https://research.aalto.fi/en/datasets/iot-devices-captures/)
describes repeated setup captures from consumer IoT devices. This pilot uses
three devices and nine original setup recordings as external evaluation data.
No public data was used for training or threshold selection.

## Result

| Method | Setups with all target addresses unknown | Setups with a false medical assignment |
| --- | ---: | ---: |
| Current selected policy | 9/9 | 0 |
| Rules | 9/9 | 0 |
| Existing raw forest | 9/9 | 0 |
| Protocol-evidence comparison | 9/9 | 0 |
| Traffic-statistics comparison | 8/9 | 1 |
| Combined comparison | 9/9 | 0 |

The traffic-statistics candidate assigned `infusion_pump` to the D-Link camera's
temporary setup address `192.168.0.20` in `Setup-B-1-STA.pcap`, with model score
0.419545. Its other camera address remained unknown. A setup counts as a failed
rejection if **any** reviewed address receives a medical category; selecting only
the most common address would have hidden this error.

All twelve MAC-attributed target address rows were exported as observed
transmitting. The selected policy rejected all twelve. Forty-five background
endpoint rows were preserved but remain outside the reviewed target labels.
The statistics candidate made nine medical assignments on those unreviewed rows,
including the gateway and a remote server. They are reported as concerns, with
their predictions retained, rather than silently treated as labelled devices.

This supports keeping the existing policy rather than promoting the statistics
candidate. The current policy has a confirmed-medical-protocol guard; no reviewed
target had confirmed HL7 or DICOM. Thus the 9/9 result demonstrates the intended
rejection behaviour on this sample, not that the forest learned these consumer
device identities, broad real-world accuracy, or ten-class hospital macro F1.

## Sample and provenance

- Original archive: 26,652,892 bytes (about 25.42 MiB).
- Locally recorded archive SHA-256:
  `41cc616e365be9e9430f13c979acab959cb4cebb8f72a66c28ce330979ce3760`.
  The publisher did not supply a checksum that was independently compared here.
- Selected original PCAPs: 355,055 bytes, 1,472 complete packet records and
  110 canonical flows. No prefixes or synthetic packets were used.
- Devices: D-LinkCam, TP-LinkPlugHS100 and SmarterCoffee.
- Three publisher MAC identities, with three setup captures each. These are
  repeated observations of the same identities, not nine independent devices.
- Selection was fixed before scoring: first filename for each available setup
  person, then fill to three captures per device in filename order. Consequently
  the coffee-maker fill capture is `Setup-A-10-STA.pcap` (lexicographic order).
- Publisher identity comes from the archive's per-device directory and
  `_iotdevice-mac.txt`. Every transmitting, non-unspecified/non-multicast source
  IP uniquely tied to that MAC is evaluated, including the camera's earlier IP.
- The consumer camera, plug and coffee maker are reviewed as outside all ten
  hospital categories. IPs, MACs and filenames are label/evidence metadata only.

All selected packet files were classic Ethernet PCAPs and passed validation.
No selected record was truncated. The TP-Link `Setup-C-1` trace had six TShark
retransmission markers; no selected trace had TShark lost-segment markers. The
canonical target counters reported zero missed payload bytes. Those measurements
do not prove capture completeness. SmarterCoffee has only eleven packets per
setup, mainly EAPOL, DHCP, ARP and IGMP. The result covers sparse startup traffic,
not sustained device operation.

## Reproduce

Run from the repository root with Module 4 dependencies, TShark and the existing
pinned Zeek Docker image available. Use fresh, reasonably short directories to
avoid Windows path limits inside canonical artifact storage:

```powershell
python -m module4.sentinel_pilot prepare `
  --archive 'C:\Users\Ibrahim Khan\Downloads\captures_IoT_Sentinel.zip' `
  --root runs/sentinel-repro

python -m module4.sentinel_pilot evaluate `
  --root runs/sentinel-repro `
  --models runs/module4-traffic-comparison-20261116/models `
  --study runs/module4-learning-study-20261116 `
  --output runs/sentinel-repro/result
```

Preparation reads only exact allowlisted ZIP members, skips macOS resource
forks, validates complete packet records and preserves input bytes. Evaluation
checks the ZIP/capture hashes, publisher MACs, MAC/IP ownership, original capture
selection, and imported capture hash. It reuses the Modules 2/3 importer and the
same canonical features as hospital recordings. It checks model/selection hashes
before and after scoring and verifies identifier/time invariance per recording.

The completed run is in `runs/module4-sentinel-pilot-20261117/results/`:

- `REPORT.md`: human-readable outcome and limitations.
- `report.json`: metrics, bindings, capture audits, frozen hashes and concerns.
- `predictions.json`: all target and background predictions with evidence.
- `ground-truth.json`: reviewed identities and archive provenance.
- `i01` through `i09`: individual Modules 2/3 imports, retained PCAPs and audits.

The run also retains the archive audit and selected source captures at its parent.
Earlier failed import directories remain as diagnostics and do not enter metrics.
All 33 Module 4 tests passed, including five new tests for deterministic sampling,
safe member selection, conflicting IP ownership and failure on any target alias.

## FYP use

Describe this as a small external **unknown-rejection evaluation**. Keep it
separate from the held-out GNS3 medical classification results. It adds evidence
about false hospital assignments and exposes a traffic-only generalization error.
It does not increase the medical training sample size, validate attack detection,
or independently demonstrate that the FYP/CCP requirements have been met.

## Complete archive evaluation

The full-run audit on 18 November inspected all 550 original captures in the
supplied ZIP, across 31 publisher folders. Every capture passed classic Ethernet
PCAP validation and publisher-MAC/source-IP verification. The frozen manifest
contains 924 source-IP entries across recordings, with nine pilot captures and
541 expansion captures. These entries are not 924 unique devices.

There are 29 observed publisher MAC groups. `D-LinkDoorSensor`/`D-LinkHomeHub`
share one MAC; `HueBridge`/`HueSwitch` share another. The original paper's
[Table II and experimental setup](https://arxiv.org/abs/1611.04880) distinguish
devices observed through hubs from direct network endpoints. The full audit
flags HomeMaticPlug, HueSwitch and D-LinkDoorSensor as gateway-mediated evidence.
Folder results remain visible, while equal-group averages use observed MACs.

The full evaluator preserves the pilot and provides separate, reproducible commands:

```powershell
python -m module4.sentinel_full audit `
  --archive 'C:\Users\Ibrahim Khan\Downloads\captures_IoT_Sentinel.zip' `
  --root runs/sentinel-full-repro

python -m module4.sentinel_full evaluate --root runs/sentinel-full-repro

# After an interruption, reuse only verified completed analyses:
python -m module4.sentinel_full evaluate --root runs/sentinel-full-repro --resume
```

The default artifacts are the existing learning-study model and traffic-comparison
models. The evaluator freezes their hashes, inference/extraction source hashes,
toolchain and manifest in `run.json`. It imports the new captures sequentially,
reusing the pinned analyzer for at most twenty imports or 600 seconds per batch.
The nine original pilot imports are verified and rescored without being overwritten.

Each capture retains its own recording, database and attempt history. Verified
cache results include hashes of retained packets, import metadata, recording and
canonical database. Interrupted or failed imports get new attempt directories.
Changing the frozen input, evaluator, feature sources, model or policy makes
`--resume` refuse reuse. Completed analyses with incomplete target discovery retain
their partial status; they do not become successful rejections.

Machine-readable reports distinguish completed, partial and unevaluable captures.
An observed medical assignment on any reviewed target alias remains an error,
even if another alias is missing. Other incomplete captures are unevaluable for
successful rejection. Per-method totals, per-folder results, per-MAC results,
equal-MAC averages, pilot/expansion breakdowns and fallback additions are preserved.
Unreviewed background predictions remain separate. No confidence interval treats
repeated captures as independent devices.

The working run is `runs/sentinel-full-20261117/`; immutable manifests and per-capture
attempts remain there. Completed report editions are written below `reports/`.
The expansion label means a capture was not scored in the pilot; it does not mean
every capture comes from a previously unseen physical device. It includes the
remaining setups of the three pilot identities. The ZIP and publisher's original
folder layout are preserved, and no new public training split is constructed.

### Full result: 18 November 2026

All **550/550 captures completed**, with **zero partial or unevaluable captures**.
The run processed 541 new imports and verified/rescored the nine existing pilot
imports. Every one of the 924 reviewed target-address entries was discovered with
attributed transmission. The captures contained 193,421 packet records and yielded
17,256 canonical flows. The full processing/inference invocation took 1,776.797
seconds (about 29.6 minutes); this is packet processing and evaluation time, not
model training time.

| Method | Setups correctly rejected | Setups with medical assignments | Wrong target-address assignments | Equal-MAC rejection mean |
| --- | ---: | ---: | ---: | ---: |
| Protocol baseline | 550/550 | 0 | 0 | 100.0% |
| Rules | 550/550 | 0 | 0 | 100.0% |
| Raw forest | 550/550 | 0 | 0 | 100.0% |
| Raw fallback | 550/550 | 0 | 0 | 100.0% |
| Selected forest | 550/550 | 0 | 0 | 100.0% |
| Selected fallback | 550/550 | 0 | 0 | 100.0% |
| Protocol-evidence comparison | 550/550 | 0 | 0 | 100.0% |
| Statistics-only comparison | 357/550 | 193 | 272 | 58.6% |
| Combined comparison | 550/550 | 0 | 0 | 100.0% |

For the statistics-only candidate, capture-weighted correct rejection was 64.9%.
Giving each of the 29 evaluable observed-MAC groups equal weight yields 58.6%.
These are rejection rates, not medical-category F1. All 272 incorrect reviewed
address assignments were `infusion_pump`. Multiple erroneous aliases can occur
within one setup, so 272 address errors correspond to 193 failed setup rejections.

The pilot reproduced exactly: statistics-only failed one of nine setups. In the
541-capture expansion it failed 192 setups; the selected fallback correctly
rejected all 541. All reviewed targets lacked confirmed HL7/DICOM. The selected
policy's protocol guard explains its rejection behaviour. The rules and selected
fallback therefore tied here; neither raw nor selected fallback added a medical
assignment after the rules abstained.

There were 3,828 unreviewed background endpoint rows. Statistics-only made 622
medical assignments on those rows. They are preserved as concerns outside formal
target metrics, with no claim that those background rows are independently
labelled test devices.

The first complete report is
`runs/sentinel-full-20261117/reports/v001/REPORT.md`; the adjacent `report.json`
contains every folder/MAC/cohort metric, `predictions.json` preserves every
endpoint decision, and `failures.json` records the empty incomplete-capture list.
The frozen manifest and `AUDIT.md` are at the run root. Models, thresholds and
23 inference/extraction source files remained unchanged throughout scoring.

Keep the medical results separate: the existing twelve-session GNS3 study reports
selected-fallback macro F1 0.778, versus rules 0.774, with one additional correct
assignment and zero added errors after rules abstained. Its selected-forest macro
F1 is 0.764. Those numbers remain in
`runs/module4-learning-study-20261116/REPORT.md`; Sentinel supplies external
rejection evidence rather than additional medical training examples or proof of
physical-medical-device classification accuracy.

Validation completed with all **44 Module 4 regression tests passing**. A real
`evaluate --resume` invocation verified all 550 cached results, performed zero
new imports and produced identical metrics in 58.078 seconds. Its report edition
is `runs/sentinel-full-20261117/reports/v002/`. The final integrity/accounting
record is `runs/sentinel-full-20261117/verification.json`: every capture occurs
once, all identifier/time checks passed, and ZIP, manifest, pilot, model/policy
and source hashes stayed unchanged. The original ZIP and pilot outputs remain
preserved. No GitHub push was performed.
