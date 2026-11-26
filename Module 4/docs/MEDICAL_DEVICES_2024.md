# Medical Devices 2024: bounded KardiaMobile compatibility audit

Completed 18 November 2026. This is a format, provenance and inference-compatibility
audit, not an ECG-class accuracy evaluation. No model, threshold, parser or feature
extractor was changed.

## Pinned source and sample

The [author repository](https://github.com/iotsec-lab/medical) was inspected at
commit `db156987d7c1d88b82f7e0895c68c246538405b6`. Its KardiaMobile listing has
70 `.pcap` members, totalling 6,329,968 bytes; ten group-1 members are empty.
The activity/function names corresponding to numeric filename groups were not
verified. Folder identity alone does not label a packet as an ECG measurement.

Before packet inspection, select first repetitions `2_1.pcap`, `3_1.pcap` and
`7_1.pcap`, plus empty `1_1.pcap` as a control. Download only 289,665 capture bytes.
Verify every downloaded file against the publisher's Git blob SHA-1 from the
pinned contents API, and record an independent SHA-256.

| File | Bytes | Packets | Observed duration | Canonical flows | Exported address rows |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1_1.pcap | 0 | None | None | Not imported | None |
| 2_1.pcap | 125,292 | 402 | 6.408 s | 42 | 6 |
| 3_1.pcap | 80,527 | 235 | 4.232 s | 11 | 4 |
| 7_1.pcap | 83,846 | 246 | 7.360 s | 11 | 3 |

The nonempty samples are complete, multi-packet **classic PCAPs with raw-IP
encapsulation (link type 101)**. They preserve timestamps, nonzero IP addresses
and transport tuples. They contain no Ethernet/MAC headers. This differs from
the README's single-packet PCAPNG description for these three inspected files;
other device directories were not audited. No conversion or invented Ethernet
headers were needed. The zero-byte control was correctly rejected as invalid PCAP.

## What is actually observed

The three traces contain TLS/TCP and DNS activity, including AliveCor service
names. The observed `10.215.173.1` client and `10.215.173.2` DNS addresses match
the virtual interfaces documented by [PCAPdroid's own FAQ](https://emanuele-f.github.io/PCAPdroid/faq.html).
Its [capture architecture](https://github.com/emanuele-f/PCAPdroid/blob/master/docs/how_it_works.md)
explains that non-root captures show application-to-VPN/proxy traffic and may
emulate IP/TCP headers. The [authors' paper](https://arxiv.org/html/2407.13857v1)
identifies PCAPdroid as their Wi-Fi collection tool.

Together, these observations support an app/proxy-side interpretation of these
samples. They do not establish that a visible network endpoint is physical ECG
hardware. AliveCor service association is evidence of related app activity;
it is not a hospital `ecg_monitor` endpoint label. No virtual IP or cloud server
was relabelled as medical-device ground truth.

Session-like grouping, timing and flow tuples are recoverable for the sampled
files, but their transport statistics must not be treated as validated physical
device fingerprints. No TCP SYN packets were observed in the three samples.
No recorded packets were truncated; canonical missed-byte counters were zero.
Those observations do not prove complete original network conversations.

## Existing pipeline and model response

All three nonempty samples imported through the existing Modules 2/3 pipeline,
producing 883 packet records, 64 canonical flows and thirteen exported endpoint
address rows. No confirmed HL7/DICOM evidence was present.

The unchanged selected fallback returned `unknown` for all thirteen rows, with
reason `insufficient_attributed_protocol_evidence`. Identifier/time renaming
checks passed for all three recordings. All six frozen model/selection artifact
hashes matched the preceding full Sentinel evaluation before and after inference.

These are observed decisions on **unlabelled** endpoints, not thirteen correct
ECG classifications or a scored rejection benchmark. No medical accuracy,
recall or F1 was computed, and these samples were not added to training.

## Verdict and next evidence

- Format compatibility is demonstrated for these three raw-IP captures.
- Use this audit to document real ECG-associated app/cloud traffic and the
  current classifier's protocol-coverage boundary.
- Do not add these rows as positive hospital ECG examples without verified
  endpoint attribution, category mapping and the original function/session labels.
- A future app/activity classifier would be a separate task requiring different
  labels and independent evaluation. It cannot silently replace device-category
  classification in the FYP.
- The remaining medical evidence gap needs verified device-side medical traces
  or independently justified medical protocol profiles for the approved lab scope.

## Evidence and reproduction

Local evidence is in `runs/kardia-audit-20261118/`: pinned repository listing,
sample selection, untouched packet files, per-sample packet summaries,
`report.json`, `model-predictions.json`, and the three imports `r21`, `r31`, `r71`.
The earlier failed Docker startup remains under `i21` as diagnostics and is not
included in the results.

Source sample links use the pinned commit, for example:
`https://raw.githubusercontent.com/iotsec-lab/medical/db156987d7c1d88b82f7e0895c68c246538405b6/kardiamobile/2_1.pcap`.

Run from the repository root with the existing Module 4 environment and Docker:

```powershell
python -m module4.traffic_study import-pcap `
  --pcap runs/kardia-audit-20261118/samples/2_1.pcap `
  --output runs/kardia-repro-21

python -m module4.study --root runs/module4-learning-study-20261116 predict `
  --recording runs/kardia-repro-21/recording.json `
  --output runs/kardia-repro-21/selected-predictions.json
```

Repeat using fresh output directories for the other two nonempty samples. Do not
merge different publisher files into an invented single recording. No GitHub
push or model training was performed.
