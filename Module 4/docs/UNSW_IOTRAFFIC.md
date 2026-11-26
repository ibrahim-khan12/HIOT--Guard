# UNSW-IoTraffic external Module 4 pilot

Status on 17 November 2026: **tooling prepared; public packets not downloaded or
evaluated**. Both the public PCAP link and the 1,840-byte device inventory link
returned HTTP 403 from this environment. The Dryad file-download API returned
HTTP 401, `Unauthorized, must have current bearer token`. Metadata APIs worked.
This is a data-access limitation; no UNSW evaluation result is claimed.

The publisher file manifest and exact HTTP errors are saved locally in
`runs/module4-unsw-access-20261117/`. All 28 current Module 4 tests passed,
including seven new prefix/provenance tests. The existing selected model and all
three comparison artifacts loaded successfully with their source/hash guards;
no fitting or policy changes were made. These are tooling checks, not a public
dataset evaluation.

## Source and selection

- [Publisher](https://iotanalytics.unsw.edu.au/unsw-iotraffic.html).
- [Versioned deposit](https://doi.org/10.5061/dryad.w0vt4b94b), Dryad version 392848.
- `pcaps.zip`, file 4322593: 13,919,387,057 compressed bytes; publisher SHA-256
  `feb647d4ed05e122309bbec68bba9715fd8bc761940d160283c763fd2e610e68`.
- `device_pcap_summary.csv`, file 4322597: 1,840 bytes; publisher SHA-256
  `34455dadf9aaada1110ca130082cec643430a6d456f1b7ce1303cd3da6f53e95`.

The deposit describes 27 consumer IoT device traces across about 203 days.
These are external evaluation candidates, not additional labelled CT, MRI,
ventilator, etc. training examples. Do not substitute the publisher's flow CSV
columns for our canonical features: its flow timeout and payload accounting
need not match Zeek's. Re-extract features from packet bytes using Modules 2/3.

Obtain the public files through the publisher's supported download mechanism.
Verify the archive/inventory hashes above and extract selected device PCAPs.
Keep their `DeviceName_DeviceMAC.pcap` names. Initially select three different
consumer devices, preferably a camera, smart plug and speaker if their identities
are confirmed by the downloaded inventory. Their actual availability and MACs
have not been verified here. Fix this selection before looking at predictions.

## Prepare and import a bounded sample

Use an extracted publisher PCAP and a fresh output directory:

```powershell
python -m module4.unsw_pilot prepare `
  --pcap '<path-to-DeviceName_DeviceMAC.pcap>' `
  --output runs/module4-unsw-pilot/device-1

python -m module4.traffic_study import-pcap `
  --pcap runs/module4-unsw-pilot/device-1/sample.pcap `
  --output runs/module4-unsw-pilot/import-1 `
  --models runs/module4-traffic-comparison-20261116/models
```

The prefix is the first 50,000 complete packets, bounded at 16 MiB. It preserves
packet bytes, timestamps and original frame numbers within that prefix. It saves
the original full-file hash and separate prefix hash in `source-audit.json`.
The original file is never changed. PCAPNG requires conversion to classic PCAP
first, keeping both source and conversion provenance. Prefix extraction validates
the selected records, not the unselected tail. Import requires the existing
local TShark and pinned Zeek Docker runtime.

## Review labels, then evaluate

Independently confirm the publisher's device name/MAC in the inventory and find
its transmitting source IP in the sample. Check whether the device is outside
all ten hospital categories; do not automatically map a health-related product
to a hospital category. MAC/IP values join evaluation labels to packet evidence;
they never enter the feature vector. Create `reviewed-manifest.json` in
`runs/module4-unsw-pilot/` using real reviewed values:

```json
{
  "schema_version": "hiot.module4.unsw-pilot.v1",
  "recordings": [{
    "sample_directory": "device-1",
    "import_directory": "import-1",
    "original_session": "DeviceName_DeviceMAC.pcap",
    "device": "DeviceName",
    "target_mac": "publisher MAC from source-audit.json",
    "target_ip": "observed transmitting IP",
    "expected": "unknown",
    "review_status": "out_of_scope_reviewed",
    "identity_source": "publisher device_pcap_summary.csv, exact reviewed row",
    "mapping_rationale": "Explain why this confirmed device is outside the ten categories"
  }]
}
```

```powershell
python -m module4.unsw_pilot evaluate `
  --manifest runs/module4-unsw-pilot/reviewed-manifest.json `
  --models runs/module4-traffic-comparison-20261116/models `
  --study runs/module4-learning-study-20261116 `
  --output runs/module4-unsw-pilot/evaluation
```

The evaluator verifies the prefix hash, imported recording hash, publisher-file
identity, and observed MAC/source-IP binding. It rejects duplicate original
recordings, checks identifier/time invariance, and verifies frozen models and
selection files remain unchanged. Only independently reviewed target endpoints
enter rejection metrics; every background prediction remains in predictions.json.

Outputs are `report.json`, `predictions.json`, the reviewed manifest and `REPORT.md`.
They compare the current policy and the existing protocol, statistics and combined
models. They report correct unknown rejections and incorrect hospital assignments.
They do not compute ten-category macro F1, train a model or adjust thresholds.

## Interpretation for the FYP / CCP

This supplies an external-domain rejection check once actual packets are scored.
It cannot establish improvement until results exist. Protocol-gated methods may
reject all these devices solely because HL7/DICOM is absent. The traffic-only
and combined candidates give additional evidence about false hospital assignments,
but remain unpromoted comparison models. A forest score is not an unknown-class
probability. A short prefix can emphasize startup and cut flows; it does not
represent the full 203-day trace. Prefixes/windows from one trace are not additional
independent devices or sessions. The main ten-category FYP evaluation remains the
held-out GNS3 study; external consumer traffic does not increase its training size.
