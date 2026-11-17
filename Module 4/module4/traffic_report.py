"""Render the traffic-feature comparison without changing fitted artifacts."""
import argparse
from collections import defaultdict
import csv
from pathlib import Path
import random

from .experiment import load_json, scorecard, write_json
from .traffic_study import FAMILIES


def paired_intervals(predictions, profiles, iterations=1000):
    sessions, groups = defaultdict(list), defaultdict(list)
    for row in predictions:
        sessions[row["scope"]].append(row)
    for scope, rows in sessions.items():
        groups[profiles[scope]].append(rows)
    rng = random.Random(1604057)
    differences = {name: [] for name in FAMILIES}
    for _ in range(iterations):
        sampled = [row for group in groups.values() for _ in range(len(group)) for row in rng.choice(group)]
        actual = [row["actual"] for row in sampled]
        base = scorecard(actual, [row["decisions"]["existing_raw_forest"]["category"] for row in sampled])["macro_f1"]
        for name in FAMILIES:
            value = scorecard(actual, [row["decisions"][name]["category"] for row in sampled])["macro_f1"]
            differences[name].append(value - base)
    result = {}
    for name, values in differences.items():
        values.sort()
        result[name] = {"lower": values[24], "upper": values[974]}
    return {"iterations": iterations, "seed": 1604057, "unit": "whole session within traffic profile",
            "difference_from_existing_forest_95_percent": result}


def render(root, study):
    selection = load_json(root / "models" / "selection.json")
    report = load_json(root / "evaluation" / "report.json")
    predictions = load_json(root / "evaluation" / "predictions.json")["predictions"]
    profiles = {load_json(study / entry["recording"])["scope"]: entry["profile"]
                for entry in load_json(study / "test.json")["recordings"]}
    intervals = paired_intervals(predictions, profiles)
    write_json(root / "paired-bootstrap.json", intervals)
    names = {"existing_raw_forest": "Existing larger raw forest", "rules": "Evidence rules",
             "protocol_evidence": "Protocol evidence forest", "statistics": "Traffic statistics forest",
             "combined": "Combined forest"}
    lines = ["# Module 4 traffic-feature comparison", "",
             "The added traffic features did not improve this evaluation. Keep the existing selected policy. "
             "No CICIoMT2024 capture was downloaded or evaluated, and no external data entered training.", "",
             "## Experiment", "",
             "Three new 200-tree Random Forests used 30 training sessions (450 endpoint rows) and ten "
             "validation sessions (150 rows). Minimum leaf size was two, class weights were balanced and "
             "seed was 4057. Validation chose each threshold before test scoring. Every split has distinct "
             "recordings and emulator instances. The same twelve test sessions contain 180 labelled "
             "endpoints: twelve per medical category and sixty supporting endpoints.", "",
             "The test set was already inspected in the preceding study, so this is an exploratory feature "
             "comparison. A fresh final test is needed after further design changes. All ten categories "
             "remain in macro F1, including abstained devices.", "",
             "| Feature family | Features | Train F1 | Validation F1 | Fit time | Threshold |",
             "| --- | ---: | ---: | ---: | ---: | ---: |"]
    for name, model in selection["models"].items():
        lines.append(f"| {names[name]} | {len(model['features'])} | {model['training']['macro_f1']:.3f} | "
                     f"{model['validation']['macro_f1']:.3f} | {model['fit_seconds']:.3f} s | {model['threshold']:.4f} |")
    lines += ["", "Times include vectorization and forest fitting, excluding extraction and threshold search. "
              "The statistics forest reached training F1 1.000 and validation F1 0.678, showing a substantial "
              "generalization gap. Validation selected the protocol evidence family; it was not promoted.", "",
              "## Same-session test results", "",
              "| Method | Macro F1 | Correct | Wrong | Unknown | Coverage |",
              "| --- | ---: | ---: | ---: | ---: | ---: |"]
    for name in ("existing_raw_forest", "rules", *FAMILIES):
        card = report["methods"][name]
        lines.append(f"| {names[name]} | {card['macro_f1']:.3f} | {card['correct']} | {card['incorrect']} | "
                     f"{card['abstained']} | {card['coverage']:.1%} |")
    lines += ["", "Unknown counts include the sixty supporting endpoints. All sixty received unknown under "
              "every method. Statistics alone misses the FYP target of macro F1 >= 0.70. The protocol "
              "evidence forest's tiny F1 increase comes with four more wrong assignments. Shared bedside/ECG "
              "evidence remains unresolved.", "",
              "| Category (support 12 each) | Existing forest F1 | Protocol evidence F1 | Statistics F1 | Combined F1 |",
              "| --- | ---: | ---: | ---: | ---: |"]
    for category in report["methods"]["existing_raw_forest"]["classes"]:
        values = [report["methods"][method]["classes"][category]["f1"]
                  for method in ("existing_raw_forest", *FAMILIES)]
        lines.append("| " + category + " | " + " | ".join(f"{value:.3f}" for value in values) + " |")
    lines += ["", "## Contribution after rules abstain", "",
              "| Fallback forest | Additional correct | Additional wrong | Still unknown |",
              "| --- | ---: | ---: | ---: |"]
    for name, increment in report["fallback_increment"].items():
        lines.append(f"| {names[name]} | {increment['additional_correct']} | {increment['additional_wrong']} | {increment['still_unknown']} |")
    lines += ["", "The previously selected shared-heart-rate abstention policy adds one correct assignment "
              "after the rules and zero errors on this test. None of the raw comparison models replaces it. "
              "Report additional correct and wrong assignments together for the CCP evaluation.", "",
              "## Uncertainty", "",
              "Approximate paired 95% intervals for macro F1 differences from the existing raw forest, "
              "using 1,000 whole-session resamples within each traffic profile:", ""]
    for name, interval in intervals["difference_from_existing_forest_95_percent"].items():
        lines.append(f"- {names[name]}: {interval['lower']:+.3f} to {interval['upper']:+.3f}.")
    lines += ["", "These intervals describe sampled emulator profiles, without establishing performance "
              "on new vendors, physical devices or the public dataset.", "",
              "## Feature and validation audit", "",
              "The extractor reads canonical Module 2 flows and verifies alignment with the Module 3 "
              "recording. It measures directional packets, transport payload bytes, flow durations, flow "
              "initiation intervals, peer counts and rates. Overlapping link observations are never summed. "
              "Missing counters are explicit. IPs, MACs, ports, registry roles, sender names, AE titles and "
              "absolute timestamps are excluded. All twelve identifier/time renaming checks passed for all "
              "three families. The statistics and combined candidates can score endpoints without HL7/DICOM. "
              "The protocol evidence model and existing classifier require confirmed medical protocol evidence.", "",
              "Payload bytes per packet is an aggregate ratio, not a packet-size distribution. Flow initiation "
              "timing is not packet IAT. Both datasets need the same raw-PCAP extraction. Published CIC CSV "
              "columns cannot be appended based on similar names. A high forest score does not guarantee "
              "that an unfamiliar device belongs to a hospital category.", "",
              "## CICIoMT2024 status", "",
              "The [official description](https://www.unb.ca/cic/datasets/iomt-dataset-2024.html) "
              "documents separate profiling PCAPs and attack traffic. Start with profiling for Module 4. "
              "Attack classification remains Module 5.", "",
              "The [authors' preprint](https://www.preprints.org/manuscript/202402.0898) describes "
              "seven Wi-Fi devices for power profiling, including cameras, SOS devices and a baby monitor. "
              "This inventory does not supply our ten hospital categories. The simulated MQTT topology "
              "includes Wellue EKG, but power profiling excludes simulated MQTT devices. A compatible ECG "
              "profiling label is unverified. BLE profiling needs a separate Bluetooth importer.", "",
              "| Input | Verified state | Consequence |",
              "| --- | --- | --- |",
              "| Publisher download | Registration form; linked browse page returned HTTP 403 | User registration/download needed |",
              "| Actual public files and labels | Unavailable locally | External metrics pending |",
              "| Importer smoke check | Existing GNS3 pump capture; 13 canonical flows, 8 unlabelled endpoints | Import works; this is not public-data validation |", "",
              "Complete registration at the [publisher download page](https://cicresearch.ca/IOTDataset/CICIoMT2024/). "
              "Choose a small original Wi-Fi profiling power PCAP, ideally a camera and an SOS device in "
              "separate recordings. Keep device/MAC metadata and recording provenance. Supply the local "
              "folder path, then use the import command in module4/CICIOMT2024.md.", "",
              "Verify the profiled target endpoint before scoring. Cameras and SOS devices can test "
              "out-of-scope rejection after identity verification. Background cloud hosts remain unlabelled. "
              "Do not infer hospital categories from attack labels or map an infant monitor to a bedside "
              "monitor. Any later training keeps all chunks/windows from a device instance in one split "
              "and reports public results separately from GNS3 ten-class F1.", "",
              "No registration was submitted and no personal details were fabricated.", ""]
    (root / "REPORT.md").write_text("\n".join(lines), encoding="utf-8")
    with (root / "comparison.csv").open("x", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(("method", "macro_f1", "correct", "incorrect", "unknown", "coverage"))
        for name, card in report["methods"].items():
            writer.writerow((name, card["macro_f1"], card["correct"], card["incorrect"], card["abstained"], card["coverage"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--study", type=Path, required=True)
    args = parser.parse_args()
    render(args.root, args.study)


if __name__ == "__main__":
    main()
