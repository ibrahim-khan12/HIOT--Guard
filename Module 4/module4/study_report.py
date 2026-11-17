"""Render the dataset-size experiment and final held-out results."""
import argparse
import csv
import os
from collections import defaultdict
from pathlib import Path
import statistics

from .experiment import load_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--curve-only", action="store_true")
    args = parser.parse_args()
    root = args.root
    curve = load_json(root / "learning-curve/results.json")
    groups = defaultdict(list)
    for point in curve["points"]:
        groups[point["sessions"]].append(point)
    keys = ("train_macro_f1", "validation_macro_f1", "shared_heart_rate_unknown_macro_f1",
            "training_pipeline_seconds")
    summaries = []
    for size, points in sorted(groups.items()):
        row = {"sessions": size, "training_endpoints": size * 15}
        for key in keys:
            values = [point[key] for point in points]
            row[key] = statistics.mean(values)
            row[key + "_min"] = min(values)
            row[key + "_max"] = max(values)
        summaries.append(row)
    out = root / "learning-curve"
    os.environ.setdefault("MPLCONFIGDIR", str((out / "matplotlib-cache").resolve()))
    with (out / "summary.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(summaries[0]))
        writer.writeheader()
        writer.writerows(summaries)
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, axis = plt.subplots(figsize=(9, 5.4))
    colors = ("#64748b", "#075985", "#0f766e")
    for key, label, color in zip(keys[:3], ("Training - raw forest", "Validation - raw forest",
                                           "Validation - shared heart-rate abstention"), colors):
        sizes = [row["sessions"] for row in summaries]
        axis.plot(sizes, [row[key] for row in summaries], marker="o", color=color, label=label)
        axis.fill_between(sizes, [row[key + "_min"] for row in summaries],
                          [row[key + "_max"] for row in summaries], color=color, alpha=.12)
    axis.axhline(.70, color="#991b1b", linestyle="--", linewidth=1, label="FYP target 0.70")
    axis.set(xlabel="Training sessions (15 labeled endpoints per session)",
             ylabel="Macro F1 across ten medical categories", ylim=(0, 1.04),
             title="Module 4 learning curve")
    axis.set_xticks([row["sessions"] for row in summaries])
    axis.grid(axis="y", alpha=.25)
    axis.legend(loc="lower right", fontsize=8)
    fig.text(.12, .01, "Fixed validation set of 10 sessions. Bands show the range across three training subsets.",
             fontsize=8, color="#475569")
    fig.tight_layout(rect=(0, .04, 1, 1))
    fig.savefig(out / "learning-curve.png", dpi=180)
    plt.close(fig)
    if args.curve_only:
        print(out / "learning-curve.png")
        return
    report = load_json(root / "evaluation/report.json")
    fit = load_json(root / "model/training.json")
    selection = report["selection"]
    baseline = report["original_model"]["methods"]["forest"]
    lines = [
        "# Module 4 dataset-size experiment", "",
        "The new study contains 30 training sessions (450 endpoint rows), ten validation sessions "
        "(150 rows) and twelve fresh test sessions (180 rows). Each session contains ten medical "
        "endpoints and five supporting endpoints. Each emulator instance belongs to one split.", "",
        "Training and validation cover normal, alternate, fragmented, burst and ambiguous profiles. "
        "The test sessions were collected after freezing the model and decision policy. The same "
        "emulator and service implementations underpin all splits.", "",
        "## Learning curve", "",
        "The table gives mean F1 across three session subsets at each training size. "
        "Validation sessions also select each model's abstention threshold.", "",
        "| Sessions | Rows | Train F1 | Validation F1 | Validation F1 with shared heart-rate abstention |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in summaries:
        lines.append(f"| {row['sessions']} | {row['training_endpoints']} | "
                     f"{row['train_macro_f1']:.3f} | {row['validation_macro_f1']:.3f} | "
                     f"{row['shared_heart_rate_unknown_macro_f1']:.3f} |")
    first, last = summaries[0], summaries[-1]
    change = last["validation_macro_f1"] - first["validation_macro_f1"]
    lines.extend(["", f"Mean raw validation F1 changed from {first['validation_macro_f1']:.3f} "
                  f"at {first['sessions']} training sessions to {last['validation_macro_f1']:.3f} "
                  f"at {last['sessions']} sessions, a change of {change:+.3f}."])
    lines.extend(["", "![Learning curve](learning-curve/learning-curve.png)", "",
                  "## Fresh test result", "",
                  "| Method | Macro F1 | Correct | Incorrect | Unknown |",
                  "| --- | --- | --- | --- | --- |",
                  f"| Original model, six training sessions | {baseline['macro_f1']:.3f} | "
                  f"{baseline['correct']} | {baseline['incorrect']} | {baseline['abstained']} |"])
    for key, name in (("rules", "Evidence rules"), ("forest", "Larger raw forest"),
                      ("selected_forest", "Larger forest with shared heart-rate abstention"),
                      ("selected_fallback", "Rules with selected forest fallback")):
        card = report["methods"][key]
        lines.append(f"| {name} | {card['macro_f1']:.3f} | {card['correct']} | "
                     f"{card['incorrect']} | {card['abstained']} |")
    increment = report["selected_fallback_increment"]
    intervals = report["bootstrap"]["macro_f1_intervals"]
    lines.extend(["", f"The selected fallback increases correct assignments by {increment['additional_correct']} "
                  f"and adds {increment['additional_wrong']} errors after rules abstain. "
                  f"{increment['still_unknown']} cases remain unknown. The approximate 95% "
                  f"session-bootstrap interval for selected-forest F1 is "
                  f"{intervals['forest'][0]:.3f} to {intervals['forest'][1]:.3f}.", ""])
    lines.extend(["", "## Per-category selected-forest result", "",
                  "| Category | Precision | Recall | F1 | Test examples |",
                  "| --- | --- | --- | --- | --- |"])
    for category, card in report["methods"]["selected_forest"]["classes"].items():
        lines.append(f"| {category} | {card['precision']:.3f} | {card['recall']:.3f} | "
                     f"{card['f1']:.3f} | {card['support']} |")
    lines.extend(["", "## Ambiguity and limits", "",
                  "The bedside and ECG actors emit the same heart-rate measurement kind, message "
                  "structure and sampling policy. The selected policy returns unknown for that shared "
                  "evidence. These unknown decisions reduce recall for both categories in the reported "
                  "ten-class macro F1. The table also reports the raw forest.", "",
                  f"The final training pipeline took {selection['training_pipeline_seconds']:.3f} seconds "
                  "after packet analysis. This timer includes fitting, validation threshold selection and "
                  f"saving the {len(fit['features'])}-feature model. Capture and packet processing take "
                  "additional time.", "",
                  f"The test contains {report['unlabeled_endpoints']} additional unicast address entries "
                  "without evaluation labels. Predictions include these entries and metrics exclude them.", "",
                  "The evidence establishes performance on the sampled GNS3 conditions. Physical-device "
                  "generalization requires separate evidence.", ""])
    (root / "REPORT.md").write_text("\n".join(lines), encoding="utf-8")
    print(root / "REPORT.md")
    print(out / "learning-curve.png")


if __name__ == "__main__":
    main()
