"""Score a frozen Module 4 model across the four expanded evaluation profiles."""
import argparse
import hashlib
from pathlib import Path
from random import Random

from .collect import EVALUATION_SESSIONS
from .experiment import evaluate, load_json, read_split, recording_key, row_key, scorecard, write_json


def bootstrap_intervals(labels, predictions, profiles):
    """Resample whole sessions within each prespecified evaluation profile."""
    sessions = {session: [] for group in profiles.values() for session in group}
    for outcome in predictions:
        key = row_key(outcome)
        if key in labels:
            sessions[recording_key(outcome)].append((labels[key], outcome["decisions"]))
    rng = Random(4057)
    metrics = {"rules": [], "forest": [], "fallback": [], "fallback_minus_rules": []}
    for _ in range(1000):
        sample = [endpoint for group in profiles.values() for session in rng.choices(group, k=len(group))
                  for endpoint in sessions[session]]
        actual = [label for label, _ in sample]
        scores = {method: scorecard(actual, [decisions[method]["category"] for _, decisions in sample])["macro_f1"]
                  for method in ("rules", "forest", "fallback")}
        for method, value in scores.items():
            metrics[method].append(value)
        metrics["fallback_minus_rules"].append(scores["fallback"] - scores["rules"])
    intervals = {}
    for name, values in metrics.items():
        ordered = sorted(values)
        intervals[name] = [ordered[24], ordered[974]]
    return {"samples": 1000, "resampling_unit": "GNS3 session within profile",
            "confidence_level": 0.95, "macro_f1_intervals": intervals}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True, help="Trusted locally trained model")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    from joblib import load

    model = load(args.model)
    manifests = {}
    for profile, numbers in EVALUATION_SESSIONS.items():
        manifest = load_json(args.dataset / f"{profile}.json")
        expected = {f"session-{number:02d}/recording.json" for number in numbers}
        actual = {session["recording"] for session in manifest["recordings"]}
        if actual != expected or len(manifest["recordings"]) != len(expected):
            raise ValueError(f"Incomplete evaluation profile: {profile}")
        manifests[profile] = manifest
    args.output.mkdir(parents=True)
    aggregate = {"recordings": [
        {**session, "recording": str((args.dataset / session["recording"]).resolve())}
        for manifest in manifests.values() for session in manifest["recordings"]
    ]}
    aggregate_path = args.output / "manifest.json"
    write_json(aggregate_path, aggregate)
    report, predictions = evaluate(aggregate_path, model)
    report["model_sha256"] = hashlib.sha256(args.model.read_bytes()).hexdigest()
    report["profiles"] = {}
    profile_sessions = {}
    for profile in manifests:
        path = args.dataset / f"{profile}.json"
        profile_report, _ = evaluate(path, model)
        report["profiles"][profile] = profile_report
        profile_sessions[profile] = tuple(read_split(path)[0])
    _, labels, _ = read_split(aggregate_path)
    report["bootstrap"] = bootstrap_intervals(labels, predictions, profile_sessions)
    write_json(args.output / "report.json", report)
    write_json(args.output / "predictions.json", {"predictions": predictions})
    for method, values in report["methods"].items():
        print(f"{method}: macro F1 {values['macro_f1']:.3f}, {values['correct']} correct, "
              f"{values['incorrect']} incorrect, {values['abstained']} unknown")
    print(report["fallback_increment"])


if __name__ == "__main__":
    main()
