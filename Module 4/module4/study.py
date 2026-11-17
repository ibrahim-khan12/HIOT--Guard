"""Collect the larger dataset and measure learning curves on whole sessions."""
import argparse
from collections import Counter, defaultdict
from copy import deepcopy
import hashlib
import ipaddress
import json
from pathlib import Path
import random
import time

from . import UNKNOWN
from .classifier import endpoint_rows
from .collect import analyze, capture, profile
from .experiment import (decisions, evaluate, fitted_scores, forest_decision, inference_digest,
                         load_json, read_split, row_key, scorecard, train, write_json)

FAMILIES = ("normal", "eval-alternate", "eval-fragmented", "eval-burst", "eval-ambiguous")
SPLIT_COUNTS = {"training": 30, "validation": 10, "test": 12}
IMAGE = "zeek/zeek@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3"
HEART_PAIR = {"bedside_monitor", "ecg_monitor"}


def save_once(path, data):
    if path.exists():
        if load_json(path) != data:
            raise ValueError(f"Existing study data differs: {path}")
    else:
        write_json(path, data)


def specifications(split):
    families = FAMILIES if split != "test" else FAMILIES[1:]
    offset = {"training": 100, "validation": 200, "test": 300}[split]
    return [{"split": split, "session": offset + index, "family": families[index % len(families)],
             "seed": 160057 + offset + index} for index in range(SPLIT_COUNTS[split])]


def study_profile(spec):
    family = spec["family"]
    # The legacy helper uses these small indices to rotate the ambiguity cases.
    index = spec["session"] % 3
    legacy_number = 22 + index if family == "eval-ambiguous" else 13 + index
    if family == "normal":
        legacy_number = 1 + index
    configuration = profile(legacy_number, "training" if family == "normal" else family, spec["seed"])
    settings, properties, startup, schedule = configuration
    rng = random.Random(spec["seed"] + 61)
    settings["addresses"] = dict(zip(settings["addresses"], rng.sample(range(10, 245), 15)))
    settings.update(seed=spec["seed"], chunk_bytes=rng.choice((23, 37, 61)),
                    chunk_delay=rng.uniform(.004, .02), max_observations=rng.choice((3, 5, 7)),
                    max_stores=rng.choice((2, 3, 4)))
    if family == "normal":
        # Both actors use the same emitted format throughout this new study.
        settings["traffic_profile"] = "eval-alternate"
    for role, values in properties.items():
        values["environment"] = (f"LAB_ROLE={role}\nLAB_MODE=gns3\nMODULE4_SETTINGS=" +
                                 json.dumps(settings, separators=(",", ":")))
    return settings, properties, startup, schedule


def collect_split(root, server, split, shard, shards, tshark):
    if not 0 <= shard < shards:
        raise ValueError("Shard must be in the range 0..shards-1")
    if split == "test" and not (root / "model" / "selection.json").exists():
        raise ValueError("Freeze the model and selection policy before collecting test recordings")
    root.mkdir(parents=True, exist_ok=True)
    specs = specifications(split)
    save_once(root / f"{split}-specification.json", specs)
    sessions = []
    for index, spec in enumerate(specs):
        if index % shards != shard:
            continue
        folder = root / f"session-{spec['session']:03d}"
        print(f"{split} {index + 1}/{len(specs)} {spec['family']}", flush=True)
        if not (folder / "capture-report.json").exists():
            if folder.exists():
                raise ValueError(f"Incomplete capture preserved at {folder}. Use a fresh study directory.")
            capture(server, folder, spec["session"], split, study_profile(spec))
        capture_report = load_json(folder / "capture-report.json")
        if capture_report["settings"] != study_profile(spec)[0]:
            raise ValueError("Recorded traffic configuration differs from the study specification")
        if (folder / "recording.json").exists():
            entry = {"recording": "recording.json", "endpoints": capture_report["endpoints"]}
        else:
            entry = analyze(folder, server, None, tshark=tshark, zeek_image=IMAGE)
        sessions.append({**entry, "recording": f"{folder.name}/recording.json", "profile": spec["family"]})
    save_once(root / f"{split}-shard-{shard}.json", {"recordings": sessions})


def assemble(root, split, shards):
    sessions = []
    for shard in range(shards):
        sessions.extend(load_json(root / f"{split}-shard-{shard}.json")["recordings"])
    sessions.sort(key=lambda session: session["recording"])
    expected = {f"session-{spec['session']:03d}/recording.json" for spec in specifications(split)}
    if len(sessions) != len(expected) or {session["recording"] for session in sessions} != expected:
        raise ValueError(f"Incomplete {split} split")
    save_once(root / f"{split}.json", {"recordings": sessions})
    return sessions


def absolute_manifest(root, sessions):
    return {"recordings": [{**session, "recording": str((root / session["recording"]).resolve())}
                            for session in sessions]}


def labeled_rows(path):
    records, labels, _ = read_split(path)
    rows = [row for record in records.values() for row in endpoint_rows(record) if row_key(row) in labels]
    return records, labels, rows


def model_card(rows, labels, model, threshold, abstain_heart=False):
    expected = [labels[row_key(row)] for row in rows]
    predictions = []
    for row, scored in zip(rows, fitted_scores(model, rows), strict=True):
        label = forest_decision(row, scored, threshold)[0]
        if abstain_heart and set(row["candidates"]) == HEART_PAIR:
            label = UNKNOWN
        predictions.append(label)
    return scorecard(expected, predictions)


def tune_threshold(rows, labels, model, abstain_heart):
    scores = fitted_scores(model, rows)
    actual = [labels[row_key(row)] for row in rows]
    candidates = []
    for threshold in sorted({0.0, 1.000001, *(score for _, score in scores)}):
        predictions = []
        for row, scored in zip(rows, scores, strict=True):
            label = forest_decision(row, scored, threshold)[0]
            if abstain_heart and set(row["candidates"]) == HEART_PAIR:
                label = UNKNOWN
            predictions.append(label)
        card = scorecard(actual, predictions)
        candidates.append((card["macro_f1"], -card["incorrect"], threshold, card))
    _, _, threshold, card = max(candidates, key=lambda candidate: candidate[:3])
    return threshold, card


def fit_study(root, shards):
    from joblib import load

    sessions = assemble(root, "training", shards)
    assemble(root, "validation", shards)
    if (root / "model/selection.json").exists():
        _, selection = load_selected(root)
        load_json(root / "learning-curve/results.json")
        print(json.dumps({"reused_selected_model": selection["model_sha256"]}), flush=True)
        return
    _, valid_labels, valid_rows = labeled_rows(root / "validation.json")
    curve_root = root / "learning-curve"
    curve_root.mkdir(exist_ok=True)
    grouped = {family: [session for session in sessions if session["profile"] == family] for family in FAMILIES}
    points = []
    for repeat in range(3):
        rng = random.Random(4057 + repeat)
        ordering = {family: rng.sample(values, len(values)) for family, values in grouped.items()}
        for count in (5, 10, 20, 30):
            subset = [session for family in FAMILIES for session in ordering[family][:count // len(FAMILIES)]]
            target = curve_root / f"sessions-{count:02d}-repeat-{repeat + 1}"
            target.mkdir(exist_ok=True)
            manifest_path = target / "training-manifest.json"
            save_once(manifest_path, absolute_manifest(root, subset))
            if (target / "point.json").exists():
                points.append(load_json(target / "point.json"))
                continue
            started = time.perf_counter()
            fitted = train(manifest_path, root / "validation.json", target / "fit")
            elapsed = time.perf_counter() - started
            model = load(target / "fit/model.joblib")
            _, train_labels, train_rows = labeled_rows(manifest_path)
            guarded_threshold, guarded_card = tune_threshold(valid_rows, valid_labels, model, True)
            point = {"sessions": count, "endpoints": count * 15, "repeat": repeat + 1,
                           "train_macro_f1": model_card(train_rows, train_labels, model, model["threshold"])["macro_f1"],
                           "validation_macro_f1": fitted["validation"]["macro_f1"],
                           "validation_incorrect": fitted["validation"]["incorrect"],
                           "shared_heart_rate_unknown_macro_f1": guarded_card["macro_f1"],
                           "shared_heart_rate_unknown_threshold": guarded_threshold,
                           "training_pipeline_seconds": elapsed}
            write_json(target / "point.json", point)
            points.append(point)
    # Train once on all 30 sessions in a deterministic order for the final artifact.
    started = time.perf_counter()
    fit = train(root / "training.json", root / "validation.json", root / "model")
    elapsed = time.perf_counter() - started
    model = load(root / "model/model.joblib")
    guarded_threshold, guarded_card = tune_threshold(valid_rows, valid_labels, model, True)
    selection = {"decision_policy": "shared_heart_rate_unknown", "threshold": guarded_threshold,
                 "reason": "Both heart-rate actors share the same measurement kind, emitter and scheduling distribution.",
                 "raw_threshold": model["threshold"], "raw_validation": fit["validation"],
                 "selected_validation": guarded_card, "training_pipeline_seconds": elapsed,
                 "model_sha256": fit["model_sha256"], "inference_sha256": fit["inference_sha256"],
                 "study_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    heart_rows = [row for row in valid_rows if valid_labels[row_key(row)] in HEART_PAIR]
    heart_card = model_card(heart_rows, valid_labels, model, model["threshold"])
    write_json(root / "model/heart-rate-audit.json", {
        "validation_examples": len(heart_rows),
        "same_normalized_protocol_evidence": all(set(row["candidates"]) == HEART_PAIR for row in heart_rows),
        "raw_validation_correct": heart_card["correct"],
        "raw_validation_incorrect": heart_card["incorrect"],
        "raw_validation_unknown": heart_card["abstained"],
        "source_evidence": "module4.lab_actor.HL7 gives monitor and ecg the same HEART_RATE code, value and unit.",
        "decision": "Return unknown when the passive category evidence is shared by both classes.",
    })
    write_json(root / "model/selection.json", selection)
    write_json(curve_root / "results.json", {"points": points, "training_sessions": 30,
                                            "validation_sessions": 10, "repeats": 3})
    print(json.dumps({"selected_policy": selection["decision_policy"], "validation": guarded_card["macro_f1"],
                      "raw_validation": fit["validation"]["macro_f1"], "training_pipeline_seconds": elapsed}), flush=True)


def selected_predictions(record, model, selection):
    predictions = decisions(record, model)
    rowmap = {row["asset_id"]: row for row in endpoint_rows(record)}
    for item in predictions:
        row = rowmap[item["asset_id"]]
        raw = item["decisions"]["forest"]
        category = raw["category"]
        reason = raw["reason"]
        if raw["score"] < selection["threshold"]:
            category, reason = UNKNOWN, "below_validation_threshold"
        elif category == UNKNOWN and raw["reason"] == "below_validation_threshold":
            # The study policy can select a lower threshold than the raw artifact.
            scored = fitted_scores(model, [row])[0]
            category, reason = forest_decision(row, scored, selection["threshold"])
        if set(row["candidates"]) == HEART_PAIR:
            category, reason = UNKNOWN, "shared_heart_rate_evidence"
        item["decisions"]["selected_forest"] = {**raw, "category": category, "reason": reason,
                                                "method": "selected_forest"}
        decision = item["decisions"]["rules"]
        item["decisions"]["selected_fallback"] = (item["decisions"]["selected_forest"] if
                                                  decision["category"] == UNKNOWN else decision).copy()
        item["decisions"]["selected_fallback"]["method"] = "selected_fallback"
    return predictions


def load_selected(root):
    from joblib import load

    model_path = root / "model/model.joblib"
    selection = load_json(root / "model/selection.json")
    if hashlib.sha256(model_path.read_bytes()).hexdigest() != selection["model_sha256"]:
        raise ValueError("Frozen model artifact changed")
    if inference_digest() != selection["inference_sha256"]:
        raise ValueError("Inference source changed after selecting the study model")
    if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != selection["study_source_sha256"]:
        raise ValueError("Study decision policy changed after selection")
    return load(model_path), selection


def score_study(root, shards, baseline_model, output=None):
    from joblib import load
    from .evaluate_expanded import bootstrap_intervals

    assemble(root, "test", shards)
    model, selection = load_selected(root)
    report, predictions = evaluate(root / "test.json", model)
    records, labels, _ = read_split(root / "test.json")
    selected = []
    selected_invariance = []
    for record in records.values():
        outcomes = selected_predictions(record, model, selection)
        selected.extend(outcomes)
        renamed = deepcopy(record)
        addresses = {asset["ip"] for asset in renamed["assets"]}
        for flow in renamed["flows"]:
            addresses.update((flow["source_ip"], flow["destination_ip"]))
        aliases = {ip: str(ipaddress.IPv6Address(0x20010db8000000000000000000000000 + index))
                   for index, ip in enumerate(sorted(addresses), 1)}
        renamed.update(source_id="changed-source", scope="changed-scope")
        for index, asset in enumerate(renamed["assets"]):
            asset.update(ip=aliases[asset["ip"]], asset_id=f"changed-{index}", configured={"role": "changed"})
        for flow in renamed["flows"]:
            flow.update(source_ip=aliases[flow["source_ip"]], destination_ip=aliases[flow["destination_ip"]])
            for event in flow["evidence"]:
                event["metadata"].update(sender="changed", calling_ae="changed", called_ae="changed")
        changed = selected_predictions(renamed, model, selection)
        selected_invariance.append({"scope": record["scope"],
                                    "passed": [row["decisions"] for row in outcomes] ==
                                              [row["decisions"] for row in changed]})
    labeled = [row for row in selected if row_key(row) in labels]
    actual = [labels[row_key(row)] for row in labeled]
    for method in ("selected_forest", "selected_fallback"):
        report["methods"][method] = scorecard(actual, [row["decisions"][method]["category"] for row in labeled])
    increments = Counter()
    for row in labeled:
        if row["decisions"]["rules"]["category"] == UNKNOWN:
            predicted = row["decisions"]["selected_fallback"]["category"]
            outcome = "still_unknown" if predicted == UNKNOWN else (
                "additional_correct" if predicted == labels[row_key(row)] else "additional_wrong")
            increments[outcome] += 1
    report["selected_fallback_increment"] = {
        key: increments[key] for key in ("additional_correct", "additional_wrong", "still_unknown")}
    report["selected_identifier_invariance"] = selected_invariance
    report["selection"] = selection
    report["target"] = {"method": "selected_forest", "macro_f1": .70,
                        "passed": report["methods"]["selected_forest"]["macro_f1"] >= .70}
    groups = defaultdict(list)
    for session in load_json(root / "test.json")["recordings"]:
        record = load_json(root / session["recording"])
        groups[session["profile"]].append((record["source_id"], record["scope"]))
    # Bootstrap the selected decisions using the existing session-level sampler.
    boot_predictions = deepcopy(selected)
    for row in boot_predictions:
        row["decisions"]["forest"] = row["decisions"]["selected_forest"]
        row["decisions"]["fallback"] = row["decisions"]["selected_fallback"]
    report["bootstrap"] = bootstrap_intervals(labels, boot_predictions, groups)
    report["bootstrap"]["method_mapping"] = {"forest": "selected_forest", "fallback": "selected_fallback"}
    by_profile = {}
    for name, keys in groups.items():
        members = [row for row in labeled if (row["source_id"], row["scope"]) in keys]
        truths = [labels[row_key(row)] for row in members]
        by_profile[name] = {
            method: scorecard(truths, [row["decisions"][method]["category"] for row in members])
            for method in report["methods"]
        }
    report["profiles"] = by_profile
    baseline = load(baseline_model)
    baseline_report, _ = evaluate(root / "test.json", baseline)
    report["original_model"] = {
        "sha256": hashlib.sha256(baseline_model.read_bytes()).hexdigest(),
        "methods": baseline_report["methods"],
        "fallback_increment": baseline_report["fallback_increment"],
    }
    out = output or root / "evaluation"
    out.mkdir()
    write_json(out / "report.json", report)
    write_json(out / "predictions.json", {"predictions": selected})
    for method, card in report["methods"].items():
        print(f"{method} F1={card['macro_f1']:.3f} correct={card['correct']} "
              f"incorrect={card['incorrect']} unknown={card['abstained']}", flush=True)


def main():
    from config import tshark_path

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    collect = commands.add_parser("collect")
    collect.add_argument("--split", choices=tuple(SPLIT_COUNTS), required=True)
    collect.add_argument("--server", required=True)
    collect.add_argument("--shard", type=int, default=0)
    collect.add_argument("--shards", type=int, default=3)
    collect.add_argument("--tshark", default=tshark_path())
    commands.add_parser("fit").add_argument("--shards", type=int, default=3)
    evaluation = commands.add_parser("evaluate")
    evaluation.add_argument("--shards", type=int, default=3)
    evaluation.add_argument("--baseline-model", type=Path,
                            default=Path("runs/module4-gns3-v1/model/model.joblib"))
    evaluation.add_argument("--output", type=Path)
    predict = commands.add_parser("predict")
    predict.add_argument("--recording", type=Path, required=True)
    predict.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "collect":
        collect_split(args.root, args.server, args.split, args.shard, args.shards, args.tshark)
    elif args.command == "fit":
        fit_study(args.root, args.shards)
    elif args.command == "evaluate":
        score_study(args.root, args.shards, args.baseline_model, args.output)
    else:
        model, selection = load_selected(args.root)
        write_json(args.output, {"predictions": selected_predictions(load_json(args.recording), model, selection)})


if __name__ == "__main__":
    main()
