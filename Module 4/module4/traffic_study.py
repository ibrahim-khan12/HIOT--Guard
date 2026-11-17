"""Compare protocol evidence, traffic statistics and combined endpoint models.

fit reads only training/validation. evaluate scores the predeclared families on
the existing study test set. import-pcap prepares unlabelled external samples.
"""
import argparse
from collections import Counter
import hashlib
from pathlib import Path
import time

from . import OTHER, UNKNOWN
from .classifier import rule
from .experiment import (evaluate, inference_digest, load_json,
                         read_split, row_key, scorecard, write_json)
from .traffic import VERSION, feature_rows, load_rows, renamed_inputs, selected_features

FAMILIES = ("protocol_evidence", "statistics", "combined")
IMAGE = "zeek/zeek@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_digest():
    h = hashlib.sha256(inference_digest().encode())
    for name in ("traffic.py", "traffic_study.py"):
        h.update(Path(__file__).with_name(name).read_bytes())
    return h.hexdigest()


def dataset(manifest):
    manifest = Path(manifest).resolve()
    recordings, labels, instances = read_split(manifest)
    rows, provenance = [], []
    for entry in load_json(manifest)["recordings"]:
        path = (manifest.parent / entry["recording"]).resolve()
        record, _, extracted = load_rows(path)
        rows.extend(row for row in extracted if row_key(row) in labels)
        provenance.append({"recording": str(path), "sha256": digest(path),
                           "scope": record["scope"], "canonical_flows": len(record["flows"])})
    return {"recordings": recordings, "labels": labels, "instances": instances,
            "rows": rows, "manifest": str(manifest), "manifest_sha256": digest(manifest),
            "provenance": provenance}


def disjoint(left, right):
    digests = lambda data: {record["digest"] for record in data["recordings"].values() if record.get("digest")}
    if (left["recordings"].keys() & right["recordings"].keys() or
            left["instances"] & right["instances"] or digests(left) & digests(right)):
        raise ValueError("Splits must contain separate recordings, digests and emulator instances")


def scores(model, rows):
    features = model["vectorizer"].transform([selected_features(row, model["family"]) for row in rows])
    probabilities = model["forest"].predict_proba(features)
    return [(str(model["forest"].classes_[values.argmax()]), float(values.max())) for values in probabilities]


def decision(row, fitted, threshold, family):
    category, probability = fitted
    if row["presence"] != "observed_transmitting" or not row["traffic_features"]["flow_count"]:
        return UNKNOWN, "no_attributed_transmission"
    if family == "protocol_evidence" and not row["protocols"]:
        return UNKNOWN, "no_confirmed_medical_protocol"
    if category == OTHER:
        return UNKNOWN, "learned_supporting_category"
    if probability < threshold:
        return UNKNOWN, "below_validation_threshold"
    return category, "score_meets_validation_threshold"


def card(data, model, threshold):
    rows = data["rows"]
    return scorecard([data["labels"][row_key(row)] for row in rows], [decision(
        row, fitted, threshold, model["family"])[0] for row, fitted in zip(rows, scores(model, rows), strict=True)])


def fit(root, output):
    from joblib import dump
    from sklearn import __version__ as sklearn_version
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_extraction import DictVectorizer

    if output.exists():
        raise ValueError("Use a new output directory to preserve existing experiments")
    training, validation = dataset(root / "training.json"), dataset(root / "validation.json")
    disjoint(training, validation)
    output.mkdir(parents=True)
    protocol = {
        "version": VERSION, "experiment": "exploratory_feature_comparison",
        "families": list(FAMILIES), "seed": 4057, "sklearn_version": sklearn_version,
        "forest_parameters": {"n_estimators": 200, "min_samples_leaf": 2, "class_weight": "balanced", "n_jobs": 1},
        "threshold_selection": "maximize validation macro F1; tie fewer wrong, then higher threshold",
        "test_policy": "score every predeclared family once; no test-driven feature or threshold changes",
        "comparison_limit": "existing test recordings were already used by the preceding study; this is an exploratory ablation",
        "promotion": "no production policy change",
        "external_data_used": False,
        "statistics_gate": "observed transmitter and nonzero canonical flow count; no HL7/DICOM requirement",
        "protocol_gate": "observed transmitter and confirmed outgoing HL7/DICOM",
        "feature_exclusions": ["IP", "MAC", "ports", "AE titles", "sender names", "registry roles", "recording IDs", "absolute timestamps"],
        "byte_definition": "canonical Zeek transport payload bytes; never sum duplicate link observations",
        "limitations": ["one endpoint row per recording, not one row per packet",
                        "packet-size distribution and packet IAT are not reconstructed from flow totals",
                        "no domain-shift guarantee from a Random Forest probability"],
        "source_sha256": source_digest(),
        "training": {"manifest": training["manifest"], "sha256": training["manifest_sha256"],
                     "sessions": len(training["recordings"]), "rows": len(training["rows"]),
                     "support": dict(Counter(training["labels"].values()))},
        "validation": {"manifest": validation["manifest"], "sha256": validation["manifest_sha256"],
                       "sessions": len(validation["recordings"]), "rows": len(validation["rows"])},
        "input_recordings": training["provenance"] + validation["provenance"],
    }
    write_json(output / "protocol.json", protocol)
    results = {}
    for family in FAMILIES:
        started = time.perf_counter()
        vectorizer = DictVectorizer(sparse=False)
        matrix = vectorizer.fit_transform([selected_features(row, family) for row in training["rows"]])
        forest = RandomForestClassifier(n_estimators=200, min_samples_leaf=2, class_weight="balanced",
                                        random_state=4057, n_jobs=1)
        forest.fit(matrix, [training["labels"][row_key(row)] for row in training["rows"]])
        fit_seconds = time.perf_counter() - started
        model = {"family": family, "forest": forest, "vectorizer": vectorizer,
                 "source_sha256": protocol["source_sha256"], "version": VERSION}
        fitted = scores(model, validation["rows"])
        actual = [validation["labels"][row_key(row)] for row in validation["rows"]]
        trials = []
        for threshold in sorted({0.0, 1.000001, *(score for _, score in fitted)}):
            report = scorecard(actual, [decision(row, scored, threshold, family)[0]
                                       for row, scored in zip(validation["rows"], fitted, strict=True)])
            trials.append((report["macro_f1"], -report["incorrect"], threshold, report))
        _, _, threshold, report = max(trials, key=lambda trial: trial[:3])
        model["threshold"] = threshold
        file = output / f"{family}.joblib"
        dump(model, file)
        results[family] = {"threshold": threshold, "validation": report, "training": card(training, model, threshold),
                           "fit_seconds": fit_seconds, "model_bytes": file.stat().st_size, "model_sha256": digest(file),
                           "features": list(vectorizer.get_feature_names_out())}
        print(f"{family}: validation F1={report['macro_f1']:.3f}, {fit_seconds:.3f}s", flush=True)
    # This candidate is fixed using validation alone, before evaluate reads test.
    winner = max(FAMILIES, key=lambda name: (results[name]["validation"]["macro_f1"],
                                            -results[name]["validation"]["incorrect"], -FAMILIES.index(name)))
    write_json(output / "selection.json", {"source_sha256": source_digest(), "candidate": winner,
               "models": results, "external_data_used": False, "production_model_changed": False})


def load_models(output):
    from joblib import load

    selection = load_json(output / "selection.json")
    if selection["source_sha256"] != source_digest():
        raise ValueError("Comparison source changed after fitting")
    models = {}
    for family in FAMILIES:
        path = output / f"{family}.joblib"
        if digest(path) != selection["models"][family]["model_sha256"]:
            raise ValueError("Saved comparison model hash differs")
        models[family] = load(path)
    return selection, models


def evaluate_comparison(root, model_dir, output):
    from joblib import load

    if output.exists():
        raise ValueError("Use a new evaluation directory")
    selection, models = load_models(model_dir)
    training, validation, test = (dataset(root / f"{split}.json") for split in ("training", "validation", "test"))
    protocol = load_json(model_dir / "protocol.json")
    for name, current in (("training", training), ("validation", validation)):
        if protocol[name]["sha256"] != current["manifest_sha256"] or protocol[name]["manifest"] != current["manifest"]:
            raise ValueError("Evaluation must use the original fit manifests")
    if protocol["input_recordings"] != training["provenance"] + validation["provenance"]:
        raise ValueError("Fit recordings changed since model selection")
    disjoint(training, test)
    disjoint(validation, test)
    baseline = load(root / "model" / "model.joblib")
    baseline_report, baseline_predictions = evaluate(root / "test.json", baseline)
    base_by_key = {row_key(row): row for row in baseline_predictions}
    cards = {family: card(test, model, model["threshold"]) for family, model in models.items()}
    cards["existing_raw_forest"] = baseline_report["methods"]["forest"]
    cards["rules"] = baseline_report["methods"]["rules"]
    predictions, invariance, profiles = [], [], {}
    for entry in load_json(root / "test.json")["recordings"]:
        record, flows, rows = load_rows(root / entry["recording"])
        changed_record, changed_flows = renamed_inputs(record, flows)
        changed_rows = feature_rows(changed_record, changed_flows)
        checks = {}
        family_scores = {family: scores(model, rows) for family, model in models.items()}
        for family, model in models.items():
            original = [selected_features(row, family) for row in rows]
            renamed = [selected_features(row, family) for row in changed_rows]
            checks[family] = original == renamed and family_scores[family] == scores(model, changed_rows)
        invariance.append({"scope": record["scope"], "passed": all(checks.values()), "families": checks})
        if not all(checks.values()):
            raise ValueError("Identifier/time renaming changed features or scores")
        group = []
        for index, row in enumerate(rows):
            if row_key(row) not in test["labels"]:
                continue
            outputs = {}
            for family, model in models.items():
                fitted = family_scores[family][index]
                predicted, reason = decision(row, fitted, model["threshold"], family)
                outputs[family] = {"category": predicted, "score": fitted[1], "reason": reason}
            outputs["existing_raw_forest"] = base_by_key[row_key(row)]["decisions"]["forest"]
            category, reason = rule(row)
            outputs["rules"] = {"category": category, "reason": reason}
            truth = test["labels"][row_key(row)]
            prediction = {"source_id": row["source_id"], "scope": row["scope"], "ip": row["ip"],
                          "actual": truth, "decisions": outputs, "evidence": row["references"]}
            predictions.append(prediction)
            group.append(prediction)
        if entry.get("profile"):
            profiles.setdefault(entry["profile"], []).extend(group)
    increments = {}
    for family in FAMILIES:
        added = Counter()
        truths, outcomes = [], []
        for row in predictions:
            truth, outputs = row["actual"], row["decisions"]
            predicted = outputs["rules"]["category"]
            if predicted == UNKNOWN:
                predicted = outputs[family]["category"]
                added["still_unknown" if predicted == UNKNOWN else
                      "additional_correct" if predicted == truth else "additional_wrong"] += 1
            truths.append(truth)
            outcomes.append(predicted)
        increments[family] = {key: added[key] for key in ("additional_correct", "additional_wrong", "still_unknown")}
        cards["rules_with_" + family] = scorecard(truths, outcomes)
    report = {"version": VERSION, "candidate_chosen_on_validation": selection["candidate"],
              "test_sessions": len(test["recordings"]), "test_rows": len(predictions),
              "medical_categories": 10, "methods": cards, "fallback_increment": increments,
              "identifier_and_time_invariance": invariance,
              "profiles": {name: {method: scorecard([row["actual"] for row in rows], [
                  row["decisions"][method]["category"] for row in rows])
                  for method in (*FAMILIES, "existing_raw_forest", "rules")} for name, rows in profiles.items()},
              "test_inputs": test["provenance"], "external_data_evaluated": False,
              "comparison_limit": protocol["comparison_limit"], "production_model_changed": False}
    output.mkdir(parents=True)
    write_json(output / "report.json", report)
    write_json(output / "predictions.json", {"predictions": predictions})
    for name, report in cards.items():
        print(f"{name}: F1={report['macro_f1']:.3f} correct={report['correct']} wrong={report['incorrect']} unknown={report['abstained']}", flush=True)


def import_pcap(pcaps, output, tshark, model_dir=None):
    """Audit one independently recorded external session, without inventing labels."""
    from module2.pipeline import Pipeline
    from module2.store import Store
    from .local_sensor import docker_zeek
    from .replay import project

    paths = [Path(path).resolve(strict=True) for path in pcaps]
    if len(paths) != len(set(paths)):
        raise ValueError("Duplicate input PCAP paths")
    if any(path.stat().st_size > 32 * 1024 * 1024 for path in paths):
        raise ValueError("Each PCAP must be <=32 MiB; split a large recording into chunks kept in the same session")
    if output.exists():
        raise ValueError("Use a new output directory")
    if model_dir:
        _, models = load_models(model_dir)
    else:
        models = {}
    analysis = output.resolve() / "analysis"
    analysis.mkdir(parents=True)
    store = Store(analysis / "monitoring.sqlite3")
    sensor = None
    sources = []
    try:
        sensor = docker_zeek(IMAGE, tshark, analysis)
        pipeline = Pipeline(store, analysis, sensor)
        scope = "public-profiling-sample"
        for index, path in enumerate(paths):
            imported = pipeline.import_file(path, f"capture-{index}", scope)
            sources.append({"input": str(path), "sha256": imported["sha256"], "bytes": imported["bytes"],
                            "capture_id": imported["capture_id"], "frames": imported["frames"]})
        record = project(store, scope, analysis)
        write_json(output / "recording.json", record)
    finally:
        if sensor:
            sensor.close()
        store.close()
    record, _, rows = load_rows(output / "recording.json")
    fitted = {family: scores(model, rows) for family, model in models.items()} if rows else {}
    audit = []
    for index, row in enumerate(rows):
        predictions = {}
        for family, model in models.items():
            predicted, reason = decision(row, fitted[family][index], model["threshold"], family)
            predictions[family] = {"category": predicted, "score": fitted[family][index][1], "reason": reason}
        audit.append({"ip": row["ip"], "presence": row["presence"], "traffic_features": row["traffic_features"],
                      "medical_protocols": sorted(row["protocols"]), "predictions": predictions})
    write_json(output / "sample-audit.json", {
        "version": VERSION, "inputs": sources, "sensor_versions": sensor.versions,
        "canonical_flows": len(record["flows"]), "endpoints": audit,
        "label_status": "unverified; filenames and attack labels are not medical category labels",
        "accuracy_computed": False, "used_for_training": False,
        "next_requirement": "review publisher device identity and session provenance before assigning labels",
    })
    print(f"Imported {len(paths)} PCAP(s), {len(record['flows'])} canonical flows, {len(rows)} unlabelled endpoints", flush=True)


def main():
    from config import tshark_path

    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    fitting = commands.add_parser("fit")
    fitting.add_argument("--root", type=Path, required=True)
    fitting.add_argument("--output", type=Path, required=True)
    scoring = commands.add_parser("evaluate")
    scoring.add_argument("--root", type=Path, required=True)
    scoring.add_argument("--models", type=Path, required=True)
    scoring.add_argument("--output", type=Path, required=True)
    importing = commands.add_parser("import-pcap")
    importing.add_argument("--pcap", nargs="+", type=Path, required=True)
    importing.add_argument("--output", type=Path, required=True)
    importing.add_argument("--tshark", default=tshark_path())
    importing.add_argument("--models", type=Path)
    args = parser.parse_args()
    if args.command == "fit":
        fit(args.root, args.output)
    elif args.command == "evaluate":
        evaluate_comparison(args.root, args.models, args.output)
    else:
        import_pcap(args.pcap, args.output, args.tshark, args.models)


if __name__ == "__main__":
    main()
