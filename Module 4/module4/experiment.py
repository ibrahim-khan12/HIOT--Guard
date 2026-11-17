"""Train and score the device classifier using recording-separated ground truth."""
from collections import Counter
from copy import deepcopy
import hashlib
import ipaddress
import json
from pathlib import Path

from . import MEDICAL, OTHER, UNKNOWN
from .classifier import baseline, endpoint_rows, rule

VERSION = "module4-v1"
METHODS = ("protocol", "rules", "forest", "fallback")
LABELS = (*MEDICAL, OTHER)


def inference_digest():
    digest = hashlib.sha256()
    for name in ("__init__.py", "classifier.py", "experiment.py"):
        digest.update(Path(__file__).with_name(name).read_bytes())
    return digest.hexdigest()


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path, data):
    with Path(path).open("x", encoding="utf-8") as output:
        json.dump(data, output, indent=2, allow_nan=False)
        output.write("\n")


def recording_key(data):
    return data["source_id"], data["scope"]


def row_key(row):
    return (*recording_key(row), row["ip"])


def read_split(manifest_path):
    manifest = load_json(manifest_path)
    base = Path(manifest_path).parent
    recordings, labels, instances = {}, {}, set()
    digests = set()
    for session in manifest["recordings"]:
        record = load_json(base / session["recording"])
        key = recording_key(record)
        digest = record.get("digest")
        if key in recordings or (digest and digest in digests):
            raise ValueError(f"Duplicate recording {key}")
        if digest:
            digests.add(digest)
        recordings[key] = record
        observed = {row["ip"] for row in endpoint_rows(record)}
        expected = set()
        session_labels = set()
        for entry in session["endpoints"]:
            ip, label, instance = entry["ip"], entry["category"], entry["instance_id"]
            if label not in LABELS or (*key, ip) in labels or instance in instances:
                raise ValueError(f"Invalid or duplicate ground-truth endpoint {entry}")
            labels[(*key, ip)] = label
            instances.add(instance)
            expected.add(ip)
            session_labels.add(label)
        if missing_categories := set(LABELS) - session_labels:
            raise ValueError(f"Recording {key} is missing ground-truth classes: {sorted(missing_categories)}")
        if missing := expected - observed:
            raise ValueError(f"Recording {key} is missing ground-truth endpoints: {sorted(missing)}")
    if not labels:
        raise ValueError("A split needs labeled endpoints")
    return recordings, labels, instances


def check_coverage(labels, name):
    if missing := set(LABELS) - set(labels.values()):
        raise ValueError(f"{name} is missing categories: {sorted(missing)}")


def fitted_scores(model, rows):
    features = model["vectorizer"].transform([row["features"] for row in rows])
    probabilities = model["forest"].predict_proba(features)
    classes = model["forest"].classes_
    result = []
    for scores in probabilities:
        index = scores.argmax()
        result.append((str(classes[index]), float(scores[index])))
    return result


def forest_decision(row, scored, threshold):
    category, score = scored
    if row["presence"] != "observed_transmitting" or not row["protocols"]:
        return UNKNOWN, "insufficient_attributed_protocol_evidence"
    if category == OTHER:
        return UNKNOWN, "outside_medical_categories"
    if score < threshold:
        return UNKNOWN, "below_validation_threshold"
    return category, "forest_score_meets_threshold"


def scorecard(expected, predictions):
    matrix = {label: dict.fromkeys((*MEDICAL, UNKNOWN), 0) for label in LABELS}
    counts = Counter()
    for actual, predicted in zip(expected, predictions, strict=True):
        matrix[actual][predicted] += 1
        outcome = "abstained" if predicted == UNKNOWN else "correct" if actual == predicted else "incorrect"
        counts[outcome] += 1
    classes = {}
    for label in MEDICAL:
        support = sum(matrix[label].values())
        tp = matrix[label][label]
        total_calls = sum(matrix[actual][label] for actual in LABELS)
        precision = tp / total_calls if total_calls else 0.0
        recall = tp / support if support else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        classes[label] = {"precision": precision, "recall": recall, "f1": f1, "support": support}
    return {"macro_f1": sum(row["f1"] for row in classes.values()) / len(MEDICAL),
            "coverage": (counts["correct"] + counts["incorrect"]) / len(expected) if expected else 0.0,
            "correct": counts["correct"], "incorrect": counts["incorrect"], "abstained": counts["abstained"],
            "classes": classes, "confusion": matrix}


def split_rows(recordings, labels):
    return [row for record in recordings.values() for row in endpoint_rows(record) if row_key(row) in labels]


def train(train_path, validation_path, output):
    from joblib import dump
    from sklearn import __version__ as sklearn_version
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_extraction import DictVectorizer

    training, train_labels, train_instances = read_split(train_path)
    validation, validation_labels, validation_instances = read_split(validation_path)
    for name, labels in (("Training", train_labels), ("Validation", validation_labels)):
        check_coverage(labels, name)
    train_digests = {record["digest"] for record in training.values() if record.get("digest")}
    valid_digests = {record["digest"] for record in validation.values() if record.get("digest")}
    if training.keys() & validation.keys() or train_instances & validation_instances or train_digests & valid_digests:
        raise ValueError("Training and validation must use separate recordings and emulator instances")
    rows = split_rows(training, train_labels)
    valid = split_rows(validation, validation_labels)
    vectorizer = DictVectorizer(sparse=False)
    features = vectorizer.fit_transform([row["features"] for row in rows])
    forest = RandomForestClassifier(n_estimators=200, min_samples_leaf=2, class_weight="balanced",
                                    random_state=4057, n_jobs=1)
    forest.fit(features, [train_labels[row_key(row)] for row in rows])
    model = {"version": VERSION, "sklearn_version": sklearn_version, "forest": forest, "vectorizer": vectorizer,
             "fit_recordings": sorted((*training, *validation)), "fit_instances": sorted(train_instances | validation_instances),
             "fit_digests": sorted(train_digests | valid_digests), "inference_sha256": inference_digest()}
    scored = fitted_scores(model, valid)
    actual = [validation_labels[row_key(row)] for row in valid]
    trials = []
    for threshold in sorted({0.0, 1.000001, *(value for _, value in scored)}):
        labels = [forest_decision(row, fit, threshold)[0] for row, fit in zip(valid, scored)]
        card = scorecard(actual, labels)
        trials.append((card["macro_f1"], -card["incorrect"], threshold, card))
    _, _, threshold, validation_card = max(trials, key=lambda trial: trial[:3])
    model["threshold"] = threshold
    output.mkdir(parents=True)
    dump(model, output / "model.joblib")
    report = {"version": VERSION, "sklearn_version": sklearn_version, "threshold": threshold,
              "seed": 4057, "train_rows": len(rows), "validation_rows": len(valid),
              "train_sessions": len(training), "validation_sessions": len(validation),
              "train_support": dict(Counter(train_labels.values())),
              "validation_support": dict(Counter(validation_labels.values())),
              "inference_sha256": model["inference_sha256"],
              "features": list(vectorizer.get_feature_names_out()), "validation": validation_card,
              "model_sha256": hashlib.sha256((output / "model.joblib").read_bytes()).hexdigest()}
    write_json(output / "training.json", report)
    return report


def decisions(record, model):
    rows = endpoint_rows(record)
    if not rows:
        return []
    output = []
    for row, fitted in zip(rows, fitted_scores(model, rows), strict=True):
        base, base_reason = baseline(row)
        category, rule_reason = rule(row)
        label, forest_reason = forest_decision(row, fitted, model["threshold"])
        methods = {
            "protocol": (base, base_reason, None),
            "rules": (category, rule_reason, None),
            "forest": (label, forest_reason, fitted[1]),
            "fallback": (label, forest_reason, fitted[1]) if category == UNKNOWN else (category, rule_reason, None),
        }
        output.append({key: row[key] for key in ("source_id", "scope", "asset_id", "ip")} | {
            "protocol_groups": sorted(row["protocols"]), "evidence": row["references"],
            "decisions": {name: {"category": result, "reason": reason, "score": score,
                                 "method": name, "version": model["version"]}
                          for name, (result, reason, score) in methods.items()}})
    return output


def check_identifiers(record, model, predictions):
    renamed = deepcopy(record)
    renamed["source_id"], renamed["scope"] = "renamed-source", "renamed-scope"
    addresses = {asset["ip"] for asset in renamed["assets"]}
    for flow in renamed["flows"]:
        addresses.update((flow["source_ip"], flow["destination_ip"]))
    alias = {ip: str(ipaddress.IPv6Address(0x20010db8000000000000000000000000 + index))
             for index, ip in enumerate(sorted(addresses), 1)}
    for index, asset in enumerate(renamed["assets"], 1):
        asset.update(ip=alias[asset["ip"]], asset_id=f"renamed-asset-{index}",
                     configured={"role": "renamed-role"}, mac="02:00:00:00:00:01")
    for index, flow in enumerate(renamed["flows"], 1):
        flow.update(source_ip=alias[flow["source_ip"]], destination_ip=alias[flow["destination_ip"]],
                    flow_id=f"renamed-flow-{index}", observation_source="renamed-sensor")
        for event in flow["evidence"]:
            event["capture_id"] = "renamed-capture"
            event["metadata"].update(sender="renamed", calling_ae="renamed", called_ae="renamed")
    return [row["decisions"] for row in predictions] == [row["decisions"] for row in decisions(renamed, model)]


def evaluate(holdout_path, model):
    if model["inference_sha256"] != inference_digest():
        raise ValueError("Inference source changed after training")
    holdout, labels, instances = read_split(holdout_path)
    check_coverage(labels, "Holdout")
    digests = {record["digest"] for record in holdout.values() if record.get("digest")}
    if (holdout.keys() & {tuple(key) for key in model["fit_recordings"]}
            or instances & set(model["fit_instances"]) or digests & set(model["fit_digests"])):
        raise ValueError("Holdout overlaps training or validation")
    predictions, identifier_checks = [], []
    for record in holdout.values():
        rows = decisions(record, model)
        identifier_checks.append({"scope": record["scope"], "passed": check_identifiers(record, model, rows)})
        predictions.extend(rows)
    labeled = [row for row in predictions if row_key(row) in labels]
    actual = [labels[row_key(row)] for row in labeled]
    cards = {method: scorecard(actual, [row["decisions"][method]["category"] for row in labeled]) for method in METHODS}
    added = Counter()
    for row, expected in zip(labeled, actual, strict=True):
        if row["decisions"]["rules"]["category"] == UNKNOWN:
            label = row["decisions"]["fallback"]["category"]
            outcome = "still_unknown" if label == UNKNOWN else "additional_correct" if label == expected else "additional_wrong"
            added[outcome] += 1
    report = {"version": VERSION, "threshold": model["threshold"], "holdout_sessions": len(holdout),
              "labeled_endpoints": len(labeled), "unlabeled_endpoints": len(predictions) - len(labeled),
              "target": {"method": "forest", "macro_f1": 0.70, "passed": cards["forest"]["macro_f1"] >= 0.70},
              "identifier_invariance": identifier_checks,
              "methods": cards, "fallback_increment": {key: added[key] for key in
                  ("additional_correct", "additional_wrong", "still_unknown")}}
    return report, predictions
