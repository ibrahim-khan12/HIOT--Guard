"""Fit and evaluate Module 4 policies on separated packet-backed GNS3 cohorts."""
import argparse
from collections import Counter, defaultdict
import hashlib
from pathlib import Path
import time

import numpy as np
from joblib import dump, load
from sklearn import __version__ as sklearn_version
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.model_selection import GroupKFold
from threadpoolctl import threadpool_limits

from . import MEDICAL, OTHER, UNKNOWN
from .experiment import inference_digest, load_json, scorecard, write_json
from .final_study_data import (FIT_SPLITS, TEST_SPLITS, SPLITS, WINDOWS, SEMANTIC_NAMES, TRAFFIC_NAMES,
                              WORKFLOW_CANDIDATES, ensure_disjoint, file_digest, read_split, verify_batch_captures)


VERSION = 'module4-final-v1'
SEED = 4057
TEMPERATURES = (0.5, 0.65, 0.8, 1.0, 1.25, 1.6, 2.0, 2.5, 3.0)
CURVE_THRESHOLDS = (0.0, 0.3, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 1.0, 1.01)
FAMILIES = {'semantics': sorted(SEMANTIC_NAMES), 'traffic': sorted(TRAFFIC_NAMES),
            'combined': sorted(SEMANTIC_NAMES | TRAFFIC_NAMES)}
ESTIMATOR_GRID = {
    'rf': ({'min_samples_leaf': 5}, {'min_samples_leaf': 2}),
    'hgb': ({'max_leaf_nodes': 7}, {'max_leaf_nodes': 15}),
}


def source_digest():
    digest = hashlib.sha256(inference_digest().encode())
    for name in ('final_study.py', 'final_study_data.py', 'evidence_v2.py', 'forwarding_study.py'):
        digest.update(Path(__file__).with_name(name).read_bytes())
    return digest.hexdigest()


def raw_label(label):
    return UNKNOWN if label == OTHER else str(label)


def card(truth, labels):
    result = scorecard(truth, labels)
    supporting = sum(label == OTHER for label in truth)
    false_medical = sum(actual == OTHER and label != UNKNOWN for actual, label in zip(truth, labels, strict=True))
    assignments = result['correct'] + result['incorrect']
    result.update({'labelled_endpoints': len(truth), 'supporting_endpoints': supporting,
                   'supporting_false_medical': false_medical,
                   'supporting_false_medical_rate': false_medical / supporting if supporting else None,
                   'assigned_precision': result['correct'] / assignments if assignments else None,
                   'selective_risk': result['incorrect'] / assignments if assignments else None})
    return result


def evidence(row):
    """Restrict identity claims to identifiable evidence in the declared lab setting."""
    features = row['features']
    if features.get('coverage_sufficient') != 1:
        return UNKNOWN, 0, 'insufficient_observation_coverage'
    if any(value > 0 for name, value in features.items() if name.startswith('forwarded_')):
        return UNKNOWN, 0, 'observed_cross_link_forwarding'
    workflows = {name: features.get('accepted_' + name, 0) for name in WORKFLOW_CANDIDATES}
    active = {name for name, total in workflows.items() if total > 0}
    if not active:
        return UNKNOWN, 0, 'no_supported_acknowledged_workflow'
    if len(active) != 1:
        return UNKNOWN, 0, 'conflicting_acknowledged_workflows'
    workflow = next(iter(active))
    if len(WORKFLOW_CANDIDATES[workflow]) > 1:
        return UNKNOWN, 0, 'shared_heart_rate_evidence' if workflow == 'heart_rate' else 'shared_digital_xray_evidence'
    return WORKFLOW_CANDIDATES[workflow][0], workflows[workflow], 'unique_candidate_in_lab_scope'


def rule_decision(candidate):
    return candidate[0] if candidate[1] >= 2 else UNKNOWN


def model_decision(candidate, label, confidence, threshold):
    if candidate[0] == UNKNOWN:
        return UNKNOWN, candidate[2]
    if label != candidate[0]:
        return UNKNOWN, 'model_and_workflow_disagree'
    if confidence < threshold:
        return UNKNOWN, 'below_validation_threshold'
    return str(label), 'model_agrees_with_acknowledged_workflow'


def increment(truth, rules, fallback):
    result = Counter()
    for actual, rule, final in zip(truth, rules, fallback, strict=True):
        if rule == UNKNOWN:
            key = 'still_unknown' if final == UNKNOWN else ('additional_correct' if final == actual else 'additional_wrong')
            result[key] += 1
    return {key: result[key] for key in ('additional_correct', 'additional_wrong', 'still_unknown')}


def matrix(rows, family):
    features = FAMILIES[family]
    return np.array([[row['features'].get(name, 0) for name in features] for row in rows], dtype=float)


def estimator(algorithm, parameters=None):
    if parameters is None:
        parameters = ESTIMATOR_GRID[algorithm][0]
    if algorithm == 'rf':
        return RandomForestClassifier(n_estimators=120, class_weight='balanced',
                                      random_state=SEED, n_jobs=1, **parameters)
    return HistGradientBoostingClassifier(max_iter=80, min_samples_leaf=8,
                                          l2_regularization=1, early_stopping=False,
                                          class_weight='balanced', random_state=SEED, **parameters)


def probabilities(model, features):
    with threadpool_limits(limits=1):
        return model.predict_proba(features)


def temperature_scale(probability, temperature):
    if temperature == 1:
        return probability
    logits = np.log(np.clip(probability, 1e-12, 1)) / temperature
    weights = np.exp(logits - logits.max(axis=1, keepdims=True))
    return weights / weights.sum(axis=1, keepdims=True)


def probability_metrics(probability, classes, truth):
    class_index = {label: index for index, label in enumerate(classes)}
    actual = np.array([class_index[label] for label in truth])
    predictions = probability.argmax(axis=1)
    confidence = probability.max(axis=1)
    accurate = predictions == actual
    nll = -np.log(np.clip(probability[np.arange(len(actual)), actual], 1e-12, 1)).mean()
    one_hot = np.eye(len(classes))[actual]
    brier = np.mean(np.sum(np.square(probability - one_hot), axis=1))
    bins = []
    ece = 0.0
    for start in range(10):
        lower, upper = start / 10, (start + 1) / 10
        mask = (confidence >= lower) & ((confidence < upper) if start < 9 else (confidence <= upper))
        count = int(mask.sum())
        if count:
            conf, acc = float(confidence[mask].mean()), float(accurate[mask].mean())
            ece += count * abs(conf - acc) / len(actual)
            bins.append({'range': [lower, upper], 'rows': count, 'mean_confidence': conf, 'accuracy': acc})
    return {'negative_log_likelihood': float(nll), 'multiclass_brier': float(brier),
            'ece_10_bins': ece, 'reliability_bins': bins}


def argmax(probability, classes):
    return list(zip(classes[probability.argmax(axis=1)], probability.max(axis=1), strict=True))


def choose_threshold(truth, candidates, rules, fitted):
    trials = []
    for threshold in sorted({0.0, 1.01, *(float(value) for _, value in fitted)}):
        model = [model_decision(candidate, label, score, threshold)[0]
                 for candidate, (label, score) in zip(candidates, fitted, strict=True)]
        fallback = [rule if rule != UNKNOWN else prediction for rule, prediction in zip(rules, model, strict=True)]
        added = increment(truth, rules, fallback)
        # Freeze a comparable error budget using validation only. A model can
        # abstain at 1.01 if every alternative adds validation errors.
        if added['additional_wrong']:
            continue
        fallback_card, model_card = card(truth, fallback), card(truth, model)
        key = (fallback_card['macro_f1'], added['additional_correct'], model_card['macro_f1'],
               -model_card['incorrect'], threshold)
        trials.append((key, threshold, fallback_card, model_card, added))
    return max(trials, key=lambda entry: entry[0])


def tune(algorithm, features, labels, groups, partitions):
    variants = []
    for parameters in ESTIMATOR_GRID[algorithm]:
        folds = []
        for train_ids, valid_ids in partitions:
            model = estimator(algorithm, parameters)
            with threadpool_limits(limits=1):
                model.fit(features[train_ids], [labels[i] for i in train_ids])
                predicted = [raw_label(label) for label in model.predict(features[valid_ids])]
            folds.append({'holdout_capture_groups': sorted(set(groups[valid_ids])),
                          'raw_macro_f1': card([labels[i] for i in valid_ids], predicted)['macro_f1']})
        variants.append({'parameters': parameters, 'grouped_cv': folds,
                         'mean_raw_cv_macro_f1': sum(x['raw_macro_f1'] for x in folds) / len(folds)})
    # In a tie the preordered grid prefers the less flexible model.
    return max(variants, key=lambda variant: variant['mean_raw_cv_macro_f1']), variants


def unseen_category_diagnostic(train, validation, artifact):
    """Leave out each medical class using development data only."""
    outcomes = {}
    for label in MEDICAL:
        available = [row for row in train if row['label'] != label]
        unseen = [row for row in validation if row['label'] == label]
        model = estimator(artifact['algorithm'], artifact['parameters'])
        with threadpool_limits(limits=1):
            model.fit(matrix(available, artifact['family']), [row['label'] for row in available])
            predictions = model.predict(matrix(unseen, artifact['family']))
        outcomes[label] = {'validation_examples': len(unseen),
                           'raw_assigned_as_other_medical': sum(raw_label(value) != UNKNOWN for value in predictions),
                           'workflow_guard_rejected': sum(model_decision(evidence(row), value, 1.0, 0.0)[0] == UNKNOWN
                                                          for row, value in zip(unseen, predictions, strict=True))}
    return {'purpose': 'diagnostic on validation only; excluded from model and threshold selection', 'per_withheld_category': outcomes}


def fit_candidates(train, calibration, validation):
    labels = [row['label'] for row in train]
    cal_truth = [row['label'] for row in calibration]
    val_truth = [row['label'] for row in validation]
    groups = np.array([row['capture_group'] for row in train])
    group_count = len(set(groups))
    if group_count < 2:
        raise ValueError('Grouped training cross-validation needs at least two independent capture groups')
    partitions = list(GroupKFold(n_splits=min(5, group_count)).split(train, labels, groups=groups))
    candidates = [evidence(row) for row in validation]
    rules = [rule_decision(candidate) for candidate in candidates]
    model_artifacts, results, best = {}, {}, None
    for family in FAMILIES:
        train_features, cal_features, val_features = (matrix(rows, family) for rows in (train, calibration, validation))
        for algorithm in ('rf', 'hgb'):
            name = f'{algorithm}_{family}'
            tuned, grid = tune(algorithm, train_features, labels, groups, partitions)
            parameters = tuned['parameters']
            model = estimator(algorithm, parameters)
            with threadpool_limits(limits=1):
                model.fit(train_features, labels)
            cal_probability = probabilities(model, cal_features)
            cal_trials = {value: probability_metrics(temperature_scale(cal_probability, value), model.classes_, cal_truth)
                          for value in TEMPERATURES}
            fitted_temperature = min(TEMPERATURES, key=lambda value: (cal_trials[value]['negative_log_likelihood'], abs(value - 1)))
            val_probability = probabilities(model, val_features)
            options = {}
            for temperature in sorted({1.0, fitted_temperature}):
                probs = temperature_scale(val_probability, temperature)
                val_metrics = probability_metrics(probs, model.classes_, val_truth)
                key, threshold, fallback, model_card, added = choose_threshold(val_truth, candidates, rules, argmax(probs, model.classes_))
                options[str(temperature)] = {'calibration_metrics': cal_trials[temperature], 'validation_probability_metrics': val_metrics,
                                             'threshold': threshold, 'fallback': fallback, 'guarded_model': model_card,
                                             'rule_abstention_increment': added}
                # Predictive performance and rule-abstention value precede
                # calibration loss. Calibration must also survive validation.
                rank = (*key[:-1], -val_metrics['negative_log_likelihood'], key[-1], temperature == 1, name)
                if best is None or rank > best[0]:
                    best = (rank, name, temperature, threshold)
            results[name] = {'family': family, 'algorithm': algorithm, 'features': FAMILIES[family],
                             'selection_from_grouped_cv': tuned, 'parameter_trials': grid,
                             'temperature_proposed_from_calibration': fitted_temperature, 'validation_options': options}
            model_artifacts[name] = {'estimator': model, 'family': family, 'algorithm': algorithm, 'parameters': parameters}
    _, name, temperature, threshold = best
    selected = {'candidate': name, 'temperature': temperature, 'threshold': threshold}
    return model_artifacts, {'selected': selected, 'validation_rules': card(val_truth, rules), 'candidates': results,
                             'development_open_set': unseen_category_diagnostic(train, validation, model_artifacts[name])}


def fit(dataset, output, counts, windows, primary):
    started = time.monotonic()
    splits = {name: read_split(dataset / (name + '.jsonl'), name, windows, counts[name]) for name in FIT_SPLITS}
    audit = {name: split.audit() for name, split in splits.items()}
    ensure_disjoint(audit)
    for item in audit.values():
        verify_batch_captures(dataset.parent / 'batches', item)
    primary_rows = [[row for row in splits[name].rows if row['window_seconds'] == primary] for name in FIT_SPLITS]
    models, validation = fit_candidates(*primary_rows)
    output.mkdir(parents=True, exist_ok=False)
    model_path = output / 'models.joblib'
    dump(models, model_path, compress=3)
    report = {'version': VERSION, 'sklearn_version': sklearn_version, 'seed': SEED, 'fitting_inputs': audit,
              'allocation': counts, 'windows_seconds': list(windows), 'primary_window_seconds': primary,
              'selection_basis': 'validation macro F1 with zero additional validation errors after rules abstain',
              'holdout_files_opened': [], 'inference_source_sha256': source_digest(),
              'artifact_sha256': file_digest(model_path), 'fit_seconds': time.monotonic() - started, **validation}
    write_json(output / 'selection.json', report)
    print(f'Frozen {validation["selected"]["candidate"]} with threshold {validation["selected"]["threshold"]:.6f}')
    return report


def paired_uncertainty(truth, rules, fallback, groups):
    by_group = defaultdict(list)
    for index, group in enumerate(groups):
        by_group[group].append(index)
    if len(by_group) < 3:
        return {'independent_capture_groups': len(by_group), 'ci95': None,
                'reason': 'fewer than three capture groups; endpoint and logical-session resampling would overstate independence'}
    samples = np.random.default_rng(SEED).integers(0, len(by_group), size=(500, len(by_group)))
    group_rows = list(by_group.values())
    changes = []
    for sample in samples:
        ids = [i for group in sample for i in group_rows[group]]
        actual = [truth[i] for i in ids]
        baseline = scorecard(actual, [rules[i] for i in ids])['macro_f1']
        augmented = scorecard(actual, [fallback[i] for i in ids])['macro_f1']
        changes.append(augmented - baseline)
    return {'independent_capture_groups': len(by_group), 'bootstrap_resamples': 500,
            'paired_fallback_minus_rules_macro_f1_ci95': [float(v) for v in np.quantile(changes, [.025, .975])]}


def score_window(rows, models, selection):
    truth = [row['label'] for row in rows]
    candidates = [evidence(row) for row in rows]
    rules = [rule_decision(candidate) for candidate in candidates]
    cards = {'updated_rules': card(truth, rules)}
    for name, artifact in models.items():
        model = artifact['estimator']
        raw = probabilities(model, matrix(rows, artifact['family']))
        cards['diagnostic_raw_' + name] = card(truth, [raw_label(label) for label, _ in argmax(raw, model.classes_)])
        if name == selection['candidate']:
            selected_raw, classes = raw, model.classes_
    selected = temperature_scale(selected_raw, selection['temperature'])
    fitted = argmax(selected, classes)
    decisions = [model_decision(candidate, label, conf, selection['threshold'])
                 for candidate, (label, conf) in zip(candidates, fitted, strict=True)]
    model_labels = [label for label, _ in decisions]
    fallback = [rule if rule != UNKNOWN else label for rule, label in zip(rules, model_labels, strict=True)]
    cards['guarded_model'] = card(truth, model_labels)
    cards['selected_fallback'] = card(truth, fallback)
    risk_coverage = []
    for threshold in CURVE_THRESHOLDS:
        labels = [rule if rule != UNKNOWN else model_decision(candidate, label, conf, threshold)[0]
                  for rule, candidate, (label, conf) in zip(rules, candidates, fitted, strict=True)]
        trial = card(truth, labels)
        risk_coverage.append({'threshold': threshold, 'assigned_coverage': trial['coverage'],
                              'selective_risk': trial['selective_risk'], 'macro_f1': trial['macro_f1'],
                              'supporting_false_medical_rate': trial['supporting_false_medical_rate']})
    groups = [row['capture_group'] for row in rows]
    group_metrics = {}
    for group in sorted(set(groups)):
        subset = [index for index, value in enumerate(groups) if value == group]
        a, r, f = ([values[i] for i in subset] for values in (truth, rules, fallback))
        group_metrics[group] = {'updated_rules': card(a, r), 'selected_fallback': card(a, f),
                                'rule_abstention_increment': increment(a, r, f)}
    result = {'methods': cards, 'rule_abstention_increment': increment(truth, rules, fallback),
              'selected_probability_diagnostics': probability_metrics(selected, classes, truth),
              'risk_coverage_diagnostic': risk_coverage, 'by_capture_group': group_metrics,
              'paired_uncertainty': paired_uncertainty(truth, rules, fallback, groups),
              'observation_coverage_sufficient_rows': sum(row['features'].get('coverage_sufficient') == 1 for row in rows)}
    predictions = []
    for row, candidate, rule, final, (label, reason), (raw, conf) in zip(rows, candidates, rules, fallback, decisions, fitted, strict=True):
        identifiers = {key: row[key] for key in ('session_id', 'capture_group', 'endpoint', 'label', 'window_seconds', 'captures')}
        predictions.append({**identifiers, 'rules': rule, 'rule_reason': candidate[2] if candidate[0] == UNKNOWN else (
            'two_accepted_exchanges' if rule != UNKNOWN else 'one_accepted_exchange'), 'guarded_model': label,
            'model_reason': reason, 'selected_candidate_argmax': str(raw), 'selected_confidence': float(conf), 'fallback': final})
    return result, predictions


def score(dataset, fitted, output):
    started = time.monotonic()
    frozen = load_json(fitted / 'selection.json')
    model_path = fitted / 'models.joblib'
    if (frozen['version'] != VERSION or frozen['inference_source_sha256'] != source_digest()
            or frozen['artifact_sha256'] != file_digest(model_path) or frozen['sklearn_version'] != sklearn_version):
        raise ValueError('Frozen model file, inference code or environment changed')
    for name, audit in frozen['fitting_inputs'].items():
        if file_digest(dataset / (name + '.jsonl')) != audit['sha256']:
            raise ValueError(f'Fitting input {name} differs from the frozen run')
    windows = tuple(frozen['windows_seconds'])
    primary = frozen['primary_window_seconds']
    counts = frozen['allocation']
    tests = {name: read_split(dataset / (name + '.jsonl'), name, windows, counts[name]) for name in TEST_SPLITS}
    audit = {name: split.audit() for name, split in tests.items()}
    ensure_disjoint({**frozen['fitting_inputs'], **audit})
    for item in audit.values():
        verify_batch_captures(dataset.parent / 'batches', item)
    # Joblib is reserved for the local fitting output whose digest was checked above.
    models = load(model_path)
    selection = frozen['selected']
    results, predictions = {}, []
    for name, split in tests.items():
        windows_results = {}
        for window in windows:
            report, decisions = score_window([row for row in split.rows if row['window_seconds'] == window], models, selection)
            windows_results[str(window)] = report
            predictions.extend(dict(row, split=name) for row in decisions)
        main = windows_results[str(primary)]['methods']['selected_fallback']
        results[name] = {'sessions': len(split.sessions), 'capture_groups': len(split.groups), 'windows': windows_results,
                         'primary_targets': {'macro_f1_at_least_0_70': main['macro_f1'] >= .70,
                                             'assigned_precision_at_least_0_95': main['assigned_precision'] is not None and main['assigned_precision'] >= .95,
                                             'supporting_false_medical_rate_at_most_0_05': main['supporting_false_medical_rate'] <= .05,
                                             'additional_correct_coverage_at_least_0_05': windows_results[str(primary)]['rule_abstention_increment']['additional_correct'] / main['labelled_endpoints'] >= .05}}
        print(f'{name}: {len(split.sessions)} sessions in {len(split.groups)} capture groups, '
              f'fallback macro F1={main["macro_f1"]:.3f}; {main["correct"]} correct, {main["incorrect"]} wrong, {main["abstained"]} unknown')
    report = {'version': VERSION, 'selected': selection, 'primary_window_seconds': primary, 'test_inputs': audit,
              'frozen_selection_sha256': file_digest(fitted / 'selection.json'), 'artifact_sha256': frozen['artifact_sha256'],
              'historical_baseline': {'status': 'separate', 'reason': 'Frozen v1 requires a compatible Module 3 v1 recording, not the transaction-window feature schema.'},
              'interpretation': 'Scope is the sampled synthetic lab workflows and sender implementations. Raw model variants are diagnostic. Supported workflow alone does not authenticate the physical device.',
              'cohorts': results, 'scoring_seconds': time.monotonic() - started}
    output.mkdir(parents=True, exist_ok=False)
    write_json(output / 'report.json', report)
    write_json(output / 'predictions.json', predictions)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ('fit', 'score'):
        sub = commands.add_parser(command)
        sub.add_argument('--dataset', required=True, type=Path)
        sub.add_argument('--output', required=True, type=Path)
        if command == 'fit':
            sub.add_argument('--windows', type=int, nargs='+', default=WINDOWS)
            sub.add_argument('--primary-window', type=int, default=120)
            sub.add_argument('--allocation', type=int, nargs=5, metavar=('TRAIN', 'CAL', 'VAL', 'FAMILIAR', 'TRANSFER'),
                             default=list(SPLITS.values()))
        else:
            sub.add_argument('--fitted', required=True, type=Path)
    args = parser.parse_args()
    if args.command == 'fit':
        if (args.primary_window not in args.windows or not set(args.windows) <= set(WINDOWS)
                or len(set(args.windows)) != len(args.windows) or min(args.allocation) < 1):
            parser.error('Invalid frozen windows or split allocation')
        fit(args.dataset, args.output, dict(zip(SPLITS, args.allocation, strict=True)), tuple(args.windows), args.primary_window)
    else:
        score(args.dataset, args.fitted, args.output)


if __name__ == '__main__':
    main()
