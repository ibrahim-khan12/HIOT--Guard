"""Independently audit split ownership, endpoint coverage and saved PCAP hashes."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from math import isclose
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from module2.pcap import MAGICS, complete_pcap
from module4 import MEDICAL


PLAN = {'train': (40, 'A', 4), 'calibration': (10, 'A', 1), 'validation': (10, 'A', 1),
        'familiar': (10, 'A', 1), 'transfer': (20, 'B', 2)}
WINDOWS = {10, 30, 60, 120}
EXPECTED_LABELS = {**dict.fromkeys(MEDICAL, 1), 'other': 5}


def pin(mapping, key, value, description):
    if mapping.setdefault(key, value) != value:
        raise ValueError(f'Conflicting {description} for {key}')


def packet_times(data):
    frame = struct.Struct(MAGICS[data[:4]] + 'IIII')
    precision = 1e9 if data[:4] in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d') else 1e6
    times = [None]  # Capture references are one-based.
    offset = 24
    while offset < len(data):
        seconds, fraction, captured, _ = frame.unpack_from(data, offset)
        times.append(seconds + fraction / precision)
        offset += frame.size + captured
    return times


def frame_time(index, digest, frames):
    if type(frames) is not list or not frames or any(type(frame) is not int or frame <= 0 for frame in frames):
        raise ValueError('Every evidence reference must contain positive integer frame numbers')
    if digest not in index or max(frames) >= len(index[digest]):
        raise ValueError('Evidence references a missing packet frame')
    return max(index[digest][frame] for frame in frames)


def audit_evidence(rows_dir, index):
    references = 0
    for split in PLAN:
        with (rows_dir / f'{split}.jsonl').open(encoding='utf-8') as stream:
            for line in stream:
                row = json.loads(line)
                local = {digest: index[digest] for digest in row['captures']}
                marker = row['observation_end']
                end = frame_time(local, marker['capture_sha256'], [marker['frame']])
                references += 1
                for evidence in row['flow_evidence']:
                    stamp = frame_time(local, evidence['capture_sha256'], evidence['frames'])
                    if stamp > end or not isclose(stamp, evidence['completed_at'], rel_tol=0, abs_tol=1e-6):
                        raise ValueError('Completed flow evidence does not match its recorded frames')
                    references += 1
                for pair in row['paired_evidence']:
                    times = {}
                    for side in ('upstream', 'downstream'):
                        event = pair[side]
                        for part in ('request', 'reply'):
                            ref = event[part]
                            stamp = frame_time(local, event['capture_sha256'], ref['frames'])
                            if not isclose(stamp, ref['completed_at'], rel_tol=0, abs_tol=1e-6):
                                raise ValueError('Forwarding evidence does not match its recorded frames')
                            times[side, part] = stamp
                            references += 1
                    if not (times['upstream', 'request'] <= times['downstream', 'request'] <= times['downstream', 'reply']
                            <= times['upstream', 'reply'] <= end):
                        raise ValueError('Forwarding evidence falls outside observed transaction order')
    return references


def audit(rows_dir, raw_dir):
    sessions, groups, captures = {}, {}, {}
    report = {'splits': {}, 'captures': {}, 'windows': sorted(WINDOWS)}
    for split, (expected_sessions, stack, expected_groups) in PLAN.items():
        path = rows_dir / f'{split}.jsonl'
        session_groups = {}
        by_window = defaultdict(Counter)
        endpoint_windows = defaultdict(set)
        endpoint_labels = {}
        with path.open(encoding='utf-8') as rows:
            for line, value in enumerate(rows, start=1):
                row = json.loads(value)
                if (row['split'], row['stack']) != (split, stack):
                    raise ValueError(f'Unexpected split or sender stack at {path.name}:{line}')
                session, group = row['session_id'], row['capture_group']
                pin(groups, group, split, 'split ownership for capture batch')
                pin(sessions, session, split, 'split ownership for session')
                pin(session_groups, session, group, 'capture batch for session')
                endpoint = (session, row['endpoint'])
                pin(endpoint_labels, endpoint, row['label'], 'ground-truth label')
                window = row['window_seconds']
                if window not in WINDOWS or window in endpoint_windows[endpoint]:
                    raise ValueError(f'Invalid or duplicate observation window at {path.name}:{line}')
                endpoint_windows[endpoint].add(window)
                by_window[(session, window)][row['label']] += 1
                if row['features'].get('coverage_sufficient') != 1:
                    raise ValueError(f'Insufficient observed coverage at {path.name}:{line}')
                if not row['captures']:
                    raise ValueError(f'Missing capture references at {path.name}:{line}')
                for digest in row['captures']:
                    pin(captures, digest, (split, group), 'capture split or batch ownership')
        if len(session_groups) != expected_sessions or len(set(session_groups.values())) != expected_groups:
            raise ValueError(f'{split} has {len(session_groups)} sessions in {len(set(session_groups.values()))} batches')
        if any(observed != WINDOWS for observed in endpoint_windows.values()):
            raise ValueError(f'Missing endpoint windows in {split}')
        if any(labels != EXPECTED_LABELS for labels in by_window.values()):
            raise ValueError(f'Incorrect category support in {split}')
        report['splits'][split] = {'sessions': len(session_groups), 'capture_batches': expected_groups, 'stack': stack,
                                   'labelled_endpoints': len(endpoint_labels), 'window_rows': sum(map(len, endpoint_windows.values())),
                                   'rows_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    index = {}
    for path in raw_dir.rglob('*.pcap'):
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest in captures:
            _, facts = complete_pcap(data)
            index[digest] = packet_times(data)
            report['captures'][digest] = {'path': path.relative_to(raw_dir).as_posix(), 'split': captures[digest][0],
                                         'capture_batch': captures[digest][1], 'bytes': facts['bytes'], 'frames': facts['frames']}
    if missing := captures.keys() - report['captures'].keys():
        raise ValueError(f'There are {len(missing)} capture references without matching saved PCAP bytes')
    report['verified_frame_reference_entries'] = audit_evidence(rows_dir, index)
    report['totals'] = {'sessions': len(sessions), 'capture_batches': len(groups),
                        'labelled_endpoints': sum(d['labelled_endpoints'] for d in report['splits'].values()),
                        'window_rows': sum(d['window_rows'] for d in report['splits'].values()), 'pcaps': len(captures)}
    return report


def audit_scores(rows_dir, scored):
    report = json.loads((scored / 'report.json').read_text(encoding='utf-8'))
    predictions = json.loads((scored / 'predictions.json').read_text(encoding='utf-8'))
    expected = {}
    for split in ('familiar', 'transfer'):
        with (rows_dir / f'{split}.jsonl').open(encoding='utf-8') as stream:
            for line in stream:
                row = json.loads(line)
                expected[split, row['session_id'], row['endpoint'], row['window_seconds']] = row
    cohorts = defaultdict(list)
    for record in predictions:
        key = tuple(record[name] for name in ('split', 'session_id', 'endpoint', 'window_seconds'))
        truth = expected.pop(key, None)
        if truth is None or any(record[name] != truth[name] for name in ('label', 'captures', 'capture_group')):
            raise ValueError(f'Prediction provenance differs from held-out row {key}')
        cohorts[record['split'], record['window_seconds']].append(record)
    if expected:
        raise ValueError('Some held-out rows do not have a recorded decision')
    reconstructed = {}
    for (split, window), rows in cohorts.items():
        stored = report['cohorts'][split]['windows'][str(window)]
        results = {}
        support = Counter(row['label'] for row in rows)
        for field, name in (('rules', 'updated_rules'), ('guarded_model', 'guarded_model'), ('fallback', 'selected_fallback')):
            decisions = Counter(row['label'] if row[field] == row['label'] else '' for row in rows)
            predicted = Counter(row[field] for row in rows)
            correct = sum(decisions[label] for label in MEDICAL)
            incorrect = len(rows) - predicted['unknown'] - correct
            macro = sum((2 * decisions[label]) / (support[label] + predicted[label]) for label in MEDICAL) / len(MEDICAL)
            false_support = sum(row['label'] == 'other' and row[field] != 'unknown' for row in rows)
            values = {'correct': correct, 'incorrect': incorrect, 'abstained': predicted['unknown'],
                      'supporting_false_medical': false_support, 'macro_f1': macro}
            for metric, value in values.items():
                if not isclose(stored['methods'][name][metric], value, abs_tol=1e-12):
                    raise ValueError(f'Saved {metric} differs for {split}/{window}/{name}')
            results[name] = values
        increment = Counter('still_unknown' if row['fallback'] == 'unknown' else
                            'additional_correct' if row['fallback'] == row['label'] else 'additional_wrong'
                            for row in rows if row['rules'] == 'unknown')
        if {name: increment[name] for name in ('additional_correct', 'additional_wrong', 'still_unknown')} != stored['rule_abstention_increment']:
            raise ValueError(f'Saved fallback increment differs for {split}/{window}')
        if any(row['rules'] != 'unknown' and row['rules'] != row['fallback'] for row in rows):
            raise ValueError('Fallback changed an assigned rule decision')
        reconstructed.setdefault(split, {})[str(window)] = {'methods': results, 'increment': stored['rule_abstention_increment']}
    return {'prediction_rows': len(predictions), 'reconstructed': reconstructed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rows', type=Path, required=True)
    parser.add_argument('--raw', type=Path, required=True)
    parser.add_argument('--scored', type=Path, help='Also check saved held-out predictions and independently recompute metrics')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = audit(args.rows, args.raw)
    if args.scored:
        report['score_verification'] = audit_scores(args.rows, args.scored)
    with args.output.open('x', encoding='utf-8') as output:
        json.dump(report, output, indent=2)
    print(json.dumps(report['totals'], sort_keys=True))


if __name__ == '__main__':
    main()
