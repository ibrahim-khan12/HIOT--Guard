"""Check whether acknowledged waveform and acquisition evidence separates matched controls."""
import argparse
from collections import Counter
import json
from pathlib import Path

from .forwarding_study import load_capture


def describe(events):
    counts = Counter(workflow for event in events for workflow in event.workflows)
    valid_sequence = False
    if counts == {'mpps_create': 1, 'dx_storage': 1, 'mpps_set': 1}:
        ordered = sorted(events, key=lambda event: event.request['completed_at'])
        valid_sequence = ([event.workflows for event in ordered] == [('mpps_create',), ('dx_storage',), ('mpps_set',)]
                          and ordered[0].digest == ordered[2].digest
                          and all(left.reply['completed_at'] <= right.request['completed_at']
                                  for left, right in zip(ordered, ordered[1:])))
    return {'workflow_counts': dict(counts), 'ordered_acquisition_sequence': valid_sequence,
            'packet_evidence': [event.evidence() for event in events]}


def evaluate(root, tshark):
    runs = []
    for path in sorted((root / 'specificity').glob('*/session.json')):
        session = json.loads(path.read_text(encoding='utf-8'))
        if session['mode'] != 'specificity' or session['purpose'] != 'development_only':
            raise ValueError(f'Unexpected control manifest {path}')
        events = load_capture(path.parent, 'direct', session, tshark)
        profiles = {label: describe([event for event in events if event.sender == f'10.90.0.{suffix}'])
                    for label, suffix in (('bedside', 13), ('ecg', 14), ('portable_xray', 15), ('fixed_xray', 16))}
        checks = {
            'both_heart_sources_show_waveform': all(profiles[label]['workflow_counts'] ==
                                                  {'heart_rate': 3, 'ecg_waveform_reporting': 1}
                                                  for label in ('bedside', 'ecg')),
            'both_xray_sources_show_acquisition_sequence': all(profiles[label]['ordered_acquisition_sequence']
                                                               for label in ('portable_xray', 'fixed_xray')),
        }
        runs.append({'capture': str(path.parent.relative_to(root) / 'direct.pcap'), 'profiles': profiles, 'checks': checks})
    if not runs:
        raise ValueError('No completed specificity recordings')
    shared = all(all(run['checks'].values()) for run in runs)
    return {'purpose': 'synthetic_development_controls', 'sessions': len(runs), 'shared_workflow_checks_passed': shared,
            'result': 'unknown_for_both_pairs_under_tested_semantics' if shared else 'incomplete_control_evidence',
            'runs': runs}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--folder', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--tshark', default=r'C:\Program Files\Wireshark\tshark.exe')
    args = parser.parse_args()
    report = evaluate(args.folder, args.tshark)
    with args.output.open('x', encoding='utf-8') as output:
        json.dump(report, output, indent=2)
    print(json.dumps({key: value for key, value in report.items() if key != 'runs'}, indent=2))
    if not report['shared_workflow_checks_passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
