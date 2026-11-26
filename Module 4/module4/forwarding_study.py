"""Audit transaction attribution across two labelled GNS3 observation links."""
import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from module2.pcap import complete_pcap
from .evidence_v2 import contiguous, dicom_messages, hl7_messages, packets


@dataclass(frozen=True)
class Transaction:
    sender: str
    receiver: str
    protocol: str
    workflows: tuple
    digest: bytes
    capture_sha256: str
    request: dict
    reply: dict

    def evidence(self):
        return {'sender': self.sender, 'receiver': self.receiver, 'protocol': self.protocol,
                'workflows': self.workflows, 'capture_sha256': self.capture_sha256,
                'request': self.request, 'reply': self.reply}


def exchanges(items, sha256):
    groups = defaultdict(list)
    for packet in items:
        if packet['stream'] != '':
            groups[packet['stream'], packet['src'], packet['dst']].append(packet)
    parsed = {}
    for route, group in groups.items():
        if any(p['captured'] < p['length'] for p in group):
            continue
        data, marks, quality = contiguous(group)
        if not any(quality.values()):
            parsed[route] = (hl7_messages(data, marks, linkage=True), dicom_messages(data, marks, linkage=True))
    result = []
    for (stream, source, destination), (hl7, dicom) in parsed.items():
        peer_hl7, peer_dicom = parsed.get((stream, destination, source), ([], []))
        controls = Counter(m['control'] for m in hl7 if m['type'] == 'ORU')
        for request in hl7:
            if request['type'] != 'ORU' or not request['control'] or controls[request['control']] != 1:
                continue
            replies = [m for m in peer_hl7 if m['type'] == 'ACK' and m.get('ack_for') == request['control']]
            if (len(replies) == 1 and replies[0].get('ack_status') == 'AA'
                    and replies[0]['reference']['completed_at'] >= request['reference']['completed_at']):
                result.append(Transaction(source, destination, 'HL7/MLLP', tuple(request['kinds']),
                                          request['message_digest'], sha256, request['reference'], replies[0]['reference']))
        proposals = {(m['context'], m['workflow']) for m in dicom if m['type'] == 'proposal'}
        accepted = {m['context'] for m in peer_dicom if m['type'] == 'context_result' and m['status'] == 0}
        requests = [m for m in dicom if m['type'] in ('store_request', 'create_request', 'set_request')]
        identifiers = Counter((m['id'], m['context']) for m in requests)
        for request in requests:
            identity = (request['id'], request['context'])
            workflow = request['workflow']
            if (request['id'] is None or identifiers[identity] != 1 or not workflow
                    or request['context'] not in accepted or (request['context'], workflow) not in proposals
                    or 'instance_digest' not in request):
                continue
            operation = request['type'].removesuffix('_request')
            replies = [m for m in peer_dicom if m['type'] == operation + '_response' and (m['id'], m['context']) == identity]
            if (len(replies) == 1 and replies[0]['status'] == 0
                    and replies[0]['reference']['completed_at'] >= request['reference']['completed_at']):
                name = workflow if operation == 'store' else workflow + '_' + operation
                result.append(Transaction(source, destination, 'DICOM', (name,), request['instance_digest'],
                                          sha256, request['reference'], replies[0]['reference']))
    return sorted(result, key=lambda item: item.request['completed_at'])


def attribute(upstream, downstream):
    def key(item):
        return item.protocol, item.workflows, item.digest

    groups = defaultdict(list)
    for item in upstream:
        groups[key(item)].append(item)
    counts = Counter(map(key, downstream))
    outcomes = []
    for item in downstream:
        matches = groups[key(item)]
        source = matches[0] if len(matches) == counts[key(item)] == 1 else None
        if source and (source.capture_sha256 == item.capture_sha256 or not (
            source.request['completed_at'] <= item.request['completed_at'] <= item.reply['completed_at']
            <= source.reply['completed_at'] <= source.request['completed_at'] + 10
        )):
            source = None
        outcomes.append({'downstream': item.evidence(),
                         'upstream': source.evidence() if source else None,
                         'upstream_sender': source.sender if source else None,
                         'physical_category': 'unknown'})
    return outcomes


def load_capture(folder, link, manifest, tshark):
    path = folder / (link + '.pcap')
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    complete_pcap(raw)
    expected = manifest['captures'][link]
    if digest != expected['sha256'] or len(raw) != expected['bytes']:
        raise ValueError(f'Capture integrity check failed for {folder.name}/{link}')
    return exchanges(packets(path, tshark), digest)


def histogram(events, sender):
    return Counter((item.protocol, item.workflows) for item in events if item.sender == sender)


def evaluate(root, tshark, stacks=('A', 'B')):
    sessions = {}
    for path in sorted(root.glob('*/session.json')):
        session = json.loads(path.read_text(encoding='utf-8'))
        if session['stack'] not in stacks:
            continue
        key = session['stack'], session['repeat'], session['mode']
        if key in sessions or session['purpose'] != 'development_only':
            raise ValueError(f'Invalid session manifest {path}')
        sessions[key] = session, path.parent
    repeats = sorted({key[1] for key in sessions})
    expected = {(stack, repeat, mode) for repeat in repeats for stack in stacks for mode in ('direct', 'forwarded')}
    if not expected or expected != sessions.keys():
        raise ValueError('Every repeat must contain direct and forwarded recordings from each selected stack')

    # Independent scorer ground truth from the experiment topology. The matching
    # function itself does not receive the role or address relationships.
    expected_sources = {'10.89.0.21': '10.88.0.11', '10.89.0.22': '10.88.0.12'}
    rows = []
    for repeat in repeats:
        for stack in stacks:
            direct_session, direct_folder = sessions[stack, repeat, 'direct']
            path_session, path_folder = sessions[stack, repeat, 'forwarded']
            direct = load_capture(direct_folder, 'direct', direct_session, tshark)
            upstream = load_capture(path_folder, 'upstream', path_session, tshark)
            downstream = load_capture(path_folder, 'downstream', path_session, tshark)
            sides = attribute(upstream, downstream)
            blind = attribute([], downstream)
            unrelated = attribute(direct, downstream)
            controls = {}
            for label, left, right, protocol, workflow, count in (
                ('bedside_vs_ecg', 13, 14, 'HL7/MLLP', 'heart_rate', 3),
                ('portable_vs_fixed_xray', 15, 16, 'DICOM', 'dx_storage', 1),
            ):
                expected_profile = Counter({(protocol, (workflow,)): count})
                controls[label] = (histogram(direct, f'10.90.0.{left}') == expected_profile
                                   == histogram(direct, f'10.90.0.{right}'))
            source_match = sum(row['upstream_sender'] is not None
                               and row['upstream_sender'] == expected_sources.get(row['downstream']['sender']) for row in sides)
            paired_workflows = all(histogram(direct, f'10.90.0.{suffix}') == expected_workflows
                                   == histogram(upstream, f'10.88.0.{suffix}') for suffix, expected_workflows in
                                   ((11, {('HL7/MLLP', ('flow_rate',)): 3}), (12, {('DICOM', ('ct_storage',)): 2})))
            rows.append({'stack': stack, 'repeat': repeat, 'direct_seconds': direct_session['seconds'],
                         'forwarded_seconds': path_session['seconds'], 'direct_successes': [item.evidence() for item in direct],
                         'downstream_only': blind, 'both_links': sides, 'correct_upstream': source_match,
                         'wrong_upstream': sum(row['upstream_sender'] is not None for row in sides) - source_match,
                         'unrelated_direct_matches': sum(row['upstream_sender'] is not None for row in unrelated),
                         'paired_direct_and_upstream_workflows': paired_workflows, 'same_semantics_controls': controls})
    passed = all(len(row['both_links']) == row['correct_upstream'] == 5 and row['wrong_upstream'] == 0
                 and row['unrelated_direct_matches'] == 0 and row['paired_direct_and_upstream_workflows']
                 and all(row['same_semantics_controls'].values()) for row in rows)
    return {'purpose': 'development_only', 'stacks': stacks, 'paired_runs': len(rows), 'sessions': len(sessions),
            'two_link_attribution_checks_passed': passed, 'cross_stack_check_passed': passed and set(stacks) == {'A', 'B'},
            'physical_category_evaluation': 'not_scored',
            'downstream_only_attributed': sum(row['upstream_sender'] is not None for r in rows for row in r['downstream_only']),
            'two_link_correct': sum(r['correct_upstream'] for r in rows), 'two_link_wrong': sum(r['wrong_upstream'] for r in rows),
            'downstream_transactions': sum(len(r['both_links']) for r in rows), 'runs': rows,
            'limits': ['Known capture placement and synchronous forwarding; same GNS3 host clock.',
                       'HL7 requires unchanged wire messages. DICOM matches an instance UID and class, not image content.',
                       'Independent sender libraries share the intermediary and receiver implementations.',
                       'Attribution identifies the observed upstream sender. Physical ten-category evidence remains unresolved.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--folder', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--tshark', default=r'C:\Program Files\Wireshark\tshark.exe')
    parser.add_argument('--stack', choices=('A', 'B', 'both'), default='both')
    args = parser.parse_args()
    report = evaluate(args.folder, args.tshark, ('A', 'B') if args.stack == 'both' else (args.stack,))
    with args.output.open('x', encoding='utf-8') as output:
        json.dump(report, output, indent=2)
    print(json.dumps({key: value for key, value in report.items() if key not in ('runs', 'limits')}, indent=2))
    if not report['two_link_attribution_checks_passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
