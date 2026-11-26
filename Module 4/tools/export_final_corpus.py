"""Verify raw captures and export split-local packet-prefix feature rows."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from final_corpus_profiles import ALLOCATION, LINK_PREFIX, WINDOWS, endpoints, sessions, topology
from module2.pcap import complete_pcap
from module4.evidence_v2 import analyze, packets
from module4.forwarding_study import attribute, exchanges


def load(path):
    return json.loads(path.read_text(encoding='utf-8'))


def address_in_session(address, link, number):
    return address.startswith(f'10.{LINK_PREFIX[link]}.{number}.')


def read_capture(folder, link, facts, tshark):
    path = folder / (link + '.pcap')
    raw = path.read_bytes()
    _, validation = complete_pcap(raw)
    digest = hashlib.sha256(raw).hexdigest()
    if (digest, len(raw), validation['frames']) != (facts['sha256'], facts['bytes'], facts['frames']):
        raise ValueError(f'Raw recording {path} does not match its committed manifest')
    return packets(path, tshark)


def forward_evidence(by_link, selected, deadline, sender, hashes):
    downstream = exchanges(selected, hashes['downstream'])
    downstream = [event for event in downstream if event.sender == sender]
    if not downstream:
        return []
    prior = exchanges([row for row in by_link['upstream'] if row['time'] <= deadline], hashes['upstream'])
    return [candidate for candidate in attribute(prior, downstream) if candidate['upstream_sender'] is not None]


def export_session(session, by_link, digests, receipt):
    number = session['number']
    suffixes, _ = topology(session)
    marker = f'10.{LINK_PREFIX["direct"]}.{number}.{suffixes["end_marker"]}'
    session_packets = {link: [pkt for pkt in rows if address_in_session(pkt['src'], link, number)
                              and address_in_session(pkt['dst'], link, number)] for link, rows in by_link.items()}
    frames = [row for row in session_packets['direct'] if row['src'] == marker and row['stream'] == '']
    if len(frames) != 1 or receipt['marker_source'] != marker:
        raise ValueError(f'{session["session_id"]} lacks its unique captured stop marker')
    capture_end = frames[0]['time']
    for actor in session['endpoints']:
        endpoint = actor['endpoint']
        link = actor['link']
        records = [row for row in session_packets[link] if endpoint in (row['src'], row['dst'])]
        if not records:
            raise ValueError(f'{session["session_id"]} has no packets for {actor["role"]}')
        start = min(row['time'] for row in records)
        for window in WINDOWS:
            deadline = start + window
            row = analyze(records, endpoint, window, capture_end, digests[link])
            if not row['features'].get('coverage_sufficient'):
                raise ValueError(f'{session["session_id"]}/{actor["role"]} lacks {window}s capture coverage')
            prefix = [item for item in records if item['time'] <= deadline]
            transactions = [event for event in exchanges(prefix, digests[link]) if event.sender == endpoint]
            matched = forward_evidence(session_packets, prefix, deadline, endpoint, digests) if link == 'downstream' else []
            additions = Counter('accepted_' + workflow for event in transactions for workflow in event.workflows)
            additions.update('forwarded_' + workflow for match in matched for workflow in match['downstream']['workflows'])
            yield {'session_id': session['session_id'], 'capture_group': session['capture_group'],
                   'stack': session['stack'], 'split': session['split'], 'endpoint': endpoint,
                   'label': actor['label'], 'window_seconds': window, 'features': {**row['features'], **additions},
                   'captures': sorted(digests.values()), 'flow_evidence': row['evidence'],
                   'paired_evidence': matched, 'observation_end': {'capture_sha256': digests['direct'],
                                                                    'frame': frames[0]['frame']}}


def export_batch(root, group, expected_sessions, sources, tshark):
    folder = root / 'batches' / group
    saved = load(folder / 'manifest.json')
    expected = [{**session, 'endpoints': list(endpoints(session))} for session in expected_sessions]
    if saved['capture_group'] != group or saved['sessions'] != expected or saved['source_sha256'] != sources:
        raise ValueError(f'Batch {group} differs from the preregistered plan')
    receipts = {row['session_id']: row for row in saved['receipts']}
    if set(receipts) != {x['session_id'] for x in expected} or len(receipts) != len(saved['receipts']):
        raise ValueError(f'Batch {group} has missing or duplicate emission receipts')
    by_link = {link: read_capture(folder, link, facts, tshark) for link, facts in saved['captures'].items()}
    if set(by_link) != set(LINK_PREFIX):
        raise ValueError(f'Batch {group} is missing a capture link')
    digests = {link: facts['sha256'] for link, facts in saved['captures'].items()}
    return [row for session in expected for row in export_session(session, by_link, digests, receipts[session['session_id']])]


def export(root, split, expected, source_hashes, tshark):
    destination = root / 'dataset' / (split + '.jsonl')
    destination.parent.mkdir(exist_ok=True)
    split_groups = defaultdict(list)
    for session in expected:
        if session['split'] == split:
            split_groups[session['capture_group']].append(session)
    manifest_paths = [root / 'batches' / group / 'manifest.json' for group in split_groups]
    if any(not path.exists() for path in manifest_paths):
        return False
    pending = destination.with_suffix('.pending')
    rows = 0
    try:
        with pending.open('w', encoding='utf-8', newline='\n') as output:
            for group, expected_group in split_groups.items():
                data = export_batch(root, group, expected_group, source_hashes, tshark)
                for row in data:
                    output.write(json.dumps(row, separators=(',', ':'), sort_keys=True, allow_nan=False) + '\n')
                rows += len(data)
                print(f'{group}: exported {len(data)} independently windowed endpoint rows', flush=True)
        if rows != ALLOCATION[split][1] * 15 * len(WINDOWS):
            raise ValueError(f'Split {split} did not produce all expected rows')
        if destination.exists() and pending.read_bytes() != destination.read_bytes():
            raise ValueError(f'Re-extraction differs from sealed {destination}')
        pending.replace(destination)
    finally:
        pending.unlink(missing_ok=True)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--folder', type=Path, required=True)
    parser.add_argument('--split', action='append', choices=tuple(ALLOCATION))
    parser.add_argument('--tshark', default=r'C:\Program Files\Wireshark\tshark.exe')
    parser.add_argument('--wait', type=float, default=0, metavar='SECONDS',
                        help='Export completed splits as their captures arrive, up to this deadline.')
    args = parser.parse_args()
    plan = load(args.folder / 'corpus-plan.json')
    expected = list(sessions())
    if plan['sessions'] != expected or plan['windows'] != list(WINDOWS):
        raise ValueError('Recorded corpus plan differs from the fixed split and horizon')
    completed = []
    pending = list(args.split or ALLOCATION)
    deadline = time.monotonic() + args.wait
    while pending:
        for split in pending[:]:
            if export(args.folder, split, expected, plan['source_sha256'], args.tshark):
                completed.append(split)
                pending.remove(split)
        if not pending or time.monotonic() >= deadline:
            break
        time.sleep(min(5, max(0, deadline - time.monotonic())))
    print(json.dumps({'complete_splits': completed, 'missing_recordings': pending}))
    if pending and args.wait:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
