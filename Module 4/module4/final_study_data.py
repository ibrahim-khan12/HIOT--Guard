"""Input and provenance checks for the packet-backed Module 4 final study."""
from collections import Counter, defaultdict
from dataclasses import dataclass
import hashlib
import json
from math import isfinite
from pathlib import Path
import re

from module2.pcap import complete_pcap

from . import MEDICAL, OTHER


SPLITS = {'train': 40, 'calibration': 10, 'validation': 10, 'familiar': 10, 'transfer': 20}
FIT_SPLITS = ('train', 'calibration', 'validation')
TEST_SPLITS = ('familiar', 'transfer')
WINDOWS = (10, 30, 60, 120)
LABELS = (*MEDICAL, OTHER)

WORKFLOW_CANDIDATES = {
    'flow_rate': ('infusion_pump',), 'ct_storage': ('ct',), 'mr_storage': ('mri',),
    'ultrasound_storage': ('ultrasound',), 'dx_storage': ('portable_xray', OTHER),
    'heart_rate': ('bedside_monitor', 'ecg_monitor'), 'glucose': ('lab_analyzer',),
    'respiratory_rate': ('ventilator',), 'blood_flow': ('dialysis_machine',),
}
SEMANTIC_NAMES = frozenset({
    'oru_messages', 'unmapped_observations', 'dicom_proposals', 'store_requests',
    'store_success', 'store_non_success', 'store_unconfirmed',
    *(f'oru_{value}' for value in ('accepted', 'rejected', 'error', 'unrecognized_ack',
                                  'unacknowledged', 'limited_capture')),
    *(f'observed_{value}' for value in ('flow_rate', 'heart_rate', 'glucose', 'respiratory_rate', 'blood_flow')),
    *(f'{value}_success' for value in ('ct_storage', 'mr_storage', 'ultrasound_storage', 'dx_storage')),
    *(f'{prefix}_{kind}' for prefix in ('accepted', 'forwarded')
      for kind in (*WORKFLOW_CANDIDATES, 'mpps_create', 'mpps_set', 'ecg_waveform_reporting', 'generic_hl7', 'dicom_verification')),
})
TRAFFIC_NAMES = frozenset({
    'connections', 'truncated_packets', 'missing_syn', 'gap', 'conflicting_overlap',
    *(f'idle_intervals_{side}' for side in ('sent', 'received')),
    *(f'{stat}_{side}_{kind}' for stat in ('packet_length', 'iat') for side in ('sent', 'received')
      for kind in ('count', 'mean', 'std', 'min', 'max')),
})
FEATURE_NAMES = SEMANTIC_NAMES | TRAFFIC_NAMES | {'coverage_sufficient'}
SHA256 = re.compile('[a-f0-9]{64}').fullmatch
FILE_COMPONENT = re.compile('[A-Za-z0-9_-]{1,128}').fullmatch


def file_digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'Repeated JSON key {key!r}')
        result[key] = value
    return result


@dataclass
class Split:
    name: str
    sha256: str
    rows: list
    sessions: set
    groups: set
    captures: set
    group_captures: dict

    def audit(self):
        return {'sha256': self.sha256, 'rows': len(self.rows), 'sessions': sorted(self.sessions),
                'capture_groups': sorted(self.groups), 'capture_sha256': sorted(self.captures),
                'capture_sha256_by_group': {group: sorted(refs) for group, refs in sorted(self.group_captures.items())}}


def valid_identity(value):
    return isinstance(value, str) and 0 < len(value) <= 256 and bool(value.strip())


def read_split(path, name, windows=WINDOWS, session_count=None):
    """Validate all windows while preserving a fixed, separate ground-truth column."""
    path = Path(path)
    records, digest = [], hashlib.sha256()
    session_details, captures = {}, {}
    endpoint_details, observed_windows = {}, defaultdict(set)
    counts = defaultdict(Counter)
    with path.open('rb') as stream:
        for number, raw in enumerate(stream, 1):
            digest.update(raw)
            try:
                row = json.loads(raw, object_pairs_hook=unique_keys)
                session, group, endpoint = (row[key] for key in ('session_id', 'capture_group', 'endpoint'))
                window, label, features, refs = (row[key] for key in ('window_seconds', 'label', 'features', 'captures'))
                if not all(valid_identity(value) for value in (session, group, endpoint)):
                    raise ValueError('Invalid session, group or endpoint identity')
                if not FILE_COMPONENT(group):
                    raise ValueError('Capture group requires a portable file component')
                if row['stack'] != ('B' if name == 'transfer' else 'A') or row['split'] != name:
                    raise ValueError('Row belongs to an unexpected stack or split')
                if type(window) is not int or window not in windows or label not in LABELS:
                    raise ValueError('Unexpected observation window or ground-truth label')
                if not isinstance(refs, list) or not refs or any(not isinstance(ref, str) or not SHA256(ref) for ref in refs):
                    raise ValueError('A packet capture SHA-256 is required for every row')
                if len(refs) != len(set(refs)):
                    raise ValueError('Capture digest repeated on one row')
                if not isinstance(features, dict) or features.keys() - FEATURE_NAMES:
                    unknown = sorted(features.keys() - FEATURE_NAMES) if isinstance(features, dict) else []
                    raise ValueError(f'Feature outside the packet allowlist: {unknown}')
                if any(type(value) not in (int, float) or not isfinite(value) or value < 0 for value in features.values()):
                    raise ValueError('Features must be finite nonnegative numbers')
                if features and features.get('coverage_sufficient') not in (0, 1):
                    raise ValueError('Packet rows must explicitly describe observation coverage')
                if session_details.setdefault(session, group) != group:
                    raise ValueError('Session appears in more than one capture group')
                for ref in refs:
                    if captures.setdefault(ref, group) != group:
                        raise ValueError('One capture appears in multiple collection groups')
                endpoint_id = (session, endpoint)
                if endpoint_details.setdefault(endpoint_id, label) != label:
                    raise ValueError('Ground truth changed between observation windows')
                if window in observed_windows[endpoint_id]:
                    raise ValueError('Duplicate endpoint window')
                observed_windows[endpoint_id].add(window)
                counts[session, window][label] += 1
            except (TypeError, ValueError, KeyError, UnicodeError) as error:
                raise ValueError(f'{path.name}, line {number}: {error}') from error
            records.append(row)
    if not records or session_count is not None and len(session_details) != session_count:
        raise ValueError(f'{name} has {len(session_details)} sessions, expected {session_count or "a positive count"}')
    for key, found in observed_windows.items():
        if found != set(windows):
            raise ValueError(f'Missing observation windows for {key}')
    expected = Counter({**dict.fromkeys(MEDICAL, 1), OTHER: 5})
    for key, found in counts.items():
        if found != expected:
            raise ValueError(f'{key} needs one endpoint per medical category and five supporting endpoints')
    group_captures = defaultdict(set)
    for digest_value, group in captures.items():
        group_captures[group].add(digest_value)
    return Split(name, digest.hexdigest(), records, set(session_details), set(session_details.values()),
                 set(captures), dict(group_captures))


def verify_batch_captures(root, audit):
    """Verify physical PCAPs only for groups in the supplied split audit."""
    for group, expected in sorted(audit['capture_sha256_by_group'].items()):
        if not FILE_COMPONENT(group):
            raise ValueError('Invalid capture group in audit')
        directory = root / group
        manifest = json.loads((directory / 'manifest.json').read_text(encoding='utf-8'), object_pairs_hook=unique_keys)
        verified = set()
        for link, hints in manifest['captures'].items():
            if not FILE_COMPONENT(link):
                raise ValueError(f'Invalid capture link name in {group}')
            path = directory / (link + '.pcap')
            raw = path.read_bytes()
            _, metadata = complete_pcap(raw)
            if metadata['sha256'] != hints['sha256'] or len(raw) != hints['bytes'] or metadata['frames'] != hints['frames']:
                raise ValueError(f'Packet capture differs from manifest: {group}/{path.name}')
            if not metadata['frames']:
                raise ValueError(f'Empty packet capture: {group}/{path.name}')
            if metadata['sha256'] in verified:
                raise ValueError(f'Batch lists duplicate capture bytes: {group}/{path.name}')
            verified.add(metadata['sha256'])
        if set(expected) != verified:
            raise ValueError(f'Endpoint evidence does not reference exactly the verified manifests of {group}')


def ensure_disjoint(audits):
    for index, (name, audit) in enumerate(audits.items()):
        for later, other in list(audits.items())[index+1:]:
            for key in ('sessions', 'capture_groups', 'capture_sha256'):
                if set(audit[key]).intersection(other[key]):
                    raise ValueError(f'{name} and {later} share {key}')
