import hashlib
import json
from pathlib import Path
import struct
from tempfile import TemporaryDirectory
import unittest

from module4 import MEDICAL, OTHER, UNKNOWN
from module4.final_study import evidence, fit, model_decision, paired_uncertainty, rule_decision, score
from module4.final_study_data import WORKFLOW_CANDIDATES, ensure_disjoint, read_split


def write_fixture(root, split, count, windows=(10, 120), add_features=None):
    """Tiny plumbing fixture, deliberately unrelated to the study corpus."""
    dataset = root / 'dataset'
    dataset.mkdir(exist_ok=True)
    path = dataset / (split + '.jsonl')
    with path.open('w', encoding='utf-8') as stream:
        for offset in range(count):
            group = f'{split}-{offset}'
            batch = root / 'batches' / group
            batch.mkdir(parents=True, exist_ok=True)
            body = group.encode()
            raw = struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + struct.pack('<IIII', 1, 0, len(body), len(body)) + body
            digest = hashlib.sha256(raw).hexdigest()
            (batch / 'direct.pcap').write_bytes(raw)
            (batch / 'manifest.json').write_text(json.dumps({'captures': {'direct': {
                'sha256': digest, 'bytes': len(raw), 'frames': 1}}}), encoding='utf-8')
            for window in windows:
                for index, label in enumerate((*MEDICAL, *((OTHER,) * 5))):
                    workflow = next((kind for kind, values in WORKFLOW_CANDIDATES.items() if label in values and label != OTHER), None)
                    features = {'coverage_sufficient': 1, 'packet_length_sent_mean': 40 + index}
                    if workflow:
                        features['accepted_' + workflow] = 2
                    row = {'session_id': group, 'capture_group': group, 'endpoint': str(index), 'split': split,
                           'stack': 'B' if split == 'transfer' else 'A', 'label': label,
                           'captures': [digest], 'window_seconds': window, 'features': {**features, **(add_features or {})}}
                    stream.write(json.dumps(row) + '\n')
    return path


class FinalStudyTests(unittest.TestCase):
    def test_paired_capture_groups_remain_disjoint(self):
        shared = {'sessions': ['session-a'], 'capture_groups': ['capture-a'], 'capture_sha256': ['a' * 64]}
        for field in shared:
            other = {'sessions': ['session-b'], 'capture_groups': ['capture-b'], 'capture_sha256': ['b' * 64]}
            other[field] = shared[field]
            with self.subTest(shared=field), self.assertRaisesRegex(ValueError, field):
                ensure_disjoint({'train': shared, 'familiar': other})

    def test_rejects_identifying_and_missing_coverage_features(self):
        with TemporaryDirectory() as directory:
            path = write_fixture(Path(directory), 'train', 1, add_features={'ip_suffix': 11})
            with self.assertRaisesRegex(ValueError, 'ip_suffix'):
                read_split(path, 'train', (10, 120), 1)
            write_fixture(Path(directory), 'train', 1, add_features={'coverage_sufficient': 2})
            with self.assertRaisesRegex(ValueError, 'explicitly describe observation coverage'):
                read_split(path, 'train', (10, 120), 1)

    def test_workflow_guard_ignores_model_confidence_on_confounded_categories(self):
        for kind, guessed in (('heart_rate', 'ecg_monitor'), ('dx_storage', 'portable_xray')):
            candidate = evidence({'features': {'coverage_sufficient': 1, 'accepted_' + kind: 3}})
            self.assertEqual(rule_decision(candidate), UNKNOWN)
            self.assertEqual(model_decision(candidate, guessed, 1, 0)[0], UNKNOWN)
        relay = evidence({'features': {'coverage_sufficient': 1, 'accepted_flow_rate': 3, 'forwarded_flow_rate': 1}})
        self.assertEqual(model_decision(relay, 'infusion_pump', 1, 0), (UNKNOWN, 'observed_cross_link_forwarding'))

    def test_refuses_uncertainty_when_sessions_share_too_few_capture_groups(self):
        result = paired_uncertainty(['ct'] * 30, ['ct'] * 30, ['ct'] * 30, ['one'] * 10 + ['two'] * 20)
        self.assertIsNone(result['ci95'])
        self.assertEqual(result['independent_capture_groups'], 2)

    def test_fit_before_holdouts_exist_and_report_both_cohorts(self):
        counts = {'train': 2, 'calibration': 1, 'validation': 1, 'familiar': 1, 'transfer': 1}
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ('train', 'calibration', 'validation'):
                write_fixture(root, name, counts[name])
            frozen = fit(root / 'dataset', root / 'fit', counts, (10, 120), 120)
            self.assertEqual(frozen['holdout_files_opened'], [])
            self.assertEqual(len(frozen['candidates']), 6)
            for name in ('familiar', 'transfer'):
                write_fixture(root, name, counts[name])
            scored = score(root / 'dataset', root / 'fit', root / 'score')
            self.assertEqual(set(scored['cohorts']), {'familiar', 'transfer'})
            self.assertEqual(len(scored['cohorts']['transfer']['windows']['120']['methods']['selected_fallback']['classes']), 10)
            path = root / 'batches' / 'transfer-0' / 'direct.pcap'
            path.write_bytes(path.read_bytes() + b'truncated')
            with self.assertRaisesRegex(ValueError, 'Truncated PCAP'):
                score(root / 'dataset', root / 'fit', root / 'tampered')
