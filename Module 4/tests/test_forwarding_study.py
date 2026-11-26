import unittest

from module4.forwarding_study import Transaction, attribute
from module4.evidence_v2 import hl7_messages
from module4.specificity_study import describe


def transaction(sender, capture, start, stop, digest=b'same'):
    return Transaction(sender, 'receiver', 'DICOM', ('ct_storage',), digest, capture,
                       {'completed_at': start, 'frames': [1]}, {'completed_at': stop, 'frames': [2]})


class ForwardingTests(unittest.TestCase):
    def test_linked_sender_requires_two_captures_and_ordered_replies(self):
        original = transaction('original', 'up', 1, 4)
        intermediary = transaction('intermediary', 'down', 2, 3)
        outcome, = attribute([original], [intermediary])
        self.assertEqual(outcome['upstream_sender'], 'original')
        self.assertEqual(outcome['physical_category'], 'unknown')
        self.assertNotIn('digest', outcome['upstream'])
        for candidates in ([], [transaction('original', 'up', 2.5, 4)],
                           [transaction('original', 'up', 1, 2.5)],
                           [transaction('original', 'down', 1, 4)],
                           [transaction('original', 'up', 1, 4, b'different')]):
            with self.subTest(candidates=candidates):
                self.assertIsNone(attribute(candidates, [intermediary])[0]['upstream_sender'])

    def test_reused_correlation_key_abstains(self):
        original = transaction('original', 'up', 1, 4)
        intermediary = transaction('intermediary', 'down', 2, 3)
        another_origin = transaction('another', 'up', 1.5, 3.5)
        self.assertIsNone(attribute([original, another_origin], [intermediary])[0]['upstream_sender'])
        self.assertTrue(all(row['upstream_sender'] is None for row in
                            attribute([original], [intermediary, intermediary])))

    def test_waveform_structure_requires_matching_observation_sub_id(self):
        header = b'\x0bMSH|^~\\&|S||R||20261126000000||ORU^W01|CTRL|P|2.5\r'
        channels = b'OBX|1|CD|ECG&CHN^^99HIOT|1|channel\rOBX|2|TS|ECG&TIM^^99HIOT|1|time\r'
        for sub_id, expected in ((b'1', ['ecg_waveform_reporting']), (b'2', [])):
            wire = header + channels + b'OBX|3|NA|ECG&WAV^^99HIOT|' + sub_id + b'|values\r\x1c\r'
            parsed, = hl7_messages(wire, [(1, 0.0)] * len(wire), linkage=True)
            self.assertEqual(parsed['kinds'], expected)
            self.assertNotIn('values', str(parsed))

    def test_dicom_acquisition_requires_same_step_instance_and_order(self):
        def event(workflow, start, digest):
            return Transaction('source', 'sink', 'DICOM', (workflow,), digest, 'capture',
                               {'completed_at': start}, {'completed_at': start + 0.5})

        create = event('mpps_create', 1, b'step')
        storage = event('dx_storage', 2, b'image')
        self.assertTrue(describe([create, storage, event('mpps_set', 3, b'step')])['ordered_acquisition_sequence'])
        self.assertFalse(describe([create, storage, event('mpps_set', 3, b'other')])['ordered_acquisition_sequence'])
