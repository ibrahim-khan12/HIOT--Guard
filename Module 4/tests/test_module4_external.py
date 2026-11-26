import unittest

from module4.external_pilot import FIELDS, rejection_metrics, verify_binding


class ExternalTargetTests(unittest.TestCase):
    def packet(self, source_mac="90:11:95:16:40:3b", source_ip="192.168.137.7", frame="1"):
        return dict.fromkeys(FIELDS, "") | {"frame.number": frame, "eth.src": source_mac,
                                            "eth.dst": "8c:ae:4c:dd:1e:39", "ip.src": source_ip}

    def test_identity_needs_publisher_mac_and_observed_ip_to_agree(self):
        packet = self.packet()
        binding = verify_binding([packet], "90:11:95:16:40:3B", "192.168.137.7")
        self.assertEqual(binding["source_ip_mac_packets"], 1)
        self.assertEqual(binding["supporting_source_frames"], [1])
        with self.assertRaises(ValueError):
            verify_binding([packet], "1c:90:ff:e6:e2:4b", "192.168.137.7")
        with self.assertRaises(ValueError):
            verify_binding([packet], "90:11:95:16:40:3b", "192.168.137.235")

    def test_conflicting_mac_at_same_ip_is_not_silently_assigned(self):
        packets = [self.packet(), self.packet(source_mac="01:02:03:04:05:06", frame="2")]
        with self.assertRaises(ValueError):
            verify_binding(packets, "90:11:95:16:40:3b", "192.168.137.7")

    def test_broadcast_or_unspecified_target_is_rejected(self):
        for ip in ("255.255.255.255", "0.0.0.0", "224.0.0.1", "::"):
            with self.assertRaises(ValueError):
                verify_binding([self.packet(source_ip=ip)], "90:11:95:16:40:3b", ip)

    def test_only_reviewed_unknown_targets_enter_rejection_metrics(self):
        rows = [{"expected": "unknown", "decisions": {"model": {"category": "unknown"}}},
                {"expected": "unknown", "decisions": {"model": {"category": "infusion_pump"}}}]
        card = rejection_metrics(rows)["model"]
        self.assertEqual(card["targets"], 2)
        self.assertEqual(card["correct_unknown_rejections"], 1)
        self.assertEqual(card["incorrect_medical_assignments"], 1)
        self.assertEqual(card["correct_rejection_fraction"], .5)
        rows[1]["expected"] = "infusion_pump"
        with self.assertRaises(ValueError):
            rejection_metrics(rows)

    def test_inconsistent_methods_and_unexpected_categories_fail(self):
        with self.assertRaises(ValueError):
            rejection_metrics([])
        for row in ({"expected": "unknown", "decisions": {}},
                    {"expected": "unknown", "decisions": {"model": {"category": "camera"}}}):
            with self.assertRaises(ValueError):
                rejection_metrics([{"expected": "unknown", "decisions": {"model": {"category": "unknown"}}}, row])


if __name__ == "__main__":
    unittest.main()
