import unittest
from unittest.mock import patch
from types import SimpleNamespace

from module4.sentinel_pilot import capture_metrics, select_members, source_addresses


class SentinelPilotTests(unittest.TestCase):
    def test_selection_uses_different_setup_people_before_repeats(self):
        prefix = "captures_IoT-Sentinel/D-LinkCam/"
        names = [prefix + name for name in ("Setup-A-1-STA.pcap", "Setup-A-2-STA.pcap",
                                             "Setup-B-1-STA.pcap", "Setup-C-1-STA.pcap")]
        self.assertEqual(select_members(names[::-1], "D-LinkCam"), [names[0], names[2], names[3]])

    def test_selection_excludes_archive_traversal_and_resource_forks(self):
        names = [f"captures_IoT-Sentinel/D-LinkCam/Setup-A-{i}-STA.pcap" for i in range(1, 4)]
        unsafe = ["captures_IoT-Sentinel/D-LinkCam/../Setup-B-1-STA.pcap",
                  "__MACOSX/captures_IoT-Sentinel/D-LinkCam/Setup-B-1-STA.pcap"]
        self.assertEqual(select_members(names + unsafe, "D-LinkCam"), names)
        with self.assertRaises(ValueError):
            select_members(names + [names[0]], "D-LinkCam")

    def test_every_target_ip_alias_must_be_rejected_for_a_setup_to_pass(self):
        def row(member, prediction):
            return {"member": member, "decisions": {"model": {"category": prediction}}}
        metrics = capture_metrics([row("setup1", "unknown"), row("setup1", "infusion_pump"),
                                   row("setup2", "unknown")])["model"]
        self.assertEqual(metrics["targets"], 2)
        self.assertEqual(metrics["correct_unknown_rejections"], 1)
        self.assertEqual(metrics["incorrect_medical_assignments"], 1)

    @patch("module4.sentinel_pilot.subprocess.run")
    def test_all_attributed_ipv4_and_ipv6_aliases_are_kept(self, run):
        mac = "00:11:22:33:44:55"
        run.return_value = SimpleNamespace(stdout=f"{mac}\t0.0.0.0\t\n{mac}\t10.0.0.2\t\n"
                                          f"{mac}\t10.0.0.3\t\n{mac}\t\tfe80::1\n")
        self.assertEqual(source_addresses("capture", "tshark", mac),
                         {"10.0.0.2": 1, "10.0.0.3": 1, "fe80::1": 1})

    @patch("module4.sentinel_pilot.subprocess.run")
    def test_conflicting_mac_ownership_is_rejected(self, run):
        mac = "00:11:22:33:44:55"
        run.return_value = SimpleNamespace(stdout=f"{mac}\t10.0.0.2\t\n66:77:88:99:aa:bb\t10.0.0.2\t\n")
        with self.assertRaises(ValueError):
            source_addresses("capture", "tshark", mac)


if __name__ == "__main__":
    unittest.main()
