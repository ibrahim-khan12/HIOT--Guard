import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from config import CAPTURE_ROLES
from gns3 import GNS3
from module2.live import Spool
from scenario_profile import IMAGE, PROFILE, ROLE_IPS, SCENARIOS, capture_sources, parse_payload, payload
from scenario_runs import ScenarioRuns


class ScenarioTests(unittest.TestCase):
    def test_manifest_keeps_legacy_and_requires_every_scenario_link(self):
        manifest = {"complete": True, "links": {role: f"link-{role}" for role in CAPTURE_ROLES}}
        self.assertEqual(capture_sources(manifest, CAPTURE_ROLES), CAPTURE_ROLES)
        manifest.update(profile=PROFILE, capture_sources=[*CAPTURE_ROLES, *ROLE_IPS])
        with self.assertRaises(ValueError):
            capture_sources(manifest, CAPTURE_ROLES)
        manifest["links"].update({role: f"link-{role}" for role in ROLE_IPS})
        self.assertEqual(len(capture_sources(manifest, CAPTURE_ROLES)), 17)
        manifest["links"]["burst_b"] = manifest["links"]["burst_a"]
        with self.assertRaises(ValueError):
            capture_sources(manifest, CAPTURE_ROLES)

    def test_scenario_switch_rejects_a_hospital_uplink(self):
        adapter = GNS3("http://127.0.0.1", ".", PROFILE)
        adapter.manifest = {"project_id": "scenario", "nodes": {role: role for role in ROLE_IPS},
                            "links": {role: role for role in ROLE_IPS}, "switches": {"scenario": "isolated"}}
        nodes = {role: {"node_type": "docker", "properties": {"image": IMAGE, "adapters": 1,
                 "environment": f"LAB_ROLE={role}\nLAB_MODE=gns3\nLAB_PROFILE={PROFILE}"}} for role in ROLE_IPS}
        nodes["isolated"] = {"node_type": "ethernet_switch"}
        links = [{"link_id": role, "nodes": [{"node_id": role}, {"node_id": "isolated"}]} for role in ROLE_IPS]
        with patch.object(adapter, "api", return_value=links):
            adapter.validate_isolation(nodes)
            links.append({"link_id": "foreign", "nodes": [{"node_id": "gateway"}, {"node_id": "isolated"}]})
            with self.assertRaisesRegex(ValueError, "four isolated actors"):
                adapter.validate_isolation(nodes)

    def test_partial_dispatch_cancels_acknowledged_peer_and_persists_incomplete(self):
        self.exercise_dispatch(partial=True)

    def test_capture_interruption_cancels_both_agents_and_persists_result(self):
        self.exercise_dispatch(partial=False)

    def exercise_dispatch(self, partial):
        run_id = "a" * 32
        started, cancelled = set(), set()

        def agent(role, endpoint, data=None):
            if data is None:
                return {"command": {"run_id": run_id, "running": role not in cancelled} if role in started else None}
            if data["action"] == "start":
                if role == "burst_b" and partial:
                    raise RuntimeError("second agent unavailable")
                started.add(role)
                return {"run_id": run_id}
            if data["action"] == "cancel":
                cancelled.add(role)
                return {}
            return {"counts": {}}

        with TemporaryDirectory() as directory:
            coordinator = ScenarioRuns(SimpleNamespace(agent=agent, session=Path(directory)))
            record = {"run_id": run_id, "scenario_id": "udp-dual", "request_id": "request"}
            coordinator.active = record
            with patch("scenario_runs.DISPATCH_LEAD", 0.01), patch.object(
                coordinator, "check_context", side_effect=RuntimeError("recording interrupted")
            ):
                coordinator.run(record, SCENARIOS["udp-dual"], {})
            stored = json.loads((Path(directory) / "scenarios" / (run_id + ".json")).read_text())
        self.assertEqual(cancelled, {"burst_a", "burst_b"})
        self.assertEqual(set(stored["agents"]), started)
        self.assertEqual(stored["status"], "incomplete" if partial else "cancelled")
        self.assertIn("second agent" if partial else "recording interrupted", stored["reason"])
        self.assertFalse(coordinator.summary()["active"])

    def test_payload_requires_a_fixed_lab_envelope(self):
        run_id = "a" * 32
        raw = payload(run_id, "burst", 124)
        self.assertEqual(len(raw), 128)
        self.assertEqual(parse_payload(raw), (run_id, "burst", 124))
        self.assertIsNone(parse_payload(raw + b"x"))
        self.assertIsNone(parse_payload(b"unrelated".ljust(128, b".")))

    def test_scenario_rotation_keeps_committed_capture_evidence(self):
        with TemporaryDirectory() as directory:
            store = Mock()
            store.capture_watermarks.return_value = {}
            spool = Spool(directory, "burst_a", "scope", store, keep_evidence=True)
            spool.header = b"\x00" * 24
            spool.new_segment()
            old = spool.segments[0]
            old["bytes"] = 56
            spool.processed[old["id"]] = old["bytes"]
            spool.new_segment()
            spool.new_segment()
            self.assertFalse(old["path"].exists())
            self.assertEqual(len(spool.segments), 2)
            store.expire_raw.assert_not_called()


if __name__ == "__main__":
    unittest.main()
