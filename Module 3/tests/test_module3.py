"""Discovery invariants and actual loopback API integration, without a VM."""
import copy
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import Mock
from urllib.request import urlopen
from urllib.error import HTTPError

from module2.discovery import revision, snapshot
from module2.store import Store as MonitoringStore
from module2.server import handler as monitoring_handler
from module3.input import stage, encode
from module3.store import Store
from module3.sync import Worker
from module3.server import handler


def flow(key="a", **kwargs):
    f = {"schema_version": "hiot.monitoring.v1", "flow_id": key, "observation_id": key,
         "capture_id": "cap", "scope": "test", "source_ip": "10.77.20.20", "destination_ip": "10.77.30.40",
         "source_port": 40000, "destination_port": 2575, "transport": "tcp", "start_time": 100., "duration": 1.,
         "origin_packets": 4, "response_packets": 3, "evidence": [], "observation_source": "pump",
         "connection_state": "SF", "correlation_status": "syn_fingerprint"}
    f.update(kwargs)
    return f


def medical(**kwargs):
    return {"capture_id": "cap", "observation_id": "a", "frame": 2, "timestamp": 100.1,
            "protocol": "HL7/MLLP", "parser_status": "confirmed", "metadata": {"sender": "LAB_PUMP"}, **kwargs}


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)/"inventory.sqlite3"
        self.store = Store(self.path, {"10.77.20.20": {"role": "pump"}, "10.77.20.99": {"role": "silent"}})

    def tearDown(self):
        self.tmp.cleanup()

    def apply(self, flows, scope="test", source="sensor"):
        with stage((encode(f)+"\n" for f in flows), source, scope, True) as (db, header):
            return self.store.apply(db, header)

    def byip(self, ip):
        return next(a for a in self.store.assets()["records"] if a["ip"] == ip)

    def test_both_endpoints_and_silent_registry(self):
        self.apply([flow()])
        self.assertEqual(self.store.status()["asset_count"], 2)
        self.assertEqual(self.store.status()["configured_unobserved"][0]["ip"], "10.77.20.99")
        self.assertEqual(self.byip("10.77.20.20")["presence"], "observed_transmitting")
        self.assertEqual(self.byip("10.77.30.40")["configured"]["match"], "unregistered")

    def test_target_without_reply_is_not_live(self):
        self.apply([flow(response_packets=0, connection_state="S0")])
        self.assertEqual(self.byip("10.77.30.40")["presence"], "addressed_only")

    def test_missing_packet_counts_unresolved(self):
        self.apply([flow(origin_packets=None, response_packets=None)])
        self.assertTrue(all(a["presence"] == "unresolved" for a in self.store.assets()["records"]))

    def test_missing_mac_and_port_only_hint(self):
        self.apply([flow()])
        a = self.byip("10.77.20.20")
        self.assertEqual(a["protocols"], [])
        self.assertEqual(a["mac_observations"], [])
        self.assertIn("mac_not_available", a["unknown"])

    def test_protocol_not_device_identity(self):
        self.apply([flow(evidence=[medical()])])
        a = self.byip("10.77.20.20")
        self.assertEqual(a["protocols"], ["HL7/MLLP"])
        self.assertIn("device_category", a["unknown"])

    def test_replay_and_random_uid_idempotent(self):
        self.apply([flow(zeek_uid="random1")])
        n = self.store.status()["events"]
        result = self.apply([flow(zeek_uid="random2")])
        self.assertEqual(result["changed_flows"], 0)
        self.assertEqual(n, self.store.status()["events"])

    def test_updated_old_flow_and_restart(self):
        self.apply([flow()])
        self.apply([flow(evidence=[medical()], duration=4)])
        self.store = Store(self.path)
        self.assertEqual(self.byip("10.77.20.20")["last_seen"], 104)
        self.assertEqual(self.byip("10.77.20.20")["protocols"], ["HL7/MLLP"])

    def test_removed_flow_withdraws_contribution_preserves_history(self):
        self.apply([flow(), flow("b", source_ip="10.77.20.31")])
        key = self.byip("10.77.20.20")["asset_id"]
        self.apply([flow("b", source_ip="10.77.20.31")])
        self.assertEqual(self.store.status()["asset_count"], 2)
        self.assertFalse(self.store.asset(key)["current"])
        self.assertEqual(self.store.events(key)["records"][0]["kind"], "observations_withdrawn")

    def test_return_after_inactivity(self):
        self.apply([flow()])
        self.apply([flow(), flow("b", start_time=1000)])
        a = self.byip("10.77.20.20")
        self.assertEqual(self.store.events(a["asset_id"])["records"][0]["kind"], "returned")

    def test_evidence_correction_audited_even_if_profile_unchanged(self):
        self.apply([flow(evidence=[medical()])])
        self.apply([flow(evidence=[medical(frame=3)])])
        events = self.store.events(self.byip("10.77.20.20")["asset_id"])["records"]
        correction = next(e for e in events if e["kind"] == "upstream_flow_updated")
        self.assertEqual(correction["data"]["previous_flow"]["evidence"][0]["frame"], 2)
        self.assertEqual(correction["data"]["current_flow"]["evidence"][0]["frame"], 3)

    def test_scopes_and_sources_do_not_merge(self):
        self.apply([flow()])
        self.apply([flow(scope="other")], "other")
        self.apply([flow()], source="other_sensor")
        self.assertEqual(self.store.status()["asset_count"], 6)

    def test_ipv6_udp_and_icmp(self):
        self.apply([flow(source_ip="2001:db8::1", destination_ip="2001:db8::2", transport="udp"),
                    flow("b", transport="icmp", source_port=None, destination_port=None)])
        self.assertEqual(self.store.status()["asset_count"], 4)

    def test_routed_mac_requires_explicit_direct_context(self):
        e = medical(protocol=None, mac="aa:bb:cc:dd:ee:ff", ethernet_direction="destination", network_source_ip="10.77.20.20", network_destination_ip="10.77.30.40", observation_source="pump")
        self.apply([flow(link_layer_evidence=[e])])
        a = self.byip("10.77.30.40")
        self.assertEqual(a["mac_observations"][0]["association"], "unresolved_link_observation")

    def test_multiple_direct_link_macs_preserve_review_evidence(self):
        self.store.direct_links = {"pump": "10.77.20.20"}
        def mac(address):
            return medical(mac=address, ethernet_direction="source", network_source_ip="10.77.20.20", network_destination_ip="10.77.30.40", observation_source="pump")
        self.apply([flow(link_layer_evidence=[mac("aa:bb:cc:dd:ee:01"), mac("aa:bb:cc:dd:ee:02")])])
        self.assertIn("multiple_macs_on_configured_direct_link", self.byip("10.77.20.20")["review_findings"])
        self.assertEqual(len(self.byip("10.77.20.20")["mac_observations"]), 2)

    def test_offline_activity_anchors_to_capture_time(self):
        self.apply([flow()])
        self.assertEqual(self.byip("10.77.20.20")["activity"]["state"], "recently_observed")
        self.assertEqual(self.byip("10.77.20.20")["activity"]["anchor"], "capture_time")

    def test_multicast_address_not_physical_asset_claim(self):
        self.apply([flow(destination_ip="ff02::2", response_packets=0)])
        self.assertEqual(self.byip("ff02::2")["address_kind"], "multicast_group")

    def test_conflicts_preserved_not_attacks(self):
        self.store.registry["10.77.20.20"] = [{"role": "pump"}, {"role": "monitor"}]
        self.apply([flow(evidence=[medical(), medical(frame=3, metadata={"sender": "OTHER"})])])
        a = self.byip("10.77.20.20")
        self.assertEqual(len(a["configured"]["records"]), 2)
        self.assertEqual(len(a["review_findings"]), 2)

    def test_registry_change_event(self):
        self.apply([flow()])
        self.store.registry["10.77.20.20"] = {"role": "changed"}
        self.apply([flow()])
        self.assertEqual(self.store.events(self.byip("10.77.20.20")["asset_id"])["records"][0]["kind"], "registry_changed")

    def test_legacy_missing_capture_metadata_disclosed(self):
        self.apply([flow(evidence=[medical()])])
        e = self.store.related(self.byip("10.77.20.20")["asset_id"], True)
        self.assertEqual(e["records"][0]["captures"][0]["status"], "unknown_imported_metadata")

    def test_pagination_export_and_filters(self):
        self.apply([flow(), flow("b", source_ip="10.77.20.31")])
        first = self.store.assets(limit=1)
        self.assertEqual(first["next_offset"], 1)
        self.assertEqual(self.store.assets(registered=0)["total"], 2)
        self.assertEqual(len(list(self.store.export(registered=0))), 2)

    def test_invalid_data_never_replaces_inventory(self):
        self.apply([flow()])
        for kwargs in ({"source_ip": "bad"}, {"start_time": float("nan")}, {"response_packets": -1}, {"evidence": [medical(frame=0)]}, {"schema_version": "v99"}):
            with self.assertRaises(ValueError):
                self.apply([flow(**kwargs)])
        self.assertEqual(self.store.status()["canonical_flow_count"], 1)


class SnapshotTests(unittest.TestCase):
    apply = InventoryTests.apply
    byip = InventoryTests.byip
    def setUp(self):
        InventoryTests.setUp(self)
        self.monitor = MonitoringStore(Path(self.tmp.name)/"monitoring.sqlite3")
        # Populate the actual canonical table without invoking a remote sensor.
        self.put([flow()])

    def tearDown(self):
        self.monitor.close()
        InventoryTests.tearDown(self)

    def put(self, flows):
        with self.monitor.write() as db:
            db.execute("DELETE FROM canonical")
            for f in flows:
                db.execute("INSERT INTO canonical VALUES(?,?,?,?,?,?,?)", (f["flow_id"], f["scope"], f["start_time"], f["transport"], "", "[]", encode(f)))
            db.execute("INSERT OR REPLACE INTO captures VALUES('cap','test','pump',1,?)", (encode({"capture_id": "cap", "scope": "test", "raw_retained": True, "sha256": "hash"}),))
            db.execute("UPDATE flow_revision SET version=version+1")

    def consume(self, lines):
        with stage(lines) as (db, header):
            return self.store.apply(db, header)

    def test_snapshot_digest_truncation_duplicate_and_wrong_scope(self):
        lines = list(snapshot(self.monitor, "test"))
        self.consume(lines)
        for broken in (lines[:-1], lines+[lines[-1]], [lines[0]]+lines[2:], [lines[0].replace(b'"test"', b'"wrong"')]+lines[1:]):
            with self.assertRaises(ValueError):
                self.consume(broken)
        self.assertEqual(self.store.status()["canonical_flow_count"], 1)

    def test_snapshot_empty_scope_clears_current_inventory(self):
        self.consume(snapshot(self.monitor, "test"))
        self.put([])
        self.consume(snapshot(self.monitor, "test"))
        self.assertEqual(self.store.status()["asset_count"], 0)

    def test_capture_expiry_advances_revision(self):
        self.consume(snapshot(self.monitor, "test"))
        before = revision(self.monitor)["revision"]
        with self.monitor.write() as db:
            db.execute("UPDATE captures SET data=json_set(data,'$.raw_retained',json('false'))")
        self.assertGreater(revision(self.monitor)["revision"], before)
        self.consume(snapshot(self.monitor, "test"))
        key = self.store.assets()["records"][0]["asset_id"]
        self.assertEqual(self.store.related(key, True)["records"][0]["captures"][0]["status"], "unavailable")

    def test_concurrent_write_does_not_mix_snapshot_revisions(self):
        iterator = snapshot(self.monitor, "test")
        header = next(iterator)
        self.put([flow("new", source_ip="10.77.20.99")])
        self.consume([header]+list(iterator))
        self.assertEqual(self.store.assets(q="10.77.20.99")["total"], 0)
        self.consume(snapshot(self.monitor, "test"))
        self.assertEqual(self.store.assets(q="10.77.20.99")["total"], 1)


    def test_real_http_worker_outage_recovery_and_inventory_api(self):
        live = Mock()
        live.running, live.interval, live.scope = False, 5, None
        live.status.return_value = {"state": "stopped"}
        server = ThreadingHTTPServer(("127.0.0.1", 0), monitoring_handler(self.monitor, live, 0))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        worker = Worker(self.store, "http://127.0.0.1:"+str(server.server_port))
        try:
            worker.once()
            n = self.store.status()["events"]
            self.assertEqual(worker.once(), [])
            self.assertEqual(self.store.status()["events"], n)
            api = ThreadingHTTPServer(("127.0.0.1", 0), handler(self.store))
            t = threading.Thread(target=api.serve_forever, daemon=True); t.start()
            try:
                base = "http://127.0.0.1:"+str(api.server_port)
                with urlopen(base+"/api/assets?limit=1") as r:
                    self.assertEqual(json.load(r)["total"], 2)
                with urlopen(base+"/api/export.jsonl?registered=0") as r:
                    self.assertEqual(len(r.readlines()), 1)
                with self.assertRaises(HTTPError):
                    urlopen(base+"/api/assets?limit=-1")
            finally:
                api.shutdown(); api.server_close(); t.join()
            worker.url = "http://127.0.0.1:1"
            with self.assertRaises(Exception): worker.once()
            self.assertEqual(self.store.status()["asset_count"], 2)
            self.assertEqual(self.store.status()["input"]["state"], "unavailable")
            worker.url = "http://127.0.0.1:"+str(server.server_port)
            worker.once()
            self.assertEqual(self.store.status()["input"]["state"], "connected")
        finally:
            server.shutdown(); server.server_close(); thread.join()


class MacParserTests(unittest.TestCase):
    def test_module2_mac_extraction_and_historical_tsv(self):
        import csv
        from test_module2 import fixture
        from module2.parsing import normalize
        from module2.sensor import FIELDS
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            fixture(path)
            with (path/"packets.tsv").open() as source:
                rows = list(csv.reader(source, delimiter="\t"))
            for r in rows:
                r[FIELDS.index("eth.src")] = "02:00:00:00:00:01"
                r[FIELDS.index("eth.dst")] = "02:00:00:00:00:02"
            with (path/"packets.tsv").open("w", newline="") as out:
                csv.writer(out, delimiter="\t").writerows(rows)
            flows, _, _ = normalize(path, "cap", "pump", "test")
            self.assertTrue(flows[0]["link_layer_evidence"])
            self.assertEqual(flows[0]["link_layer_evidence"][0]["capture_id"], "cap")
            self.assertEqual(flows[0]["link_layer_evidence"][0]["association"], "link_observation_only")
            with (path/"packets.tsv").open("w", newline="") as out:
                csv.writer(out, delimiter="\t").writerows(r[:-2] for r in rows)
            flows, _, _ = normalize(path, "cap", "pump", "test")
            self.assertEqual(flows[0]["link_layer_evidence"], [])


if __name__ == "__main__":
    unittest.main()
