"""Real sensor acceptance with saved captures and optional isolated GNS3 live feed."""
import argparse
from collections import Counter
import json
from pathlib import Path
import time

from config import NORMAL_ROLES
from module2.live import Live
from module2.pipeline import Pipeline
from module2.sensor import Sensor
from module2.store import Store


def run(args):
    state = Path(args.state).resolve()
    store = Store(state / "monitoring.sqlite3")
    scope = "acceptance-" + str(time.time_ns())
    report = {"started": time.time(), "scope": scope, "checks": [], "passed": False}
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    def check(name, success, **facts):
        report["checks"].append({"name": name, "passed": bool(success), **facts})
        print(("PASS " if success else "FAIL ") + name, flush=True)
        output.write_text(json.dumps(report, indent=2))
        if not success:
            raise AssertionError(name)

    sensor = Sensor(args.sensor_host, state)
    pipeline = Pipeline(store, state, sensor)
    try:
        captures = [pipeline.import_file(Path(args.captures)/name, source, scope)
                    for name, source in (("modality.pcap", "modality"), ("pump.pcap", "pump"))]
        records = store.flows(scope=scope, limit=100000)
        tcp = [r for r in records if r["transport"] == "tcp"]
        reference = sum(c["reference"]["independent_unique_syns"] for c in captures)
        check("Offline connection totals match independent SYN reference", len(tcp) == reference,
              tcp_connections=len(tcp), independent_syn_connections=reference,
              per_capture=[{"source": c["observation_source"], "frames": c["frames"], "reference": c["reference"],
                            "sha256": c["sha256"], "analysis_seconds": c["analysis_seconds"]} for c in captures])
        dicom = [e for r in tcp for e in r["evidence"] if e["protocol"] == "DICOM"]
        hl7 = [e for r in tcp for e in r["evidence"] if e["protocol"] == "HL7/MLLP"]
        check("Captured DICOM association confirms CT to PACS", any(e["metadata"].get("calling_ae") == "LAB_CT" and e["metadata"].get("called_ae") == "LAB_PACS" for e in dicom), sample=dicom[:2])
        check("Captured pump ORU and EHR ACK metadata", any(e["metadata"].get("sender") == "LAB_PUMP" and e["metadata"].get("message_type") == "ORU^R01" for e in hl7)
              and any(e["metadata"].get("message_type", "").startswith("ACK") for e in hl7), sample=hl7[:2])
        identifiers = {r["flow_id"] for r in records}
        for name, source in (("modality.pcap", "modality"), ("pump.pcap", "pump")):
            pipeline.import_file(Path(args.captures)/name, source, scope, force=True)
        check("Forced repeated analysis is idempotent despite fresh Zeek UIDs", identifiers == {r["flow_id"] for r in store.flows(scope=scope, limit=100000)})
        pipeline.import_file(Path(args.captures)/"modality.pcap", "modality_mirror", scope)
        after = store.flows(scope=scope, limit=100000)
        check("Overlapping TCP capture does not inflate canonical connection totals", len([r for r in after if r["transport"] == "tcp"]) == reference,
              correlated_tcp=sum(r["observation_count"] > 1 for r in after if r["transport"] == "tcp"),
              note="Non-SYN ICMP observations deliberately remain separate")
        bad = state/"acceptance-truncated.pcap"
        bad.write_bytes((Path(args.captures)/"pump.pcap").read_bytes()[:-1])
        rejected = False
        try:
            pipeline.import_file(bad, "evaluation:malformed-pcap", scope)
        except ValueError:
            rejected = True
        finally:
            bad.unlink(missing_ok=True)
        store.health("evaluation:malformed-pcap", expected_failure=True)
        check("Truncated input refused and error recorded", rejected and any(h["source"] == "evaluation:malformed-pcap" and h.get("error") for h in store.status()["health"]))
        check("Every analytical record has capture and observation provenance", all(r["capture_id"] and r["observation_id"] and all(e["capture_id"] and e["frame"] for e in r["evidence"]) for r in after))
        report["sensor"] = sensor.versions
        report["offline_issues"] = store.status(scope)["issues"]
        report["background_transports"] = dict(Counter(r["transport"] for r in after))
    finally:
        sensor.close()

    if args.live:
        sensors = []
        def factory():
            sensor = Sensor(args.sensor_host, state)
            sensors.append(sensor)
            return sensor
        live = Live(store, state, factory, args.manifest, interval=5)
        try:
            live.start()
            print("Waiting for the first passive live analysis cycle (no browser is used)...", flush=True)
            deadline = time.time()+240
            while time.time() < deadline:
                seen = {c["observation_source"] for c in store.status(live.scope)["captures"]}
                if set(NORMAL_ROLES).issubset(seen):
                    break
                time.sleep(2)
            before = store.status(live.scope)
            check("All 12 normal sources analyzed independently of a browser", set(NORMAL_ROLES).issubset({c["observation_source"] for c in before["captures"]}),
                  scope=live.scope, capture_sources=[c["observation_source"] for c in before["captures"]])
            old_time = max(c["processed_at"] for c in before["captures"] if c["observation_source"] == "pump")
            with live.lock:
                pump_stream = live.streams.get("pump")
            if pump_stream:
                pump_stream.close()
            deadline = time.time()+180
            while time.time() < deadline:
                status = store.status(live.scope)
                pump_health = next((h for h in status["health"] if h["source"] == "pump"), {})
                pump_captures = [c for c in status["captures"] if c["observation_source"] == "pump"]
                if pump_health.get("reconnects", 0) and any(c["processed_at"] > old_time and c["capture_id"] != next(x["capture_id"] for x in before["captures"] if x["observation_source"] == "pump") for c in pump_captures):
                    break
                time.sleep(2)
            check("Interrupted pump reader reconnects and analyzes a new capture segment", pump_health.get("reconnects", 0) >= 1 and any(c["processed_at"] > old_time for c in pump_captures), health=pump_health)
            if args.sensor_recovery:
                deadline = time.time()+60
                victim = None
                while time.time() < deadline:
                    victim = next((s for s in reversed(sensors) if s.connected()), None)
                    if victim:
                        break
                    time.sleep(.2)
                if not victim:
                    raise AssertionError("No owned live sensor SSH connection available for interruption")
                connections_before, interrupted_at = len(sensors), time.time()
                # Only this acceptance runner's SSH connection is interrupted, never the VM or another service.
                victim.client.close()
                deadline, saw_failure, recovered = time.time()+300, False, False
                while time.time() < deadline:
                    health = store.status(live.scope)["health"]
                    sensor_health = next((h for h in health if h["source"] == "sensor"), {})
                    saw_failure |= bool(sensor_health.get("error"))
                    fresh = {h["source"] for h in health if h.get("analyzed_at", 0) > interrupted_at and not h.get("analysis_error")}
                    recovered = saw_failure and len(sensors) > connections_before and set(NORMAL_ROLES).issubset(fresh) and not sensor_health.get("error")
                    if recovered:
                        break
                    time.sleep(1)
                check("Interrupted owned sensor SSH reconnects and all normal sources resume analysis", recovered,
                      interrupted_at=interrupted_at, observed_failure=saw_failure,
                      fresh_sources=sorted(fresh), new_ssh_connections=len(sensors)-connections_before,
                      recovery_seconds=time.time()-interrupted_at)
            measurements = []
            for c in store.status(live.scope)["captures"]:
                flows = [r for r in store.flows(scope=live.scope, limit=100000) if c["capture_id"] in {e["capture_id"] for e in r["evidence"]}]
                newest = max((r["start_time"]+(r["duration"] or 0) for r in flows), default=None)
                measurements.append({"source": c["observation_source"], "analysis_seconds": c["analysis_seconds"],
                                     "snapshot_bytes": c["bytes"], "latest_medical_flow_age_at_analysis": max(0, c["processed_at"]-newest) if newest else None})
            report["live_measurements"] = measurements
            report["live_capture_loss"] = "Unavailable; not represented as zero"
        finally:
            live.stop()
    report.update(passed=all(c["passed"] for c in report["checks"]), finished=time.time())
    output.write_text(json.dumps(report, indent=2))
    store.export(output.with_suffix(".jsonl"))
    print(str(output.resolve()), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--captures", required=True)
    parser.add_argument("--state", default="runs/module2")
    parser.add_argument("--sensor-host", default="192.168.209.142")
    parser.add_argument("--manifest", default="runs/gns3-hospital-v2-manifest.json")
    parser.add_argument("--output", default="runs/module2/acceptance-report.json")
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--sensor-recovery", action="store_true", help="With --live, interrupt only this runner's sensor SSH and verify recovery")
    args = parser.parse_args()
    if args.sensor_recovery and not args.live:
        parser.error("--sensor-recovery requires --live")
    run(args)
