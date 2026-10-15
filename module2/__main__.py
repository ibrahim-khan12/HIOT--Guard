import argparse
import json
from pathlib import Path

from .sensor import Sensor
from .store import Store
from .pipeline import Pipeline
from .live import Live


def main():
    parser = argparse.ArgumentParser(description="HIoT Module 2 passive monitoring")
    parser.add_argument("--state", default="runs/module2")
    parser.add_argument("--sensor-host", default="192.168.209.142")
    parser.add_argument("--sensor-user", default="gns3")
    sub = parser.add_subparsers(dest="command", required=True)
    setup = sub.add_parser("setup-sensor")
    setup.add_argument("--trust-first-use", action="store_true", help="Record the lab VM SSH key on initial setup only")
    ingest = sub.add_parser("import")
    ingest.add_argument("capture")
    ingest.add_argument("--source", required=True)
    ingest.add_argument("--scope", required=True)
    ingest.add_argument("--force", action="store_true")
    export = sub.add_parser("export")
    export.add_argument("output")
    sub.add_parser("status")
    server = sub.add_parser("serve")
    server.add_argument("--manifest", default="runs/gns3-hospital-v2-manifest.json")
    server.add_argument("--port", default=8878, type=int)
    server.add_argument("--interval", default=20, type=int)
    args = parser.parse_args()
    state = Path(args.state).resolve()
    store = Store(state / "monitoring.sqlite3")
    factory = lambda: Sensor(args.sensor_host, state, args.sensor_user)
    if args.command == "setup-sensor":
        sensor = Sensor(args.sensor_host, state, args.sensor_user, args.trust_first_use)
        try:
            print(json.dumps(sensor.setup(), indent=2))
        finally:
            sensor.close()
    elif args.command == "import":
        sensor = factory()
        try:
            print(json.dumps(Pipeline(store, state, sensor).import_file(args.capture, args.source, args.scope, force=args.force), indent=2))
        finally:
            sensor.close()
    elif args.command == "export":
        store.export(args.output)
        print(str(Path(args.output).resolve()))
    elif args.command == "status":
        print(json.dumps(store.status(), indent=2))
    elif args.command == "serve":
        if not 5 <= args.interval <= 300:
            parser.error("interval must be 5..300 seconds")
        from .server import serve
        serve(store, Live(store, state, factory, args.manifest, args.interval), args.port)


if __name__ == "__main__":
    main()
