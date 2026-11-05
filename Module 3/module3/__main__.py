import argparse
import json
import time
from pathlib import Path

from config import registry
from .input import stage
from .store import Store
from .sync import Worker


def main():
    parser = argparse.ArgumentParser(description="Module 3 evidence-based discovery and inventory")
    parser.add_argument("--state", default="runs/module3")
    parser.add_argument("--registry", help="JSON IP-to-record/list mapping; defaults to config.registry('gns3')")
    parser.add_argument("--direct-links", help="JSON capture-source-to-directly-attached-IP mapping; absent means no device MAC binding")
    parser.add_argument("--activity-window", type=int, default=300)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("serve", "sync-once"):
        p = sub.add_parser(command)
        p.add_argument("--upstream", default="http://127.0.0.1:8878")
        p.add_argument("--scope", action="append")
        if command == "serve":
            p.add_argument("--port", type=int, default=8879)
            p.add_argument("--interval", type=float, default=5)
            p.add_argument("--offline", action="store_true")
    p = sub.add_parser("import")
    p.add_argument("input")
    p.add_argument("--legacy", action="store_true", help="Import canonical monitoring JSONL rather than framed snapshot")
    p.add_argument("--source-id")
    p.add_argument("--scope")
    sub.add_parser("status")
    p = sub.add_parser("export")
    p.add_argument("output")
    p.add_argument("--scope")
    args = parser.parse_args()
    if args.activity_window < 1 or getattr(args, "interval", 5) < .1:
        parser.error("Activity window must be positive; polling interval must be >= 0.1 seconds")
    mapping = json.loads(Path(args.registry).read_text()) if args.registry else registry("gns3")
    links = json.loads(Path(args.direct_links).read_text()) if args.direct_links else {}
    store = Store(Path(args.state)/"inventory.sqlite3", mapping, links, args.activity_window)
    if args.command == "import":
        with Path(args.input).open("rb") as stream, stage(iter(lambda: stream.readline(8*1024*1024+1), b""), args.source_id, args.scope, args.legacy) as (db, header):
            print(json.dumps(store.apply(db, header), indent=2))
            store.setting("input", {"state": "imported_snapshot", "last_success": time.time(), "source_id": header["source_id"], "scope": header["scope"], "live": False})
    elif args.command == "status":
        print(json.dumps(store.status(), indent=2))
    elif args.command == "export":
        with Path(args.output).open("wb") as stream:
            for raw in store.export(scope=args.scope):
                stream.write(raw)
    elif args.command == "sync-once":
        print(json.dumps(Worker(store, args.upstream, args.scope).once(), indent=2))
    else:
        from .server import serve
        serve(store, None if args.offline else Worker(store, args.upstream, args.scope, args.interval), args.port)


if __name__ == "__main__":
    main()
