import argparse
import json
import shutil
import time
from pathlib import Path

from config import registry
from .input import stage
from .store import Store, recording
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
            assessment = p.add_mutually_exclusive_group()
            assessment.add_argument("--classification", help="Revision-bound Module 4 workflow projection JSON")
            assessment.add_argument("--live-assessment-root", type=Path,
                                    help="Read retained captures from this directory for one explicit --scope")
            p.add_argument("--assessment-tshark", help="TShark executable for live assessment")
            p.add_argument("--assessment-window", type=int, choices=(10, 30, 60, 120), default=120)
            p.add_argument("--module4-evaluation", type=Path, help="Saved Module 4 final-study report.json to display")
    p = sub.add_parser("import")
    p.add_argument("input")
    p.add_argument("--legacy", action="store_true", help="Import canonical monitoring JSONL rather than framed snapshot")
    p.add_argument("--source-id")
    p.add_argument("--scope")
    sub.add_parser("status")
    p = sub.add_parser("export")
    p.add_argument("output")
    p.add_argument("--scope")
    p = sub.add_parser("export-recording")
    p.add_argument("output")
    p.add_argument("--source-id", required=True)
    p.add_argument("--scope", required=True)
    args = parser.parse_args()
    if args.activity_window < 1 or getattr(args, "interval", 5) < .1:
        parser.error("Activity window must be positive; polling interval must be >= 0.1 seconds")
    if args.command == "export-recording":
        try:
            data = recording(Path(args.state)/"inventory.sqlite3", args.source_id, args.scope)
            with Path(args.output).open("x", encoding="utf-8") as output:
                json.dump(data, output, indent=2)
                output.write("\n")
        except (OSError, ValueError) as error:
            parser.error(str(error))
        return
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
        from .classification import Classification, LiveClassification
        from .evaluation import load_evaluation
        try:
            evaluation = load_evaluation(args.module4_evaluation) if args.module4_evaluation else None
        except (OSError, ValueError) as error:
            parser.error(f"Cannot load Module 4 evaluation: {error}")
        classification = Classification(args.classification) if args.classification else None
        if args.live_assessment_root:
            if not args.scope or len(args.scope) != 1:
                parser.error("--live-assessment-root requires one explicit --scope")
            tshark = shutil.which(args.assessment_tshark or "tshark")
            if tshark is None:
                parser.error("TShark is required for live assessment; use --assessment-tshark to specify its path")
            try:
                classification = LiveClassification(store, args.scope[0], args.live_assessment_root, tshark,
                                                    args.assessment_window, args.interval)
            except (OSError, ValueError, ImportError) as error:
                parser.error(str(error))
        worker = None if args.offline else Worker(store, args.upstream, args.scope, args.interval)
        serve(store, worker, args.port, classification, evaluation=evaluation)


if __name__ == "__main__":
    main()
