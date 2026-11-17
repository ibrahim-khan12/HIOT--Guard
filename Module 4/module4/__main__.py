"""Module 4 offline commands."""
import argparse
import json
from pathlib import Path

from .experiment import VERSION, decisions, evaluate, load_json, train, write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    fit = commands.add_parser("train")
    fit.add_argument("--train", type=Path, required=True)
    fit.add_argument("--validation", type=Path, required=True)
    fit.add_argument("--output", type=Path, required=True)
    for name, input_name in (("predict", "recording"), ("evaluate", "holdout")):
        command = commands.add_parser(name)
        command.add_argument("--" + input_name, type=Path, required=True)
        command.add_argument("--model", type=Path, required=True, help="Trusted artifact produced locally by train")
        command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "train":
        print(json.dumps(train(args.train, args.validation, args.output), indent=2))
        return
    from joblib import load

    model = load(args.model)
    if model.get("version") != VERSION:
        parser.error("Unsupported classifier version")
    if args.command == "predict":
        write_json(args.output, {"version": VERSION, "predictions": decisions(load_json(args.recording), model)})
    else:
        report, predictions = evaluate(args.holdout, model)
        args.output.mkdir(parents=True)
        write_json(args.output / "report.json", report)
        write_json(args.output / "predictions.json", {"version": VERSION, "predictions": predictions})
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
