"""Connect an imported GNS3 portable topology to this lab's local console."""
import argparse
from pathlib import Path
from gns3 import GNS3


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gns3", required=True, help="Private GNS3 2.2 controller URL")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--project-name", help="Exact name shown in the GNS3 project list")
    target.add_argument("--project-id", help="GNS3 project UUID")
    args = parser.parse_args()
    adapter = GNS3(args.gns3, Path(__file__).resolve().parent / "runs")
    project_id = args.project_id
    if args.project_name:
        matches = [project for project in adapter.api("/projects") if project.get("name") == args.project_name]
        if len(matches) != 1:
            raise ValueError(f"Expected one project named {args.project_name!r}; found {len(matches)}")
        project_id = matches[0]["project_id"]
    manifest = adapter.attach_imported(project_id)
    print(f"Attached {manifest['project_name']} ({manifest['project_id']})")
    print("Open the local console and select GNS3 routed lab -> Start session.")


if __name__ == "__main__":
    main()
