"""Launch Module 2 independently, preserving Module 1 on port 8877."""
import argparse
import getpass
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request
import webbrowser

ROOT = Path(__file__).resolve().parent
URL = "http://127.0.0.1:8878/"


def ready():
    try:
        with urllib.request.urlopen(URL+"api/ready", timeout=2) as response:
            return json.load(response).get("app") == "hiot-module2"
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sensor-host", default="192.168.209.142")
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--state", default="runs/module2")
    args = parser.parse_args()
    if not ready():
        (ROOT / "runs").mkdir(exist_ok=True)
        python = ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        environment = os.environ.copy()
        if not environment.get("GNS3_SSH_PASSWORD"):
            environment["GNS3_SSH_PASSWORD"] = getpass.getpass("GNS3 VM SSH password (blank for configured SSH key): ")
        with (ROOT / "runs" / "module2-server.log").open("a") as log:
            process = subprocess.Popen([str(python), "-m", "module2", "--state", args.state, "--sensor-host", args.sensor_host, "serve"],
                                       cwd=ROOT, stdout=log, stderr=log, env=environment,
                                       creationflags=(subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS) if os.name == "nt" else 0,
                                       start_new_session=os.name != "nt")
        # Existing databases may need a one-time indexed-view migration.
        for _ in range(900):
            if ready():
                break
            if process.poll() is not None:
                raise RuntimeError("Module 2 startup failed; inspect runs/module2-server.log")
            time.sleep(.2)
        else:
            raise RuntimeError("Module 2 did not become ready")
    print(URL)
    if not args.no_browser:
        webbrowser.open(URL)


if __name__ == "__main__":
    main()
