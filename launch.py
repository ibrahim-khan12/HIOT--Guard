import json
import os
import subprocess
import sys
import time
import urllib.request
import venv
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
URL = "http://127.0.0.1:8877/"


def ready():
    try:
        with urllib.request.urlopen(URL + "api/status", timeout=2) as response:
            return json.load(response).get("app") == "iomt-live-v1"
    except Exception:
        return False


def main():
    if not ready():
        environment = ROOT / ".venv"
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        if not python.exists():
            print("Preparing the isolated live-lab environment...", flush=True)
            venv.create(environment, with_pip=True)
        if subprocess.run([str(python), "-c", "import pynetdicom, pydicom"], capture_output=True).returncode:
            subprocess.run([str(python), "-m", "pip", "install", "-r", str(ROOT / "requirements.txt")], check=True)
        log = (ROOT / "server.log").open("a")
        server = subprocess.Popen([str(python), str(ROOT / "server.py")], cwd=ROOT, stdout=log, stderr=log,
                                  creationflags=(subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS) if os.name == "nt" else 0,
                                  start_new_session=os.name != "nt")
        log.close()
        for _ in range(30):
            if ready():
                break
            if server.poll() is not None:
                raise RuntimeError("Live lab startup failed. Check iomt-live/server.log")
            time.sleep(0.2)
        else:
            raise RuntimeError("Live lab did not become ready. Check iomt-live/server.log")
    print("Live IoMT lab: " + URL, flush=True)
    if "--no-browser" not in sys.argv:
        webbrowser.open(URL)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
