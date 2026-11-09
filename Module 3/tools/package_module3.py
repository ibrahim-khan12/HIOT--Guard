"""Build and smoke-test a tracked-source Module 3 delivery ZIP; no deployment."""
import _bootstrap
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = _bootstrap.ROOT
PREFIX = "hiot-guard-module3"
INCLUDE = ["Module 3", "module3/__init__.py", "module2", "config.py", "gns3.py",
           "requirements.txt", "requirements-module2.txt", "test_module2.py", "MODULE2.md"]
REQUIRED = {"Module 3/module3/__main__.py", "Module 3/module3/server.py",
            "Module 3/module3/index.html", "Module 3/module3/app.js",
            "Module 3/tests/test_module3.py", "Module 3/tools/package_module3.py",
            "module3/__init__.py", "module2/discovery.py", "config.py",
            "gns3.py", "requirements-module2.txt", "requirements.txt", "test_module2.py"}
FORBIDDEN = {"runs", ".git", ".venv", "node_modules", "__pycache__"}


def git(*args):
    command = shutil.which("git")
    if not command:
        candidate = Path.home()/".cache/codex-runtimes/codex-primary-runtime/dependencies/native/git/cmd/git.exe"
        if candidate.exists():
            command = str(candidate)
    if not command:
        raise RuntimeError("Git is required to build from committed source")
    return subprocess.check_output([command, "-c", "safe.directory="+ROOT.as_posix(), *args], cwd=ROOT)


def build(output):
    commit = git("rev-parse", "HEAD").decode().strip()
    paths = [p.decode() for p in git("ls-tree", "-r", "--name-only", "-z", commit, "--", *INCLUDE).split(b"\0") if p]
    if not REQUIRED.issubset(paths):
        raise ValueError("Commit the delivery sources before packaging: "+str(sorted(REQUIRED-set(paths))))
    for name in paths:
        path = Path(name)
        if FORBIDDEN.intersection(path.parts) or path.suffix.lower() in (".pcap", ".pcapng", ".sqlite3", ".db", ".pyc"):
            raise ValueError("Runtime/private artifact in source allowlist: "+name)
    output.mkdir(parents=True, exist_ok=True)
    target = output/"hiot-guard-module3.zip"
    manifest = {"schema_version": "hiot.module3.delivery.v1", "source_commit": commit,
                "source_repository": "https://github.com/ibrahim-khan12/HIOT--Guard",
                "delivery": "Tested source package, not a deployed hospital service", "files": {}}
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(paths):
            data = git("show", commit+":"+name)
            manifest["files"][name] = hashlib.sha256(data).hexdigest()
            entry = zipfile.ZipInfo(PREFIX+"/"+name, (1980, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, data)
        entry = zipfile.ZipInfo(PREFIX+"/MANIFEST.json", (1980, 1, 1, 0, 0, 0))
        entry.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(entry, json.dumps(manifest, indent=2).encode())
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    (output/"hiot-guard-module3.zip.sha256").write_text(digest+"  "+target.name+"\n", encoding="utf-8")
    (output/"module3-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return {"archive": str(target), "sha256": digest, "source_commit": commit, "source_files": len(paths)}


HTTP_SMOKE = r"""
import json, tempfile, threading
from pathlib import Path
from http.server import ThreadingHTTPServer
from urllib.request import build_opener, ProxyHandler
import module3
from module3.store import Store
from module3.server import handler
assert Path(module3.__path__[0]).resolve().is_relative_to(Path.cwd().resolve())
with tempfile.TemporaryDirectory() as state:
    server=ThreadingHTTPServer(("127.0.0.1",0),handler(Store(Path(state)/"inventory.sqlite3")))
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    base="http://127.0.0.1:"+str(server.server_port)
    opener=build_opener(ProxyHandler({}))
    try:
        with opener.open(base+"/api/ready") as r: assert json.load(r)["app"]=="hiot-module3"
        with opener.open(base+"/") as r: assert b"Asset inventory" in r.read()
        with opener.open(base+"/app.js") as r: assert b"function inventory" in r.read()
        with opener.open(base+"/api/assets") as r: assert json.load(r)["total"]==0
    finally:
        server.shutdown();server.server_close();thread.join()
print("Extracted package CLI, HTML, JavaScript and inventory API are usable")
"""


def verify(target):
    with tempfile.TemporaryDirectory(prefix="hiot-module3-delivery-") as folder:
        root = Path(folder).resolve()
        with zipfile.ZipFile(target) as archive:
            names = archive.namelist()
            if len(set(names)) != len(names):
                raise ValueError("Duplicate ZIP entries")
            manifest = json.loads(archive.read(PREFIX+"/MANIFEST.json"))
            expected = {PREFIX+"/"+name for name in manifest["files"]} | {PREFIX+"/MANIFEST.json"}
            if set(names) != expected or not REQUIRED.issubset(manifest["files"]):
                raise ValueError("Package contents do not match the required manifest")
            for name in names:
                resolved = (root/name).resolve()
                if not resolved.is_relative_to(root) or FORBIDDEN.intersection(Path(name).parts):
                    raise ValueError("Unsafe package entry")
            for name, digest in manifest["files"].items():
                if hashlib.sha256(archive.read(PREFIX+"/"+name)).hexdigest() != digest:
                    raise ValueError("Package file digest mismatch: "+name)
            archive.extractall(root)
        unpacked = root/PREFIX
        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        logs = []
        for command in (
            [sys.executable, "-m", "module3", "--help"],
            [sys.executable, "-m", "unittest", "discover", "-s", "Module 3/tests", "-q"],
            [sys.executable, "-c", HTTP_SMOKE],
        ):
            result = subprocess.run(command, cwd=unpacked, env=env, capture_output=True, text=True, timeout=120)
            logs.append(result.stdout+result.stderr)
            if result.returncode:
                raise RuntimeError("Extracted delivery smoke test failed:\n"+logs[-1])
        return {"verified": True, "source_commit": manifest["source_commit"],
                "source_files": len(manifest["files"]), "tests": logs}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("runs/module3-delivery"))
    parser.add_argument("--verify", type=Path, help="Validate and test an extracted delivery without Git/source fallback")
    args = parser.parse_args()
    print(json.dumps(verify(args.verify) if args.verify else build(args.output), indent=2))


if __name__ == "__main__":
    main()
