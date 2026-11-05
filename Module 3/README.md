# Module 3 — Asset discovery and inventory

This folder owns Module 3's implementation, dashboard, tests, evaluation tools and
documentation. It consumes Module 2's observations rather than capturing traffic.

## Layout

| Path | Responsibility |
|---|---|
| module3/ | Discovery engine, persistence, synchronization, API, CLI and web UI |
| tests/ | Repeatable Module 3 tests |
| tools/ | Saved-capture verification, browser checks, service evaluation and stress tools |
| docs/ | Architecture, interface contract, measured evaluation and limitations |
| launch_module3.py | Python service launcher |
| run-module3.cmd | Windows launcher using the checkout's virtual environment |

The small repository-root module3 package is only a compatibility entry point.
The actual Python and UI implementation is here, with no duplicate source copy.
Shared Module 2 changes remain in the existing module2 folder.

## Run from the repository root

    & ".\Module 3\run-module3.cmd"
    .\.venv\Scripts\python.exe -m module3 serve
    .\.venv\Scripts\python.exe -m module3 serve --offline

The first two commands consume an already available Module 2 service. The last
command views previously imported records without a running sensor.
The service binds to http://127.0.0.1:8879/. It does not start any VM. Runtime state
continues to live under ignored runs/module3; moving source does not move or reset it.

## Verify

    .\.venv\Scripts\python.exe -m unittest discover -s "Module 3/tests" -v
    .\.venv\Scripts\python.exe "Module 3/tools/verify_module3_browser.py" --port 8889
    .\.venv\Scripts\python.exe "Module 3/tools/evaluate_module3_service.py" --seconds 900

Run tools with the repository's dependencies installed. Browser checks additionally
need Node, Playwright and Chrome; RUNTIME_NODE_MODULES may identify a bundled
Playwright installation. Test fixtures are distinct from captured hospital data.

Read the [architecture and commands](docs/MODULE3.md) and
[evaluation and outstanding acceptance work](docs/MODULE3_EVALUATION.md).
The offline/API phase is verified; fresh pinned-sensor MAC and full live hospital
acceptance remain outstanding. Source organization does not change those claims.
