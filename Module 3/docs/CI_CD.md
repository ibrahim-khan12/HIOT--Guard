# Module 3 CI and continuous delivery

The HIoT-Guard workflow tests the code and delivers a verified source ZIP.
It does not deploy a public website, start the hospital lab, or configure a VM.

## Pipeline

1. **Run Python Tests:** install the pinned Python requirements, then run Module 1/2
   tests and Module 3 discovery tests in separate steps. A failed earlier command
   cannot be hidden by a successful later command.
2. **Verify Module 3 Browser:** install the locked Playwright dependency and its
   Chromium build. Run the desktop/mobile checks with explicitly synthetic fixture
   records, without requiring a private inventory, capture or running sensor.
3. **Prepare Module 3 Delivery:** after both test jobs pass, build the release from
   the exact committed Git object. Check file hashes, extract it into a temporary
   directory, run its Module 3 tests, and check its CLI, HTML, JavaScript and API.
4. **Verify Downloaded Module 3 Delivery:** on a separate runner without a source
   checkout, download the uploaded artifact, check the archive checksum, install
   dependencies from its requirements, and independently smoke-test the package.

Python and browser checks run for pushes to main, module-* and feature/** and for
pull requests to main. Module 3 delivery runs for successful pushes or manual runs
on module-3 and main. The existing Module 2 packaging job remains main-only.
No merge to main is performed by this workflow.

## Downloadable artifacts

Open a completed successful run under the repository's Actions tab.

| Artifact | Contents | Retention |
|---|---|---|
| hiot-guard-module3 | Source ZIP, archive SHA-256, per-file manifest and smoke report | 30 days |
| module3-browser-evidence | Desktop/mobile screenshots, JSON results and synthetic filtered export | 14 days |
| module3-delivery-verification | Independent downloaded-package verification results | 30 days |

The package includes the Module 3 folder, its compatibility entry point, the
Module 2 contract/support package, shared configuration, requirements, and the
parser-fixture test dependency. The manifest identifies the source commit and
hashes each source file. Runtime runs/ data, PCAPs, databases, credentials, virtual
environments, node_modules and unrelated local changes are excluded.

Checksums detect accidental corruption; they are not signatures or a claim of
production security certification. Artifact retention is finite, so download
accepted releases if they need to be kept beyond the retention period.

## Local commands, from the checkout root

    npm ci --prefix "Module 3/tools" --ignore-scripts --no-audit --no-fund
    node "Module 3/tools/node_modules/playwright/cli.js" install chromium

For the browser runner, set RUNTIME_NODE_MODULES to the absolute
Module 3/tools/node_modules directory and MODULE3_BROWSER_CHANNEL to chromium.

    python "Module 3/tools/verify_module3_browser.py" --fixture --port 8889
    python "Module 3/tools/package_module3.py" --output runs/module3-delivery
    python "Module 3/tools/package_module3.py" --verify runs/module3-delivery/hiot-guard-module3.zip

Packaging requires its sources to be committed: it reads HEAD, never silently
includes uncommitted working files, and never uploads local runtime evidence.
The package can be extracted and run using the included Module 3 README.

## What CI does not prove

Synthetic browser metadata exercises the operator interface; it does not verify
DICOM/HL7 extraction from new packets. The saved-capture comparison, pinned Linux
sensor MAC acceptance, sustained hospital workload and live end-to-end acceptance
remain separately recorded experiments. The existing real socket/capture Module 1
test stays explicitly skipped unless its integration environment is enabled.
