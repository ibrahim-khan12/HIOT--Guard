# Development Status and Validation Guide

## Repository layout

The integrated `main` line contains the Module 1 mini-hospital lab and Module 2 passive monitoring implementation. Module 2 source is under `module2/`; its launcher, tests, and operator documentation are at the repository root. The older `module-2` branch name in historical notes refers to the development workflow, not a requirement to switch branches to use the integrated implementation.

## Automated regression suite

The GitHub Actions workflow uses Python 3.13 on Windows and installs the repository's Module 2 dependency set. From a prepared Windows checkout, run:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-module2.txt
.\.venv\Scripts\python.exe -m unittest test_live test_module2 test_scenarios -v
```

This is the same test command configured in `.github/workflows/ci-cd.yml`. A local pass is useful feedback, but the pull request's own Actions result is the authoritative CI result for that revision.

## Additional lab validation

- Run the native Module 1 integration tests only when the required capture tooling is installed and the management ports are free. Set `IOMT_INTEGRATION=1` as described in `README.md`.
- For Module 2, follow `MODULE2.md` to prepare the pinned Linux sensor and run the offline/live acceptance checks in `verify_module2.py`.
- For the GNS3 hospital topology, use the current private controller address and follow the measured evaluation procedure in `HOSPITAL_EVALUATION.md` and `README.md`.
- Keep runtime manifests, PCAPs, databases, SSH credentials, and other local evidence under ignored runtime storage. Do not commit secrets or raw captures.

## Interpretation of results

Unit tests, CI results, offline PCAP acceptance, and live GNS3 measurements validate different parts of the system. Do not describe a unit-test pass as proof of live sensor operation, physical medical-device compatibility, clinical deployment readiness, or ransomware detection. Preserve failed runs and their logs rather than replacing them with a passing summary.

## Daily development checklist

1. Review recent commits, open issues/pull requests, and the latest Actions run.
2. Select one bounded improvement based on an observed defect, missing test, documentation mismatch, or reproducibility gap.
3. Make the change on a feature branch and add or update a focused test when appropriate.
4. Run the narrow relevant checks, then the repository regression suite when practical.
5. Commit with a descriptive message and open a pull request for review.
6. Record any unverified assumptions or lab-only limitations in the pull request.