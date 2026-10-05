# Validation record

Review date: October 5, 2026. Baseline commit: `0947e0d25ae686448e7cbaa068fff9604be39897`.

The unmodified root project passed **57 tests**. The revised project passed **121 tests in 1.72 seconds** on Linux with Python 3.12.14, PySide6 6.11.2 and offscreen Qt. Timing describes this run, not a performance guarantee. `requirements-verified.txt` records the installed dependency versions; `requirements.txt` contains the supported installation constraints.

## Completed checks

| Check | Result |
|---|---|
| `python -m pytest tests -q` | 121 passed |
| `python -m black --check antivirus tests main.py scripts` | 60 Python files compliant |
| `python -m flake8 antivirus tests main.py scripts` | Passed |
| `python -m pip check` | No broken dependency requirements |
| `python -m compileall -q antivirus tests main.py scripts` | Passed |
| `git diff --check HEAD` | Passed |
| Real-engine CLI: clean sample | Exit 0; `summary.outcome=clean` |
| Real-engine CLI: educational ransomware sample | Exit 1; `summary.outcome=detected` |
| Real-engine CLI: missing file | Exit 2; `summary.outcome=error` |
| CLI seeding + harmless hash sample | Exact SHA-256 catalogue detection; exit 1 |
| CLI signed JSON with independently supplied matching public key | Verified; exit 0 |
| CLI signed JSON after changing a report field | Verification rejected; exit 2 |
| Flask test client with real local hash/YARA engines | Clean and detected outcomes; 401 without token; 403 outside root |
| Real-widget visual inspection | Dashboard, radar scan, results and settings at 1180×760; scrollable scan at 960×640 |

Qt workflow tests use the real event loop. They check normal completion, partial cancellation, failure recovery, radar/reduced-motion state, named navigation and saved preferences, skipped filtering, and 620-result paging/search without losing exported rows.

Security regressions cover failed and disabled engines, detections alongside failures, unavailable catalogues/rules, harmless-word false positives, changed/oversized/special/linked files, missing folders, discovery limits, persistence failure, legacy schema migration, malformed ClamAV/online responses, online lookup spacing/cache, CSV formula prefixes, and signature tampering/key substitution. API tests cover fail-closed authentication, malformed JSON, linked/outside paths, all-target batch validation, body/batch limits, busy scanning, sanitized failures and scan-gate release. Download-monitor tests check stabilization, revision detection, temporary-file rename handling and read-only behavior.

Screenshots show real application widgets with illustrative sample paths and progress values. They are not scan speed, accuracy or threat-count measurements.

## Patch delivery verification

The delivery process applies `IAS-AM-Fixes.patch` to a clean checkout of the baseline using `git apply --check` followed by `git apply`. It compares every delivered tracked file byte for byte against the reviewed tree and confirms removed files are absent. The source ZIP contains those same files, setup instructions and the patch; it excludes runtime data, credentials, signing keys and the virtual environment.

## Checks still requiring the target environment

- Actual Windows/VS Code installation, native dialogs, display scaling and screen-reader behavior.
- Live ClamAV daemon and VirusTotal account/key. Their service contracts and failure cases are tested with controlled responses; live integration is not certified here.
- Docker image build and container execution. Docker was unavailable. The Dockerfile was statically reviewed and updated with the native libraries required by the offscreen Qt tests.
- GitHub Actions matrix execution on Windows/Linux and Python 3.12/3.13. The workflow is supplied but was not pushed or run remotely.
- Measured accuracy on a labelled dataset, native-engine sandboxing, recovery timing and an organizational compliance assessment.

The current evidence establishes the listed local checks. It does not guarantee an academic grade or production antivirus efficacy. Use the course guide and the instructor's actual rubric to decide the remaining acceptance criteria.
