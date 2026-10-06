# Validation record

Original review: October 5, 2026. Quarantine/theme verification: October 6, 2026. Original baseline: `0947e0d25ae686448e7cbaa068fff9604be39897`. Update baseline: `135a69b3f53bfe758570daea0b4d96ea96b97b97`.

The unmodified root project passed **57 tests**; version 1.1 passed **121**. Version 1.2 passed **170 tests, with 1 Windows-only test skipped, in 6.39 seconds** on Linux with Python 3.12.14, PySide6 6.11.2, cryptography 48.0.1 and offscreen Qt. Timing describes this run, not a performance guarantee. `requirements-verified.txt` records the installed dependency versions; `requirements.txt` contains supported installation constraints.

## Completed checks

| Check | Result |
|---|---|
| `python -m pytest tests -q` | 170 passed, 1 skipped |
| `python -m black --check antivirus tests main.py scripts` | 67 Python files compliant |
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
| Real-widget visual inspection | All seven pages at 1180×760; scan/quarantine at 960×640; scrollable content, readable type/state and visible actions |
| Real YARA → quarantine → restore → delete | Four disposable demo categories; restored bytes match; vault deletion preserves recovered files |

Qt workflow tests use the real event loop. They check normal completion, partial cancellation, failure recovery, radar/reduced-motion state, named navigation and saved preferences, skipped filtering, and 620-result paging/search without losing exported rows.

New quarantine tests cover encrypted round trips across stream boundaries, persistence, same-name collisions, changed/replaced originals, locked-file retry, storage/catalogue failures before and after removal, damaged/truncated payloads, altered authenticated metadata, missing keys, restore conflicts/publication races, corruption between verification and recovery, interrupted preparation, deletion failure, linked paths and identifiers, size bounds, private POSIX permissions and scanner vault exclusion. Desktop tests cover selection eligibility, path normalization, cancelled confirmations, real worker completion, restore conflicts, unavailable catalogues, filters, plain-text/default-cancel dialogs, repeated worker starts on the GUI thread, scan/vault coordination and safe close while isolation runs.

The skipped test calls the real Windows DPAPI API, including a corrupted protected blob. A separate cross-platform test verifies actual DPAPI-wrapped key storage when run on Windows. The supplied Windows GitHub Actions jobs can execute both; neither was executed locally on Windows.

Security regressions cover failed and disabled engines, detections alongside failures, unavailable catalogues/rules, harmless-word false positives, changed/oversized/special/linked files, missing folders, discovery limits, persistence failure, legacy schema migration, malformed ClamAV/online responses, online lookup spacing/cache, CSV formula prefixes, and signature tampering/key substitution. API tests cover fail-closed authentication, malformed JSON, linked/outside paths, all-target batch validation, body/batch limits, busy scanning, sanitized failures and scan-gate release. Download-monitor tests check stabilization, revision detection, temporary-file rename handling and read-only behavior.

Screenshots show real application widgets with illustrative sample paths and progress values. They are not scan speed, accuracy or threat-count measurements.

## Patch delivery verification

The v1.2 delivery process applies `IAS-AM-Quarantine.patch` to a clean checkout of the update baseline with `git apply --check`, then `git apply`. It compares every tracked file byte for byte with the reviewed tree. The source ZIP contains the same tracked source, setup instructions and patch; it excludes runtime data, credentials, signing/vault keys and the virtual environment. The Git bundle contains the committed update; importing its feature branch into a disposable baseline clone and fast-forwarding verifies delivery without a GitHub write.

## Checks still requiring the target environment

- Actual Windows/VS Code installation, DPAPI key protection/corruption handling, NTFS restore, native dialogs, display scaling and screen-reader behavior.
- Live ClamAV daemon and VirusTotal account/key. Their service contracts and failure cases are tested with controlled responses; live integration is not certified here.
- Docker image build and container execution. Docker was unavailable. The Dockerfile was statically reviewed and updated with the native libraries required by the offscreen Qt tests.
- GitHub Actions matrix execution for this v1.2 update on Windows/Linux and Python 3.12/3.13. The updated commit is packaged for the user to push directly; remote workflow results require that push.
- Measured accuracy on a labelled dataset, native-engine sandboxing, recovery timing and an organizational compliance assessment.

The current evidence establishes the listed local checks. It does not guarantee an academic grade or production antivirus efficacy. Use the course guide and the instructor's actual rubric to decide the remaining acceptance criteria.
