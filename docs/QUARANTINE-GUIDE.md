# Quarantine update: usage, design and IAS evidence

Version 1.2, October 6, 2026. Update baseline: `135a69b3f53bfe758570daea0b4d96ea96b97b97` on `Alex-AI-Coding/IAS-AM`.

## What changed

| Feature | Behavior |
|---|---|
| Quarantine selected | Explicit user-confirmed isolation from selected eligible Results rows |
| Encrypted storage | AES-256-GCM with a random nonce and random payload ID |
| Verified original removal | Current bytes must match the scan's SHA-256; the encrypted copy must verify before unlinking |
| Threat details | Engine-provided categories, names, reported severity, source and explanation |
| Restore / Restore as | Authenticated recovery with atomic publication that refuses existing files |
| Encrypted backup after restore | Retained until explicit deletion; original scan verdict is unchanged |
| Delete vault copy | Removes only the stored payload; the activity record remains |
| Retry isolation | Rechecks a retained vault copy and unchanged original after a removal failure |
| Private key | Current-account Windows DPAPI wrapping, or private POSIX file permissions |
| Recovery states | Interrupted preparations need review; failed removals cannot appear fully isolated |
| Scanner exclusion | Normal desktop/CLI/API scans skip the protected vault |
| Background work | Operations keep the UI responsive; app close waits for their completion |
| Ocean theme | Reference colors applied to every page, popup, control, status and native radar |
| Cleanup | Shared palette, closed SQLite connections, GUI-thread slots and joined worker cleanup |

The existing Dashboard, file/folder/Quick scan, radar/reduced motion, search/filter/paging, JSON/CSV/Signed JSON, History, Settings, download alerts, connection snapshots, CLI and authenticated restricted API remain available. The full inventory and course mapping are in [the IAS review](IAS-ENGINEERING-REVIEW.md).

## A harmless demonstration

1. Launch from the root: `.venv\Scripts\python.exe -m antivirus.frontend_main`.
2. Scan `demo_samples/ransomware-demo.txt`. Its explicit educational marker produces a demonstration detection.
3. Select its Results row and choose **Quarantine selected**. Confirm. The app does not execute the sample.
4. Open Quarantine. Select the row and inspect **Details**: type, severity, detection source, original path, size and SHA-256. The original should be absent.
5. Choose **Restore original**. Confirm after reviewing the risk. The harmless sample should return, and the row should say **Restored · backup held**.
6. Select that row and choose **Delete vault copy**. The recovered sample stays on disk. The Deleted/All activity filters preserve the record.
7. To demonstrate no-overwrite behavior, quarantine a fresh harmless copy, recreate a different file at its original path, then attempt Restore original. The newer file must survive. Use Restore as to choose another name.

These examples show file-handling controls. They do not measure malware-detection accuracy or prove that every detection is a true infection. Quarantine is manual; the download monitor continues to alert only.

## Select and process several files

In Results and Quarantine, click a row to focus the table. **Ctrl-click** selects
separate rows, **Shift-click** selects a range, and **Ctrl+A** selects the current
filtered page (up to 250 Results rows or 200 Quarantine rows). Selection clears
when changing the filter or page. Action buttons show the number of eligible
selected files. Results excludes clean/unhashed/already-isolated entries.

Batch quarantine, Restore original, Retry isolation and Delete vault copies use
one confirmation and one background worker. The worker processes each selected
eligible file separately; a failure is reported while later files continue.
Completed actions are not rolled back. **Action summary → Show Details** lists
each returned state, attention message and failure. Existing-file conflicts and
changed originals retain the same protection as individual operations.
**Restore as…** and **Details** require exactly one selected row. App close waits
for the running file-changing batch to finish.

History has separate **Clear selected** and **Clear all history** actions with
confirmation. They delete scan records and refresh dashboard totals; they leave
the vault and its activity catalogue intact. Clear all includes entries older
than the latest 100 visible rows. New completed scans are saved normally.

## States and user choices

| State | Meaning | Available choice |
|---|---|---|
| Preparing | Evidence is committed; original has not been removed by this step | Wait for the operation |
| Isolated | Verified stored copy; original removal completed | Restore, restore-as, delete |
| Removal unconfirmed | A verified encrypted copy is held; original removal may not have completed | Details, retry, restore-as, delete vault copy |
| Needs review | Preparation was interrupted or failed; do not assume successful isolation | Inspect evidence/error; keep original; explicitly delete unwanted partial copy |
| Restored · backup held | Recovered file was published and an encrypted backup remains | Details or delete backup |
| Deletion pending | Payload deletion started; a crash/status failure can leave this state | Refresh, inspect, retry deletion |
| Deleted | Vault copy was removed; metadata retained | Inspect the activity record |

Restore never overwrites a destination, follows linked paths, or recreates missing folders. Restore as can target a different drive because it writes within the chosen destination folder. That folder's filesystem must support hard links (for example NTFS). Unsupported filesystems fail while preserving the vault copy. Restored POSIX files use mode 0600, rather than restoring executable bits.

## Storage and integrity

The default directory is `antivirus_data/quarantine`:

- `index.db`: SQLite evidence and lifecycle catalogue. Paths, detection labels and other metadata are plaintext.
- `payloads/<random-id>.qvault`: encrypted contents; no original file extension or executable permission is preserved.
- `vault-key.dpapi` on Windows: DPAPI-wrapped AES key bound to the current account/context.
- `vault-key.bin` on POSIX: raw AES key in a mode-0600 file inside mode-0700 directories.

AES-GCM authenticates payload contents and canonical immutable metadata (ID, original path, SHA-256, size, threat evidence and added time). State, latest error and restored path are mutable catalogue fields, not an authenticated audit log. Tampering with immutable evidence or encrypted contents blocks recovery. The restore worker first verifies without creating plaintext, then decrypts to a private temporary file, verifies again and publishes without replacement. Failed writes leave the encrypted copy intact.

The source is checked before/opened during/after reading, and immediately before removal. Multi-linked originals are refused because removing one path would not isolate another link. Vault and restore paths reject symlinks and Windows junctions. These checks reduce accidental races; the OS account and administrator remain trusted. Encryption does not isolate an already executing process or resist someone who can obtain the account's key and rewrite the program.

The catalogue is separate from scan History. Clearing History does not remove quarantine. Deleting a vault entry retains metadata; there is no retention/export UI for quarantine activity yet. Encrypted bytes use ordinary file deletion, not guaranteed forensic erasure or deletion from backups.

Back up the whole vault only with the app closed and keep it access controlled. Restore the matching key, catalogue and payloads together. Windows DPAPI recovery also depends on the original Windows account/context; a copied key file alone is not portable recovery. A missing key is reported, and no replacement is silently generated while recoverable records exist. Losing that key can make encrypted files unrecoverable. A fresh source-folder extraction does not copy the old data folder.

## What to explain for IAS

| Concept | Concrete evidence | Limit to acknowledge |
|---|---|---|
| Confidentiality | Encrypted payloads, local defaults, DPAPI or restricted filesystem permissions | Metadata is plaintext; the OS account is trusted |
| Integrity | SHA-256 before deletion; GCM authentication of contents/evidence | Lifecycle state is locally mutable; no external audit service |
| Availability | Bounded streaming, background workers, retained copies on failure | Disk space is finite; unsupported restore filesystems need another destination |
| Authentication | Windows account context protects the AES key | The app has no separate login, MFA or roles |
| Authorization | Explicit decisions; vault containment; safe target validation | Existing API token authorizes scanning only; quarantine is desktop-only |
| Risk response | Manual isolation and visible uncertain-removal states | No claim of stopping running malware or proving a virus family |
| Recovery | Verified restore, no overwrite, retained encrypted backup | Key loss needs protected backups; no portable DPAPI migration tooling |
| QA / SDLC | Harmless real round trips, fault injection, real Qt workflow tests | Windows/VS Code and GitHub Actions must be checked on the target machine |

The reference uses analogous green/teal/blue hues. Its six exact colors anchor backgrounds, cards, primary actions, radar signals, accents and borders. Lighter derived text provides readability; complementary pink marks destructive actions and amber marks warnings. Text labels, visible focus and reduced motion prevent reliance on color/animation alone. This has visual QA, not a screen-reader or WCAG certification.

## Improvements still worth doing

| Priority | Next improvement | Evidence needed |
|---|---|---|
| Before submission | Run the Windows demo and GitHub Actions | Native dialogs, DPAPI round trip, NTFS restore, display scaling and test output |
| Before submission | Perform a private backup/recovery drill | Matching payloads/catalogue/key; recovery time and lost-record count |
| High for production | Native-engine isolation and maintained signed feeds | Parser containment, feed provenance, safe updates and rollback |
| High if required | Individual accounts, roles and MFA | Service-enforced permissions, recovery, revocation and identity attribution |
| High for recovery | OS/hardware key custody plus backup tooling | Protected signing keys, portable recovery policy and verified backups |
| Medium | Quarantine retention/export/search refinements | Authorized evidence export/redaction and explicit metadata cleanup policy |
| Medium | Labelled accuracy dataset and calibrated severity | False-positive/false-negative measures and engine-specific explanations |
| Medium | Accessibility trials | Keyboard-only, screen reader, high DPI and varied display tests |
| Medium | Disk-space policy and stronger crash durability | Admission checks, retention limits and crash/power-loss exercises |
| Later | Automatic quarantine with rollback policy | Evidence thresholds, exclusions, multi-process coordination and user recovery |

A working quarantine adds demonstrable Protect/Respond/Recover controls. It does not alone establish every IAS concept, production antivirus efficacy, or a passing grade. Map the implementation and documented limits against the instructor's rubric.

## Primary implementation references

- [Cryptography: authenticated GCM and additional data](https://cryptography.io/en/48.0.0/hazmat/primitives/symmetric-encryption/).
- [Microsoft: CryptProtectData and Windows account context](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata).
- [Python: file opening, hard links and filesystem operations](https://docs.python.org/3.12/library/os.html).
- [Qt: QThread lifecycle and cleanup](https://doc.qt.io/qt-6/qthread.html).
- [Qt for Python: slots and thread affinity](https://doc.qt.io/qtforpython-6/tutorials/basictutorial/signals_and_slots.html).
