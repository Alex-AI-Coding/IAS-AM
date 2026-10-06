# Desktop selection, drive scanning and history update

October 6, 2026. This update includes the earlier quarantine/theme work and the
multi-location sample helper. It adds the controls below without new Python
dependencies.

## What you can do

| Location | New control |
|---|---|
| Results | Ctrl-click separate rows, Shift-click a range, or focus the table and press Ctrl+A to select the current filtered page; quarantine selected eligible detections |
| Quarantine | The same selection gestures; batch restore to original paths, retry isolation and delete vault copies; one-row Details and Restore as |
| Scan | Choose drives, check internal/USB drives such as E: or F:, or add other explicit folders; combine the chosen roots into one cancellable scan |
| History | Select records and Clear selected, or Clear all history to remove every record including older hidden entries |

Ctrl+A selects **visible rows on the current page**, not every page. Results
shows up to 250 rows per page, Quarantine up to 200, and History shows the latest
100 records. Changing a Results/Quarantine page or filter clears the selection.
Ctrl+A inside a search field selects that field's text instead; click a table
row first when selecting files.

Batch confirmations state the eligible count and preview paths. Operations run
sequentially in a background worker. A changed original or restore conflict is
reported individually while other files continue. Completed actions remain
completed. Open **Action summary → Show Details** after a batch to inspect its
states and errors. **Restore as…** and **Details** require one selected row.
Closing the app waits for an active file-changing batch to finish.

Clearing history removes scan records and refreshes dashboard statistics.
Scanned files, quarantine contents/catalogue, exported reports and current
in-memory results remain. Newly completed scans will create history again.

## Install and push using VS Code

Close the antivirus app. Download `IAS-AM-Desktop-Update.bundle` into Downloads.
Use the existing Git clone at `E:\IAS\IAS-AM-Git`, then paste this entire block
into its PowerShell terminal:

```powershell
& {
    $ErrorActionPreference = 'Stop'
    function Invoke-IASGit {
        git @args
        if ($LASTEXITCODE -ne 0) {
            throw 'Git failed. Stop and share the output.'
        }
    }
    $iasBundle = "$env:USERPROFILE\Downloads\IAS-AM-Desktop-Update.bundle"
    if (-not (Test-Path -LiteralPath $iasBundle -PathType Leaf)) {
        throw 'Download IAS-AM-Desktop-Update.bundle into Downloads first.'
    }
    Set-Location 'E:\IAS\IAS-AM-Git'
    Invoke-IASGit switch main
    Invoke-IASGit pull --ff-only origin main
    Invoke-IASGit fetch $iasBundle feat/desktop-selection-drives-history:feat/desktop-selection-drives-history
    Invoke-IASGit merge --ff-only feat/desktop-selection-drives-history
    Invoke-IASGit push origin main
}
```

The bundle preserves history and includes earlier updates, even if the previous
sample-helper bundle was not imported. Fast-forward commands stop if the
histories have diverged; share the error rather than discarding local edits.
The update does not contain your private data, vault keys or virtual environment.
Keep using the same clone and data directory so existing history/quarantine stay
available. No dependency reinstall is needed for these controls.

Reopen the app from that folder:

```powershell
Set-Location 'E:\IAS\IAS-AM-Git'
.\.venv\Scripts\python.exe -m antivirus.frontend_main
```

## Test three harmless files anywhere

The included `ransomware-demo.txt`, `trojan-demo.txt` and `spyware-demo.txt` are
plain text, with explicit markers for the app's educational YARA rules. They
contain no executable virus and do not replicate. Their category and severity
labels are educational rule metadata, not confirmed infections or measured risk.

Copy the files with File Explorer to folders or drives you control. Keep their
contents unchanged. In Settings, enable YARA; leave optional ClamAV/VirusTotal
off for a reproducible classroom check. Scan their folder: expect three
educational matches. Renaming a sample does not break its content match. Copies
of the same sample have equal SHA-256 values and distinct paths.

For several sample sets, use the included helper:

```powershell
py .\scripts\distribute_demo.py --destination ([Environment]::GetFolderPath('Desktop')) --destination 'E:\' --copies 2
```

Then choose each `IAS-AM-Scan-Demo` folder, or add those folders in **Choose
drives → Add folder or drive…** to scan them together. Each set contains all six
repository samples; expected counts and hash seeding are described in
[the multi-location guide](MULTI-LOCATION-DEMO.md).

## Drive and restore limits

No drive is selected automatically. Ready mounted volumes are offered, and
other drive roots/folders can be selected manually. Disconnected/inaccessible
locations produce errors or warnings instead of causing another drive to be
scanned. All roots in one scan share the existing **25,000-file** discovery
limit; files above **256 MiB**, links/junctions and the vault are skipped with
the existing safeguards. Choose demo folders for predictable test counts.

USB drives using FAT/exFAT can be scanned. Quarantine restore requires hard-link
support such as NTFS; use an NTFS destination for the restore demonstration.

## Verification

The full suite passed **187 tests, with one real-Windows-DPAPI test skipped**, on
Linux/Python 3.12.14. New tests use actual Qt keyboard/mouse gestures, real YARA
demo detections and real encrypted quarantine operations. They cover batch
restore conflicts, changed originals, retained-copy retry, cancellation, page
selection limits, stable-ID history removal while a new scan arrives, clearing
older hidden rows, multi-root scans and an unavailable drive. Formatting, lint
and compilation checks passed. Real Qt layouts were inspected at 1180×760 and
960×640. Native Windows drive enumeration, permissions and DPAPI still need the
target Windows environment.
