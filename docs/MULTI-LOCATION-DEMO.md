# Scan harmless samples in several folders or drives

The repository includes six plain-text samples under `demo_samples/`. They
contain no executable malware. Four deliberately match the included educational
YARA rules; one is a clean control; one demonstrates exact hash matching after
the local catalogue is seeded. Their names describe classroom categories, not
confirmed infections or measured danger levels.

## Copy to locations you choose

Open a PowerShell terminal in the repository. This copies two complete sets to
your Desktop and the E drive, creating a new `IAS-AM-Scan-Demo` folder beneath
each destination:

```powershell
py .\scripts\distribute_demo.py --destination ([Environment]::GetFolderPath('Desktop')) --destination 'E:\' --copies 2
```

Use only drives that exist on your PC. Repeat `--destination` for another folder
or connected USB drive, for example `--destination 'F:\'`. Add `--dry-run` to
preview the paths without writing. The helper requires only Python's standard
library; it does not need the application's virtual environment.

Each destination contains `location-01`, `location-02`, and so on. Each location
contains all six original samples, copied without changing their contents. A
destination must already exist. A previous `IAS-AM-Scan-Demo` folder is never
overwritten: choose another destination or move the old demo folder before
repeating the command. After a permission/disk error, inspect any partially
created demo folder before trying again.

## Scan and check the evidence

1. In the app's **Settings**, enable YARA and the SHA-256 catalogue. For this
   reproducible classroom check, leave optional ClamAV and VirusTotal off.
2. To include the hash demonstration, run the following from the same repository
   and data configuration used to launch the app:

   ```powershell
   .\.venv\Scripts\python.exe scripts\prepare_demo.py
   ```

3. Choose **Scan → Choose folder** and select one `IAS-AM-Scan-Demo` folder.
   Folder scans include its nested locations. Scan the other drive's demo folder
   separately. Quick scan targets the configured common user folders, not every
   connected drive.
4. With two sets in that folder, expect **12 scanned files: 8 educational YARA
   matches and 4 no-match files** before hash seeding. After seeding, expect
   **10 matches and 2 clean controls**. Counts refer to files, not the number of
   individual rules matched. Other engine settings can change the results.
5. Open a result's **Details** to inspect its full path, SHA-256, detection source
   and rule name. Equal copies have equal hashes; different locations have
   different full paths. Rename a sample without editing it and it should still
   match: these checks examine contents, not the filename.

Manual quarantine removes the selected original after verifying the encrypted
copy, so later scans can contain fewer files. A USB drive with FAT/exFAT can be
used for scanning, but restoring to it may fail because the app's no-overwrite
restore requires hard-link support. Use an NTFS destination for a restore demo.

## Standalone downloadable kit

The kit contains this helper and the same six samples. Extract it into
`Downloads\IAS-AM-Demo-Kit`, then run it from any PowerShell terminal:

```powershell
py "$env:USERPROFILE\Downloads\IAS-AM-Demo-Kit\scripts\distribute_demo.py" --destination ([Environment]::GetFolderPath('Desktop')) --destination 'E:\' --copies 2
```

The helper only copies the six named text files into locations you explicitly
select. It does not execute files, discover other drives, install background
tasks, or make samples replicate themselves. You can copy these same `.txt`
files by hand using File Explorer as well. Remove only your generated demo
folders when finished; keep the repository originals for later testing.
