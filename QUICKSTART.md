# Premiere Security: start here

1. Open the **IAS-AM root folder** in VS Code.
2. Run these commands in its PowerShell terminal:

```powershell
py -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m antivirus.frontend_main
```

3. Select `.venv\Scripts\python.exe` with **Python: Select Interpreter**.
4. Open **Scan → Choose folder** and select `demo_samples`.
5. Observe the radar and progress. Review detections and skipped/error entries in Results.
6. Export JSON, CSV or Signed JSON; show History and engine availability.
7. For a hash-match demo, run `python scripts/prepare_demo.py` with your selected interpreter.
8. Select a detected demo file in Results, choose **Quarantine selected**, then confirm. Open Quarantine, select the row, and inspect its type, severity and Details.
9. Restore the harmless demo. Its encrypted backup stays in the vault until you choose **Delete vault copy**. Delete leaves the restored file in place.

Each time you reopen the project, run this in the root folder:

```powershell
.venv\Scripts\python.exe -m antivirus.frontend_main
```

The setup commands are needed once, and dependency installation is needed again when requirements change.

The app checks files without executing them. The samples are harmless text. “No matches” is not a safety guarantee. The optional download monitor is an alerting tool and does not block execution. Quarantine is an explicit file-changing action; restore can reintroduce a flagged file and refuses existing destinations. Use harmless demo files for the classroom exercise.

Tests:

```powershell
.venv\Scripts\python.exe -m pytest tests -q
```

[Full setup, API and signing instructions](README.md) · [IAS audit and presentation guide](docs/IAS-ENGINEERING-REVIEW.md)
