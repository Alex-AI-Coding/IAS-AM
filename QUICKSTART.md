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

The app checks files without executing them. The samples are harmless text. “No matches” is not a safety guarantee. The optional download monitor is an alerting tool and does not block execution.

Tests:

```powershell
.venv\Scripts\python.exe -m pytest tests -q
```

[Full setup, API and signing instructions](README.md) · [IAS audit and presentation guide](docs/IAS-ENGINEERING-REVIEW.md)
