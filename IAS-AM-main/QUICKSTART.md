# Premiere Security Quick Start

## First-time setup on Windows

```powershell
git clone https://github.com/Alex-AI-Coding/IAS-AM.git
cd IAS-AM
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Start the desktop app

```powershell
python -m antivirus.frontend_main
```

No Docker container or Flask server is required for the desktop interface.

## Demonstrate a detection safely

```powershell
Set-Content demo-threat.txt "EDU_RANSOMWARE_PAYLOAD encrypt_all_files ransom_note"
```

In Premiere Security:

1. Open **Scan**.
2. Select **Choose file**.
3. Open `demo-threat.txt`.
4. Review the detection in **Scan results**.
5. Optionally export the result as a JSON or CSV report.

The sample is harmless text designed only to trigger the educational YARA rule.

## Run the tests

```powershell
python -m pytest tests -q
```

For optional ClamAV, VirusTotal, API, CLI, and Docker instructions, see [README.md](README.md).
