# Premiere Security

Premiere Security is a small, desktop antivirus demonstration created for an Information Assurance and Security (IAS) school project. It combines a polished PySide6 interface with hash matching, educational YARA rules, optional ClamAV scanning, optional VirusTotal hash reputation, scan history, report export, a CLI, and a Flask API.

The project deliberately favors a clear workflow over enterprise-level complexity:

1. Choose a Quick, File, or Folder scan.
2. Review clean, suspicious, and error results.
3. Inspect detections and export the report for documentation.

> **Academic scope:** Premiere Security is an educational scanner, not a replacement for Microsoft Defender or another maintained commercial antivirus. Its included YARA rules use harmless demonstration patterns. Real-world protection depends on regularly updated signatures, hardened isolation, real-time monitoring, and professionally maintained detection infrastructure.

## Desktop features

- **Dashboard** — protection status, totals, active engines, and recent activity
- **Desktop navigation** — clear page tabs stay at the top of the application
- **Accessible visual design** — larger text and controls with a low-glare cream-and-sage palette
- **Guided scanning** — Quick Scan for Desktop/Downloads/Documents, single-file scan, or recursive folder scan
- **Responsive progress** — accurate file counts, background scanning, and safe cancellation
- **Results workspace** — filters, detailed findings, and JSON/CSV report export
- **Persistent history** — scan type, target, totals, duration, threats, and outcome
- **Settings** — enable only installed/configured engines and understand their privacy behavior
- **Fresh-clone reliability** — application data directories and SQLite databases are created automatically

## Detection engines

| Engine | Default | Purpose |
|---|---:|---|
| SHA-256 hash catalog | On | Matches files against the local threat repository |
| YARA rules | On | Detects the included trojan, ransomware, worm, and spyware demonstration patterns |
| ClamAV | On when available | Uses a locally running ClamAV daemon for additional scanning |
| VirusTotal | Off | Sends only a SHA-256 hash for online reputation when an API key is configured and the user enables it |

Missing optional engines do not crash the application. The UI labels them as unavailable and continues with the local engines that are ready.

## Requirements

- Python 3.12 or newer
- Windows 10/11, macOS, or a Linux desktop supported by PySide6
- ClamAV only if you want the optional ClamAV engine
- A VirusTotal API key only if you want optional online hash reputation

## Run the desktop application on Windows

```powershell
git clone https://github.com/Alex-AI-Coding/IAS-AM.git
cd IAS-AM

py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

python -m antivirus.frontend_main
```

If PowerShell blocks virtual-environment activation, run this once in the same terminal:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

The desktop app does not require the Flask API or Docker to be running.

## Safe classroom demonstration

The included rules recognize harmless text indicators so the detection and reporting workflow can be demonstrated without real malware.

Create a demonstration file:

```powershell
Set-Content demo-threat.txt "EDU_RANSOMWARE_PAYLOAD encrypt_all_files ransom_note"
```

Then open Premiere Security, choose **Scan a file**, and select `demo-threat.txt`. The result should be marked suspicious by the YARA engine. You can show its details and export the report afterward.

## Optional VirusTotal setup

Copy `.env.example` to `.env` and add your API key:

```env
VIRUSTOTAL_API_KEY=your_api_key_here
```

Restart the desktop app, open **Settings**, and enable **VirusTotal reputation**. Only the file's SHA-256 hash is submitted; Premiere Security does not upload file contents.

## CLI

```powershell
# JSON is the default output
python main.py scan "C:\path\to\file.exe"

# Scan a directory and return CSV
python main.py scan "C:\path\to\folder" --format csv
```

## REST API

Start the API:

```powershell
python -m flask --app antivirus.api run --port 5000
```

Available endpoints:

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Confirm that the API is running |
| POST | `/api/v1/scan` | Scan one file or directory |
| POST | `/api/v1/scan/batch` | Scan a list of targets |
| POST | `/api/v1/report/json` | Scan and return a JSON report |
| POST | `/api/v1/report/csv` | Scan and return a CSV report |

Example:

```powershell
curl.exe -X POST http://localhost:5000/api/v1/scan `
  -H "Content-Type: application/json" `
  -d '{"target":"C:\\path\\to\\sample.txt"}'
```

## Docker

Docker is intended for the headless API and automated tests:

```powershell
docker compose up --build antivirus-api
docker compose --profile test run --rm antivirus-tests
```

Run the visible desktop application directly on the host with `python -m antivirus.frontend_main`.

## Tests and quality checks

```powershell
python -m pytest tests -q
black --check antivirus tests
flake8 antivirus tests
```

The suite covers models, hashing, YARA, ClamAV and VirusTotal boundaries, the detection engine, directory progress, history persistence, statistics, CLI output, reports, and API validation.

## Project structure

```text
antivirus/
├── config/          Application paths and environment setup
├── controller/      Desktop workflow coordination
├── detection/       Multi-engine detection and YARA rules
├── model/           Scan and threat data models
├── repository/      SQLite persistence
├── services/        Scanner, reports, statistics, and integrations
├── view/            PySide6 pages, shared components, and visual theme
├── api.py           Flask REST API
└── frontend_main.py Desktop entry point

tests/               Automated regression suite
main.py              CLI entry point
```

Application-generated databases are stored under `antivirus_data/`, which is intentionally excluded from Git.
