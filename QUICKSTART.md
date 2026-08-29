# Quick Start Guide

## Installation (2 minutes)

```bash
# 1. Clone the repository
git clone <repository-url>
cd anti-virus-ias-project

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. (Optional) Install ClamAV for full detection
# Windows: Download from https://www.clamav.net/downloads
# macOS: brew install clamav
# Linux: sudo apt-get install clamav
```

## Running the CLI Scanner (30 seconds)

```bash
# Scan a file
python main.py scan C:\path\to\file.exe --format json

# Scan a directory
python main.py scan C:\path\to\directory --format csv

# Default format is JSON
python main.py scan file.exe
```

## Running the REST API Server (1 minute)

```bash
# Terminal 1: Start the API server
python -m flask --app antivirus.api run --port 5000

# Terminal 2: Test the API
curl http://localhost:5000/health

# Scan a file via REST
curl -X POST http://localhost:5000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "C:\\path\\to\\file.exe"}'
```

## Running Docker Backend + Desktop Frontend

The recommended Windows setup runs the Flask backend in Docker and the PySide6 desktop window locally. Use two terminals from the project folder.

### Terminal 1: Start the backend

```powershell
docker compose up --build antivirus-api
```

The backend API is available at `http://localhost:5000`.

### Terminal 2: Start the desktop application

```powershell
# First-time setup
uv venv --python 3.12 .venv
.venv\Scripts\Activate.ps1
uv pip install -r requirements.txt

# Start the GUI
python -m antivirus.frontend_main
```

If PowerShell blocks activation, run this once in that terminal:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

The Docker container is headless, so it provides the backend/API while the visible PySide6 window runs on Windows. Stop the backend with `Ctrl+C` in Terminal 1.

Optional VirusTotal configuration can be placed in the project-root `.env` file:

```env
VIRUSTOTAL_API_KEY=your_key_here
```

## Using the Python API (Programmatic)

```python
from antivirus.services.scanner import Scanner
from antivirus.services.report_formatter import ReportFormatter
from antivirus.services.statistics_service import StatisticsService

# Initialize scanner
scanner = Scanner()

# Scan a file
result = scanner.scan_file("file.exe")
print(f"Status: {result.status}")
print(f"Threats: {result.threats}")

# Scan a directory
report = scanner.scan_directory("directory/")

# Export report
json_output = ReportFormatter.to_json(report)
csv_output = ReportFormatter.to_csv(report)

# Get statistics
stats = StatisticsService()
print(stats.get_detection_summary(report))
```

## Running Tests

```bash
# All tests (50 total)
pytest tests/ -v

# Specific test file
pytest tests/test_api.py -v

# With coverage report
pytest tests/ --cov=antivirus --cov-report=html

# Open coverage report
# Open htmlcov/index.html in browser
```

## Common Tasks

### Task 1: Add a Custom YARA Rule

1. Create `antivirus/detection/rules/mycategory.yar`:
```yara
rule MyCustomSignature
{
    meta:
        description = "My detection pattern"
        category = "MyCategory"
        severity = "high"
    strings:
        $pattern = "malicious_indicator"
    condition:
        $pattern
}
```

2. Update `antivirus/detection/detection_engine.py`:
```python
"MyCustomSignature": "MyCategory.Custom",
```

3. Test:
```bash
pytest tests/ -v
```

### Task 2: Enable VirusTotal Enrichment

```bash
# Set API key
export VIRUSTOTAL_API_KEY=your_key_here

# Use normally; VirusTotal will be queried automatically
python main.py scan file.exe
```

### Task 3: Query Scan History

```python
from antivirus.repository.scan_repository import ScanRepository

repo = ScanRepository()
recent = repo.get_recent_scans(limit=10)

for scan in recent:
    print(f"File: {scan['file_path']}, Status: {scan['status']}")
```

### Task 4: Manage Quarantine

```python
from antivirus.services.quarantine_service import QuarantineService

quarantine = QuarantineService()

# Quarantine a file
record_id = quarantine.quarantine("malicious.exe", "Trojan.Backdoor")

# List quarantined files
files = quarantine.list_quarantined()

# Restore a file
quarantine.restore(record_id)

# Permanently delete
quarantine.delete(record_id)
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError: No module named 'flask'` | Run `pip install Flask==3.0.0` |
| `No module named 'yara'` | Run `pip install yara-python==4.3.2` |
| ClamAV not scanning | Ensure clamd service is running (optional feature) |
| Database locked error | Restart the application; only one process should access DB at a time |
| YARA rule compilation error | Check `.yar` file syntax; all `$` variables must be referenced in condition |

## Next Steps

1. **Review README.md** for full API documentation
2. **Explore tests/** to understand usage patterns
3. **Check antivirus/detection/rules/** for available YARA patterns
4. **Read PROJECT_COMPLETION_SUMMARY.md** for architecture overview

## Support

- Check README.md for comprehensive documentation
- Review test files for usage examples
- See PROJECT_COMPLETION_SUMMARY.md for architecture details
