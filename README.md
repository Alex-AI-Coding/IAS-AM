# Educational Antivirus Backend

A Python-based educational antivirus backend implementing multi-engine threat detection with hash-based, YARA rule-based, and ClamAV integration.

## Features

### Detection Engines
- **Hash-Based Detection** — SQLite repository of known malicious file hashes (SHA-256)
- **YARA Rule Engine** — Educational heuristic signatures for malware patterns
- **ClamAV Integration** — Boundary service for real-time antivirus scanning
- **VirusTotal Enrichment** — Optional online threat intelligence (requires API key)

### Malware Categories (4/4 Implemented)
1. **Trojan** — `TrojanSignature_Backdoor`, `TrojanSignature_PrivilegeEscalation`
2. **Ransomware** — `RansomwareSignature_Encryption`, `RansomwareSignature_FileMarking`
3. **Worm** — `WormSignature_NetworkReplication`, `WormSignature_FileReplication`, `WormSignature_MassEmailer`
4. **Spyware** — `SpywareSignature_KeyLogger`, `SpywareSignature_ScreenCapture`, `SpywareSignature_DataThief`, `SpywareSignature_RemoteAccess`

### Core Services
- **Scanner** — Recursive file and directory scanning with multi-engine detection
- **Quarantine** — Safe isolation of detected threats with restore capability
- **Scan History** — Persistent SQLite storage of scan results
- **Report Formatter** — Export scan results as JSON or CSV

### Interfaces
- **CLI** — Command-line interface with format options (`json`, `csv`)
- **REST API** — Flask-based HTTP API for programmatic access
- **Python API** — Direct Python module usage

## Architecture

```
antivirus/
├── model/              # Data models (Threat, ScanResult, ScanReport, ScanStatus)
├── services/           # Core services (Scanner, Detection, Quarantine, etc.)
├── repository/         # Data persistence (SQLite)
├── detection/          # Detection engines and YARA rules
├── utils/              # Utilities (logging, helpers)
├── config/             # Configuration and settings
└── api.py              # REST API (Flask)

tests/                  # 38+ test cases covering all features
```

## Installation

### Requirements
- Python 3.12+
- ClamAV (for on-demand scanning)
- pip

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd anti-virus-ias-project
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. (Optional) Install ClamAV:
```bash
# On Windows (via Scoop or manual installation)
# On macOS
brew install clamav

# On Linux
sudo apt-get install clamav
```

## Usage

### CLI - Scan a File

```bash
python main.py scan /path/to/file.exe --format json
```

**Output:**
```json
{
  "summary": {
    "total_files": 1,
    "clean_files": 0,
    "threat_files": 1,
    "error_files": 0
  },
  "results": [
    {
      "file_path": "/path/to/file.exe",
      "status": "detected",
      "sha256": "abc123...",
      "detection_methods": ["yara", "clamav"],
      "threats": [
        {
          "name": "Trojan.Backdoor",
          "category": "Trojan",
          "severity": "High",
          "description": "Educational signature match",
          "source": "yara"
        }
      ],
      "error_message": null
    }
  ]
}
```

### CLI - Scan a Directory

```bash
python main.py scan /path/to/directory --format csv
```

**Output (CSV):**
```csv
File Path,Status,SHA256,Threat Name,Category,Severity,Source,Detection Methods,Error Message
file1.exe,detected,abc123,Trojan.Backdoor,Trojan,High,yara,yara,
file2.txt,clean,def456,,,,,
```

### REST API - Health Check

```bash
curl http://localhost:5000/health
```

**Response:**
```json
{"status": "healthy"}
```

### REST API - Scan File

```bash
curl -X POST http://localhost:5000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "/path/to/file.exe"}'
```

### REST API - Scan Batch

```bash
curl -X POST http://localhost:5000/api/v1/scan/batch \
  -H "Content-Type: application/json" \
  -d '{
    "targets": [
      "/path/to/file1.exe",
      "/path/to/file2.dll",
      "/path/to/directory"
    ]
  }'
```

### REST API - Export Report

```bash
# Export as JSON
curl -X POST http://localhost:5000/api/v1/report/json \
  -H "Content-Type: application/json" \
  -d '{"target": "/path/to/file.exe"}'

# Export as CSV
curl -X POST http://localhost:5000/api/v1/report/csv \
  -H "Content-Type: application/json" \
  -d '{"target": "/path/to/file.exe"}'
```

### Python API

```python
from antivirus.services.scanner import Scanner
from antivirus.services.report_formatter import ReportFormatter

scanner = Scanner()

# Scan a file
result = scanner.scan_file("/path/to/file.exe")
print(f"Status: {result.status}")
print(f"Threats: {len(result.threats)}")

# Scan a directory
report = scanner.scan_directory("/path/to/directory")
print(f"Total files: {report.total_files}")
print(f"Threats found: {report.threat_files}")

# Export report
json_report = ReportFormatter.to_json(report)
csv_report = ReportFormatter.to_csv(report)
```

## Running the API Server

### Docker

Build and start the API container:

```bash
docker compose up --build antivirus-api
```

The API is available at `http://localhost:5000`. Persistent SQLite and quarantine data is stored in the `antivirus-data` Docker volume.

Run the test suite in a one-off container:

```bash
docker compose --profile test run --rm antivirus-tests
```

The PySide6 package is installed in the image, but displaying a desktop window from Docker requires host-specific display forwarding. Run the GUI directly on the host with `python -m antivirus.frontend_main`.

```bash
python -m flask --app antivirus.api run --port 5000
```

Or:

```bash
python antivirus/api.py
```

The API will be available at `http://localhost:5000`

## Testing

### Run All Tests

```bash
pytest tests/ -v
```

### Run Specific Test Suite

```bash
# Detection engine tests
pytest tests/test_detection_engine.py -v

# API tests
pytest tests/test_api.py -v

# Malware category tests
pytest tests/test_worm_spyware_rules.py -v
```

### Test Coverage

```bash
pytest tests/ --cov=antivirus --cov-report=html
```

## Configuration

Configuration is defined in `antivirus/config/settings.py`:

```python
BASE_DIR = Path(__file__).parent.parent.parent
RULE_DIR = BASE_DIR / "antivirus" / "detection" / "rules"
THREAT_DB_PATH = BASE_DIR / "antivirus_data" / "threats.db"
QUARANTINE_DIR = BASE_DIR / "antivirus_data" / "quarantine"
SCAN_HISTORY_DB = BASE_DIR / "antivirus_data" / "scans.db"
```

### Optional: VirusTotal API Key

Set environment variable to enable VirusTotal enrichment:

```bash
export VIRUSTOTAL_API_KEY=your_api_key_here
```

## Project Structure

- `antivirus/model/` — Data models and enums
- `antivirus/services/` — Core business logic
- `antivirus/repository/` — SQLite persistence layer
- `antivirus/detection/` — Detection engines and YARA rules
- `antivirus/utils/` — Logging and utilities
- `antivirus/config/` — Configuration
- `antivirus/api.py` — REST API server
- `main.py` — CLI entry point
- `tests/` — Test suite (38+ tests)

## Supported File Types

The backend scans all file types without restriction. YARA rules and ClamAV define detection patterns for:
- Executable files (.exe, .dll, .so)
- Scripts (.bat, .ps1, .sh)
- Documents (.pdf, .docx, .xlsx)
- Archives (.zip, .rar, .7z)
- Any other file type

## Limitations

- **Educational Only** — Uses harmless patterns for demonstration
- **Offline-First** — Default operation without internet (VirusTotal optional)
- **No GUI** — Backend only; integrate with a frontend as needed
- **ClamAV Optional** — Works without it; requires installation for full detection

## Performance Characteristics

- **Hash Lookup** — O(1) SQLite query
- **YARA Scanning** — Linear in file size
- **ClamAV Scanning** — Depends on file size and available signatures
- **Directory Scan** — Parallel multi-engine detection per file

## Security Considerations

- Quarantined files are isolated in `antivirus_data/quarantine/`
- Scan history is stored locally (no cloud transmission)
- VirusTotal enrichment requires explicit API key configuration
- All file paths are validated before processing

## Exit Codes

- `0` — Scan completed successfully
- `1` — Scan failed (file not found, error during processing)

## Extending the Backend

### Add Custom YARA Rules

Create a new `.yar` file in `antivirus/detection/rules/`:

```yara
rule CustomSignature_Example
{
    meta:
        description = "Custom detection pattern"
        category = "CustomCategory"
        severity = "high"
    strings:
        $pattern = "malicious_code" nocase
    condition:
        $pattern
}
```

Update `antivirus/detection/detection_engine.py` with the rule mapping:

```python
"CustomSignature_Example": "Custom.Example",
```

### Add Custom Detection Service

Create a service class implementing the detection interface and integrate it into the `DetectionEngine`.

## Testing Examples

```python
# Test hash-based detection
from antivirus.repository.threat_repository import ThreatRepository
repo = ThreatRepository()
repo.add_threat("abc123", "Test.Malware", "Trojan", "High", "Test threat")
found = repo.find_by_hash("abc123")
assert found["name"] == "Test.Malware"

# Test quarantine
from antivirus.services.quarantine_service import QuarantineService
quarantine = QuarantineService()
record_id = quarantine.quarantine("path/to/file.exe", "Trojan")
quarantine.restore(record_id)

# Test scan history
from antivirus.repository.scan_repository import ScanRepository
history = ScanRepository()
history.record_scan("file.exe", "detected")
recent = history.get_recent_scans(limit=10)
```

## Troubleshooting

### ClamAV not found
- Ensure ClamAV is installed and clamd service is running
- The backend gracefully handles missing ClamAV (only uses YARA/hash detection)

### YARA rule compilation errors
- Check `.yar` files for syntax errors
- Ensure all rule strings are properly referenced in the `condition`

### SQLite database locked
- Ensure only one process is accessing the database at a time
- The backend creates necessary directories automatically

## Version

**v1.0.0** — Initial release with 4 malware categories, unified detection, REST API, and comprehensive testing.
