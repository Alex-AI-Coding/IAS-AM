import json
import csv
from io import StringIO

from antivirus.model.scan_report import ScanReport
from antivirus.model.scan_result import ScanResult
from antivirus.model.scan_status import ScanStatus
from antivirus.model.threat import Threat
from antivirus.services.report_formatter import ReportFormatter


def test_report_formatter_to_json():
    report = ScanReport()
    result = ScanResult(file_path="test.txt", status=ScanStatus.CLEAN)
    result.sha256 = "abc123"
    report.add_result(result)

    json_str = ReportFormatter.to_json(report)
    data = json.loads(json_str)

    assert "summary" in data
    assert "results" in data
    assert data["summary"]["total_files"] == 1
    assert data["summary"]["clean_files"] == 1
    assert len(data["results"]) == 1


def test_report_formatter_to_csv():
    report = ScanReport()
    result = ScanResult(file_path="malware.exe", status=ScanStatus.DETECTED)
    result.sha256 = "def456"
    threat = Threat(
        name="Test.Malware",
        category="Trojan",
        severity="High",
        description="Test threat",
        source="yara",
        hash_value="def456",
    )
    result.threats.append(threat)
    result.detection_methods.append("yara")
    report.add_result(result)

    csv_str = ReportFormatter.to_csv(report)

    reader = csv.reader(StringIO(csv_str))
    rows = list(reader)

    assert len(rows) > 1
    assert rows[0][0] == "File Path"
    assert any("malware.exe" in row for row in rows)
    assert any("Test.Malware" in row for row in rows)


def test_report_formatter_to_dict():
    report = ScanReport()
    result = ScanResult(file_path="clean.txt", status=ScanStatus.CLEAN)
    result.sha256 = "xyz789"
    report.add_result(result)

    data = ReportFormatter.to_dict(report)

    assert isinstance(data, dict)
    assert "summary" in data
    assert "results" in data
    assert data["summary"]["total_files"] == 1


def test_report_formatter_csv_with_errors():
    report = ScanReport()
    result = ScanResult(file_path="missing.txt", status=ScanStatus.ERROR)
    result.error_message = "File not found"
    report.add_result(result)

    csv_str = ReportFormatter.to_csv(report)

    reader = csv.reader(StringIO(csv_str))
    rows = list(reader)

    assert any("File not found" in row for row in rows)
