from antivirus.model.scan_report import ScanReport
from antivirus.model.scan_result import ScanResult
from antivirus.model.scan_status import ScanStatus
from antivirus.model.threat import Threat


def test_threat_defaults():
    threat = Threat(name="Educational.Ransomware.Test", category="Ransomware")

    assert threat.name == "Educational.Ransomware.Test"
    assert threat.category == "Ransomware"
    assert threat.severity == "Medium"
    assert threat.description == ""


def test_scan_result_tracks_status_and_threats():
    result = ScanResult(file_path="sample.exe", status=ScanStatus.DETECTED)
    result.threats.append(Threat(name="Trojan.Sample", category="Trojan"))

    assert result.file_path == "sample.exe"
    assert result.status == ScanStatus.DETECTED
    assert len(result.threats) == 1


def test_scan_report_summary():
    report = ScanReport(total_files=3, clean_files=2, threat_files=1, error_files=0)

    assert report.total_files == 3
    assert report.clean_files == 2
    assert report.threat_files == 1
    assert report.error_files == 0
