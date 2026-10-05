import pytest
from antivirus.services.statistics_service import StatisticsService
from antivirus.model.scan_report import ScanReport
from antivirus.model.scan_result import ScanResult, ScanStatus
from antivirus.model.threat import Threat


@pytest.fixture
def statistics_service():
    return StatisticsService()


def test_get_scan_statistics(statistics_service):
    stats = statistics_service.get_scan_statistics(hours=24)
    assert "total_scans" in stats
    assert "threat_scans" in stats
    assert "clean_scans" in stats
    assert "detection_rate" in stats
    assert stats["time_period_hours"] == 24


def test_get_threat_distribution(statistics_service):
    distribution = statistics_service.get_threat_distribution()
    assert isinstance(distribution, dict)


def test_get_top_threats(statistics_service):
    threats = statistics_service.get_top_threats(limit=5)
    assert isinstance(threats, list)
    for threat in threats:
        assert "name" in threat
        assert "count" in threat


def test_get_false_positive_ratio(statistics_service):
    ratio = statistics_service.get_false_positive_ratio()
    assert ratio is None


def test_get_detection_summary(statistics_service):
    # Create a test report
    report = ScanReport()

    threat1 = Threat(
        name="Trojan.Backdoor",
        category="Trojan",
        severity="High",
        description="Test",
        source="yara",
    )
    threat2 = Threat(
        name="Spyware.Keylogger",
        category="Spyware",
        severity="Medium",
        description="Test",
        source="hash",
    )

    result1 = ScanResult(
        file_path="test1.exe",
        status=ScanStatus.DETECTED,
        sha256="abc123",
    )
    result1.threats = [threat1, threat2]
    result1.detection_methods = ["yara", "hash"]

    report.add_result(result1)

    summary = statistics_service.get_detection_summary(report)
    assert "threat_categories" in summary
    assert "threat_severities" in summary
    assert "detection_methods" in summary
    assert summary["total_threats"] == 2
    assert "Trojan" in summary["threat_categories"]
    assert "Spyware" in summary["threat_categories"]


def test_get_performance_metrics(statistics_service):
    metrics = statistics_service.get_performance_metrics()
    assert "total_scans" in metrics
    assert "scans_processed" in metrics
    assert "avg_scan_time_ms" in metrics
