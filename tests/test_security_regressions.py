"""Regressions for concrete false-clean, authorization and export failures."""

import csv
import json
import sqlite3
from io import StringIO
from types import SimpleNamespace

import pytest

from antivirus.detection.detection_engine import DetectionEngine
from antivirus.model.scan_report import ScanReport
from antivirus.model.scan_result import ScanResult
from antivirus.model.scan_status import ScanStatus
from antivirus.model.threat import Threat
from antivirus.services.scanner import Scanner
from antivirus.services.clamav_service import ClamAVService
from antivirus.services.virustotal_service import VirusTotalService
from antivirus.services.report_formatter import ReportFormatter
from antivirus.services.report_signer import ReportSigner
from antivirus.controller.scan_controller import ScanController
from antivirus.repository.scan_repository import ScanRepository


@pytest.fixture
def sample(tmp_path):
    path = tmp_path / "safe.txt"
    path.write_text("ordinary text")
    return path


def engine(tmp_path, **kwargs):
    from antivirus.repository.threat_repository import ThreatRepository

    return DetectionEngine(
        threat_repository=ThreatRepository(str(tmp_path / "threats.db")),
        clamav_enabled=False,
        **kwargs,
    )


def test_yara_failure_never_reports_clean(tmp_path, sample):
    class BrokenYara:
        def scan_file_details(self, path):
            raise RuntimeError("rules failed")

    result = engine(tmp_path, yara_service=BrokenYara()).analyze_file(str(sample))
    assert result.status == ScanStatus.ERROR
    assert not result.is_clean
    assert result.engine_results["yara"] == "error"
    assert result.checked_engines == ["hash"]


def test_all_engines_disabled_is_skipped(tmp_path, sample):
    result = engine(tmp_path, hash_enabled=False, yara_enabled=False).analyze_file(
        str(sample)
    )
    assert result.status == ScanStatus.SKIPPED
    assert not result.is_clean
    assert not result.checked_engines


def test_hash_repository_failure_is_incomplete(tmp_path, sample):
    class BrokenRepository:
        def find_by_hash(self, value):
            raise RuntimeError("database locked")

    result = DetectionEngine(
        threat_repository=BrokenRepository(), clamav_enabled=False
    ).analyze_file(str(sample))
    assert result.status == ScanStatus.ERROR
    assert "Hash lookup failed" in result.error_message


def test_engine_availability_survives_locked_hash_catalogue():
    class BrokenRepository:
        def count(self):
            raise sqlite3.OperationalError("database is locked")

    states = DetectionEngine(
        threat_repository=BrokenRepository(), clamav_enabled=False
    ).get_engine_states()
    assert not states["hash"]["available"]
    assert states["hash"]["signature_count"] is None
    assert "cannot be read" in states["hash"]["error_message"]
    assert states["yara"]["available"]


def test_detection_survives_another_engine_failure(tmp_path, sample):
    class BrokenRepository:
        def find_by_hash(self, value):
            raise RuntimeError("database locked")

    sample.write_text("EDU_RANSOMWARE_PAYLOAD ransom_note")
    result = DetectionEngine(
        threat_repository=BrokenRepository(), clamav_enabled=False
    ).analyze_file(str(sample))
    assert result.is_detected
    assert result.error_message
    assert not result.is_clean


def test_common_benign_words_do_not_trigger_demo_signatures(tmp_path, sample):
    sample.write_text(
        "Cookie Password Email Clipboard Screenshot GetDC BitBlt CopyFileA "
        "System32 SMTP Outlook bind cmd.exe Remote encrypt_all_files ransom_note"
    )
    result = engine(tmp_path).analyze_file(str(sample))
    assert result.is_clean
    assert result.engine_results["yara"] == "clean"


def test_file_changed_during_scan_is_incomplete(tmp_path, sample):
    class WritingYara:
        def scan_file_details(self, path):
            sample.write_text("a longer different revision")
            return []

    result = engine(tmp_path, yara_service=WritingYara()).analyze_file(str(sample))
    assert result.status == ScanStatus.ERROR
    assert "changed" in result.error_message


def test_size_limit_does_not_report_clean(tmp_path, sample):
    result = engine(tmp_path, max_file_bytes=1).analyze_file(str(sample))
    assert result.status == ScanStatus.SKIPPED


def test_special_file_does_not_block_scanning(tmp_path):
    import os

    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO files are POSIX only")
    path = tmp_path / "pipe"
    os.mkfifo(path)
    result = engine(tmp_path).analyze_file(str(path))
    assert result.status == ScanStatus.SKIPPED


def test_file_symlink_is_skipped(tmp_path, sample):
    link = tmp_path / "linked.txt"
    try:
        link.symlink_to(sample)
    except OSError:
        pytest.skip("Symlink creation is unavailable")
    result = engine(tmp_path).analyze_file(str(link))
    assert result.status == ScanStatus.SKIPPED


def test_missing_folder_and_regular_file_folder_target_are_errors(tmp_path, sample):
    scanner = Scanner(engine(tmp_path))
    for target in [tmp_path / "missing", sample]:
        report = scanner.scan_directory(str(target))
        assert report.error_files == 1
        assert report.outcome == "error"


def test_skipped_report_and_empty_report_are_not_clean():
    report = ScanReport()
    assert report.outcome == "empty"
    report.add_result(ScanResult("oversized", ScanStatus.SKIPPED))
    assert report.clean_files == 0
    assert report.skipped_files == 1
    assert report.outcome == "error"


def test_partial_scan_history_preserves_incomplete_status(tmp_path, sample):
    repository = ScanRepository(str(tmp_path / "history.db"))

    class PartialScanner:
        def scan_directory(self, *args):
            report = ScanReport()
            report.add_result(ScanResult(str(sample), ScanStatus.CLEAN))
            report.add_result(ScanResult("unreadable", ScanStatus.ERROR))
            report.add_result(ScanResult("big", ScanStatus.SKIPPED))
            return report

    report = ScanController(PartialScanner(), repository).scan_directory(str(tmp_path))
    row = repository.get_recent_scans()[0]
    assert row["status"] == "partial"
    assert row["skipped_files"] == 1
    assert row["started_at"] <= row["completed_at"]
    assert row["duration"] >= 0
    assert report.outcome == "partial"


def test_cancellation_preserves_results_and_never_claims_clean(tmp_path, sample):
    (tmp_path / "second.txt").write_text("safe")
    stop = [False]

    def progress(*args):
        stop[0] = True

    report = Scanner(engine(tmp_path)).scan_directory(
        str(tmp_path), progress, lambda: stop[0]
    )
    assert report.total_files == 1
    assert report.cancelled
    assert report.outcome == "cancelled"


def test_scan_file_limit_is_visible(tmp_path):
    for i in range(4):
        (tmp_path / f"{i}.txt").write_text("safe")

    class CleanEngine:
        def analyze_file(self, path):
            return ScanResult(path)

    report = Scanner(CleanEngine(), max_files=2).scan_directory(str(tmp_path))
    assert report.total_files == 2
    assert report.outcome == "partial"
    assert report.warnings


def test_history_failure_does_not_discard_file_result(tmp_path, sample):
    class BrokenHistory:
        def record_scan(self, *args, **kwargs):
            raise RuntimeError("disk full")

    result = ScanController(Scanner(engine(tmp_path)), BrokenHistory()).scan_file(
        str(sample)
    )
    assert result.is_clean


@pytest.mark.parametrize(
    "response",
    [{"/file": ("ERROR", "permission denied")}, {}, {"unexpected": "nonsense"}],
)
def test_clamav_daemon_errors_are_not_clean(tmp_path, sample, response):
    service = ClamAVService(SimpleNamespace(scan_file=lambda p: response))
    assert service.scan_file(str(sample))["status"] == "error"


def test_virustotal_unknown_is_not_clean():
    service = VirusTotalService(
        "test-key", lambda *a, **k: SimpleNamespace(status_code=404)
    )
    assert service.lookup_hash("a" * 64)["status"] == "unknown"


@pytest.mark.parametrize(
    "payload",
    [
        {},
        [],
        {"data": {"attributes": {"last_analysis_stats": {}}}},
        {"data": {"attributes": {"last_analysis_stats": {"malicious": "five"}}}},
    ],
)
def test_invalid_virustotal_statistics_are_errors(payload):
    service = VirusTotalService(
        "test-key",
        lambda *a, **k: SimpleNamespace(status_code=200, json=lambda: payload),
    )
    assert service.lookup_hash("a" * 64)["status"] == "error"


def test_online_limit_and_cache_do_not_repeat_requests():
    calls = []

    def client(*args, **kwargs):
        calls.append(kwargs)
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 1}}}}

    service = VirusTotalService("test-key", client)
    assert service.lookup_hash("a" * 64)["status"] == "detected"
    assert service.lookup_hash("a" * 64)["status"] == "detected"
    assert service.lookup_hash("b" * 64)["status"] == "error"
    assert len(calls) == 1
    assert calls[0]["allow_redirects"] is False


@pytest.mark.parametrize(
    "value", ['=HYPERLINK("x")', "+1+1", "-1+1", "@SUM(A1)", "\t=1", "   =1"]
)
def test_csv_neutralizes_untrusted_formula_fields(value):
    report = ScanReport()
    report.add_result(
        ScanResult(value, threats=[Threat(value, value)], error_message=value)
    )
    rows = list(csv.reader(StringIO(ReportFormatter.to_csv(report))))
    assert rows[1][0].startswith("'")
    assert rows[1][3].startswith("'")
    assert rows[1][4].startswith("'")
    assert rows[1][8].startswith("'")


def test_report_export_keeps_cancellation_and_skips():
    report = ScanReport(cancelled=True, warnings=["Incomplete scan"])
    report.add_result(ScanResult("large", ScanStatus.SKIPPED))
    data = json.loads(ReportFormatter.to_json(report))
    assert data["summary"]["outcome"] == "cancelled"
    assert data["summary"]["skipped_files"] == 1
    assert data["summary"]["warnings"] == ["Incomplete scan"]


def test_signed_report_detects_tampering_and_requires_trusted_key(tmp_path):
    report = ScanReport()
    report.add_result(ScanResult("file.txt"))
    signer = ReportSigner(tmp_path / "keys")
    bundle = signer.sign(report)
    public = (tmp_path / "keys" / "report-public.pem").read_bytes()
    assert ReportSigner.verify(bundle, public)
    bundle["report"]["summary"]["clean_files"] = 999
    assert not ReportSigner.verify(bundle, public)
    bundle = signer.sign(report)
    other = ReportSigner(tmp_path / "other")
    other.sign(report)
    assert not ReportSigner.verify(
        bundle, (tmp_path / "other" / "report-public.pem").read_bytes()
    )
    assert not ReportSigner.verify([], public)


def test_signature_private_key_is_owner_only_on_posix(tmp_path):
    import os

    signer = ReportSigner(tmp_path / "keys")
    signer.sign(ScanReport())
    if os.name == "posix":
        assert (
            tmp_path / "keys" / "report-signing.pem"
        ).stat().st_mode & 0o777 == 0o600


def test_missing_yara_dependency_is_not_a_clean_check(monkeypatch, tmp_path, sample):
    import antivirus.services.yara_service as module

    monkeypatch.setattr(module, "yara", None)
    result = engine(tmp_path, yara_service=module.YaraService()).analyze_file(
        str(sample)
    )
    assert result.status == ScanStatus.ERROR
    assert result.engine_results["yara"] == "error"


def test_linked_folder_is_skipped_without_scanning_its_contents(tmp_path):
    target = tmp_path / "outside"
    target.mkdir()
    (target / "sample.txt").write_text("safe")
    root = tmp_path / "root"
    root.mkdir()
    link = root / "linked"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("Symlink creation is unavailable")

    class NeverScan:
        def analyze_file(self, path):
            raise AssertionError("Linked content was scanned")

    report = Scanner(NeverScan()).scan_directory(str(root))
    assert report.skipped_files == 1
    assert report.clean_files == 0


def test_old_history_schema_migrates_without_losing_rows(tmp_path):
    import sqlite3

    path = tmp_path / "old.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE scan_history (id INTEGER PRIMARY KEY, started_at TEXT NOT NULL, "
            "completed_at TEXT, file_count INTEGER NOT NULL, threats_found INTEGER NOT NULL, "
            "clean_files INTEGER NOT NULL, error_files INTEGER NOT NULL, status TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO scan_history VALUES (1, '2026-01-01', '2026-01-01', 1, 0, 1, 0, 'clean')"
        )
    repository = ScanRepository(str(path))
    old = repository.get_recent_scans()[0]
    assert old["clean_files"] == 1
    assert old["skipped_files"] == 0
    assert old["warnings"] == []
    repository.record_scan(1, 0, 0, 0, "error", skipped_files=1, warnings=["too large"])
    assert len(repository.get_recent_scans()) == 2
    assert repository.get_recent_scans()[0]["warnings"] == ["too large"]


def test_detected_file_with_failed_checks_is_also_incomplete():
    report = ScanReport()
    report.add_result(
        ScanResult("sample", ScanStatus.DETECTED, error_message="Engine failed")
    )
    assert report.threat_files == 1
    assert report.incomplete_files == 1
    assert report.outcome == "detected"
    assert report.warnings
