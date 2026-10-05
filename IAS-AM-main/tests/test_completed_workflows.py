from antivirus.controller.scan_controller import ScanController
from antivirus.detection.detection_engine import DetectionEngine
from antivirus.model.scan_result import ScanResult
from antivirus.model.scan_status import ScanStatus
from antivirus.repository.scan_repository import ScanRepository
from antivirus.services.scanner import Scanner
from antivirus.services.statistics_service import StatisticsService


class CleanEngine:
    def analyze_file(self, file_path):
        return ScanResult(file_path=file_path, status=ScanStatus.CLEAN)


class FakeHashService:
    def calculate_sha256(self, _path):
        return "a" * 64


class FakeYaraService:
    _compiler = object()

    def scan_file_details(self, _path):
        return []


class FakeClamAVService:
    client = object()

    def scan_file(self, _path):
        return {"status": "clean"}


class EmptyThreatRepository:
    def find_by_hash(self, _file_hash):
        return None


class PositiveVirusTotalService:
    api_key = "test-key"

    def lookup_hash(self, _file_hash):
        return {
            "status": "detected",
            "malicious_count": 3,
            "suspicious_count": 1,
        }


def test_scan_repository_creates_parent_and_round_trips_details(tmp_path):
    db_path = tmp_path / "nested" / "scan_history.db"
    repository = ScanRepository(str(db_path))
    repository.record_scan(
        file_count=2,
        threats_found=1,
        clean_files=1,
        error_files=0,
        status="detected",
        target="sample-folder",
        scan_type="folder",
        duration=1.25,
        threats=[{"name": "Educational.Test", "category": "Test"}],
    )

    record = repository.get_recent_scans(limit=1)[0]

    assert db_path.exists()
    assert record["target"] == "sample-folder"
    assert record["scan_type"] == "folder"
    assert record["duration"] == 1.25
    assert record["threats"][0]["name"] == "Educational.Test"


def test_directory_scan_reports_accurate_progress(tmp_path):
    for name in ("a.txt", "b.txt", "c.txt"):
        (tmp_path / name).write_text("safe", encoding="utf-8")
    progress = []

    report = Scanner(CleanEngine()).scan_directory(
        str(tmp_path),
        lambda current, total, path: progress.append((current, total, path)),
    )

    assert report.total_files == 3
    assert [entry[:2] for entry in progress] == [(1, 3), (2, 3), (3, 3)]


def test_scan_controller_records_folder_history(tmp_path):
    target = tmp_path / "files"
    target.mkdir()
    (target / "safe.txt").write_text("safe", encoding="utf-8")
    repository = ScanRepository(str(tmp_path / "history.db"))
    controller = ScanController(Scanner(CleanEngine()), repository)

    controller.scan_directory(str(target))

    record = repository.get_recent_scans(limit=1)[0]
    assert record["scan_type"] == "folder"
    assert record["target"] == str(target)
    assert record["file_count"] == 1
    assert record["status"] == "clean"


def test_virustotal_detection_is_connected_to_detection_engine(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"safe test content")
    engine = DetectionEngine(
        hash_service=FakeHashService(),
        yara_service=FakeYaraService(),
        clamav_service=FakeClamAVService(),
        virustotal_service=PositiveVirusTotalService(),
        threat_repository=EmptyThreatRepository(),
        virustotal_enabled=True,
    )

    result = engine.analyze_file(str(sample))

    assert result.status == ScanStatus.DETECTED
    assert "virustotal" in result.detection_methods
    assert any(threat.name == "VirusTotal.Consensus" for threat in result.threats)


def test_statistics_use_persisted_threat_details(tmp_path):
    repository = ScanRepository(str(tmp_path / "history.db"))
    repository.record_scan(
        1,
        1,
        0,
        0,
        "detected",
        threats=[{"name": "Trojan.Backdoor", "category": "Trojan"}],
    )
    service = StatisticsService(scan_repo=repository)

    assert service.get_threat_distribution() == {"Trojan": 1}
    assert service.get_top_threats() == [{"name": "Trojan.Backdoor", "count": 1}]
