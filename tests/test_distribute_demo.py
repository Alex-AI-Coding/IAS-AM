"""Copy real demo content, then check it using the real local scanner."""

from pathlib import Path

import pytest

from antivirus.detection.detection_engine import DetectionEngine
from antivirus.model.scan_status import ScanStatus
from antivirus.repository.threat_repository import ThreatRepository
from antivirus.services.hash_service import HashService
from antivirus.services.scanner import Scanner
from scripts.distribute_demo import DEMO_FOLDER, SOURCE_DIR, distribute_samples, main


def test_copies_scan_with_real_yara_and_exact_hash_at_multiple_locations(tmp_path):
    destinations = [tmp_path / "first drive", tmp_path / "second drive"]
    for destination in destinations:
        destination.mkdir()
    targets = distribute_samples(destinations, copies=2)
    repository = ThreatRepository(str(tmp_path / "threats.db"))
    engine = DetectionEngine(
        threat_repository=repository,
        clamav_enabled=False,
        virustotal_enabled=False,
    )
    scanner = Scanner(engine)
    initial = scanner.scan_directories([str(target) for target in targets])
    assert initial.total_files == 24
    assert sum(result.status == ScanStatus.DETECTED for result in initial.results) == 16
    assert sum(result.status == ScanStatus.CLEAN for result in initial.results) == 8

    repository.add_threat(
        "Educational.Hash.Catalogue",
        "Harmless demonstration",
        HashService.calculate_sha256(str(SOURCE_DIR / "hash-match-demo.txt")),
        severity="Low",
    )
    report = scanner.scan_directories([str(target) for target in targets])

    assert report.total_files == 24
    assert sum(result.status == ScanStatus.DETECTED for result in report.results) == 20
    assert sum(result.status == ScanStatus.CLEAN for result in report.results) == 4
    for result in report.results:
        filename = Path(result.file_path).name
        sample = SOURCE_DIR / filename
        assert HashService.calculate_sha256(str(sample)) == result.sha256
        expected = [] if filename == "clean.txt" else ["yara"]
        if filename == "hash-match-demo.txt":
            expected = ["hash"]
        assert result.detection_methods == expected


def test_existing_demo_folder_is_preserved_before_any_destination_is_written(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    existing = second / DEMO_FOLDER
    existing.mkdir(parents=True)
    retained = existing / "ransomware-demo.txt"
    retained.write_bytes(b"Existing user content")

    with pytest.raises(ValueError, match="already exists"):
        distribute_samples([first, second])

    assert retained.read_bytes() == b"Existing user content"
    assert not (first / DEMO_FOLDER).exists()


def test_missing_destination_does_not_create_folders(tmp_path):
    existing = tmp_path / "valid"
    existing.mkdir()
    missing = tmp_path / "missing drive"

    assert main(["-d", str(existing), "-d", str(missing)]) == 2
    assert not missing.exists()
    assert not (existing / DEMO_FOLDER).exists()


def test_dry_run_lists_locations_without_creating_samples(tmp_path, capsys):
    assert main(["-d", str(tmp_path), "--copies", "2", "--dry-run"]) == 0
    assert not (tmp_path / DEMO_FOLDER).exists()
    assert "Would create:" in capsys.readouterr().out
