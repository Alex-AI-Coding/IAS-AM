from antivirus.repository.scan_repository import ScanRepository


def test_scan_repository_records_and_reads_history(tmp_path):
    db_path = tmp_path / "scan_history.db"
    repository = ScanRepository(str(db_path))

    repository.record_scan(
        file_count=5,
        threats_found=2,
        clean_files=3,
        error_files=0,
        status="completed",
    )

    history = repository.get_recent_scans(limit=10)

    assert len(history) == 1
    assert history[0]["file_count"] == 5
    assert history[0]["threats_found"] == 2
    assert history[0]["status"] == "completed"
