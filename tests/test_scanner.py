from antivirus.services.scanner import Scanner


def test_scan_directory_returns_summary(tmp_path):
    safe_file = tmp_path / "safe.txt"
    safe_file.write_text("this is a harmless file", encoding="utf-8")

    risky_file = tmp_path / "ransomware_test.txt"
    risky_file.write_text(
        "EDU_RANSOMWARE_PAYLOAD encrypt_all_files ransom_note", encoding="utf-8"
    )

    scanner = Scanner()
    report = scanner.scan_directory(str(tmp_path))

    assert report.total_files == 2
    assert report.threat_files >= 1
    assert report.clean_files >= 1


def test_scan_file_returns_result_for_missing_file():
    scanner = Scanner()
    result = scanner.scan_file("does_not_exist.bin")

    assert result.status.value == "error"
    assert "not found" in result.error_message.lower()
