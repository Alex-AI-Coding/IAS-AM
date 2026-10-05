from antivirus.detection.detection_engine import DetectionEngine
from antivirus.model.scan_status import ScanStatus


def test_detection_engine_detects_yara_match(tmp_path):
    sample = tmp_path / "ransomware_test.txt"
    sample.write_text(
        "EDU_RANSOMWARE_PAYLOAD encrypt_all_files ransom_note", encoding="utf-8"
    )

    engine = DetectionEngine()
    result = engine.analyze_file(str(sample))

    assert result.status == ScanStatus.DETECTED
    assert any(threat.category == "Ransomware" for threat in result.threats)


def test_detection_engine_handles_missing_file():
    engine = DetectionEngine()
    result = engine.analyze_file("does_not_exist.bin")

    assert result.status == ScanStatus.ERROR
    assert result.error_message
