from antivirus.detection.detection_engine import DetectionEngine
from antivirus.model.scan_status import ScanStatus


def test_worm_network_replication_detection(tmp_path):
    engine = DetectionEngine()
    test_file = tmp_path / "worm_test.bin"
    test_file.write_text("CreateRemoteThread bind payload")

    result = engine.analyze_file(str(test_file))

    assert result.status == ScanStatus.DETECTED
    assert "yara" in result.detection_methods
    assert any("Worm" in threat.category for threat in result.threats)


def test_worm_file_replication_detection(tmp_path):
    engine = DetectionEngine()
    test_file = tmp_path / "worm_replicator.bin"
    test_file.write_text("CopyFileA System32 propagate")

    result = engine.analyze_file(str(test_file))

    assert result.status == ScanStatus.DETECTED
    assert "yara" in result.detection_methods
    assert any("Worm" in threat.category for threat in result.threats)


def test_worm_mass_emailer_detection(tmp_path):
    engine = DetectionEngine()
    test_file = tmp_path / "worm_mailer.bin"
    test_file.write_text("SMTP SendMailA Outlook AddressBook")

    result = engine.analyze_file(str(test_file))

    assert result.status == ScanStatus.DETECTED
    assert "yara" in result.detection_methods
    assert any("Worm" in threat.category for threat in result.threats)


def test_spyware_keylogger_detection(tmp_path):
    engine = DetectionEngine()
    test_file = tmp_path / "keylogger.bin"
    test_file.write_text("SetWindowsHookExA GetKeyState WM_KEYDOWN")

    result = engine.analyze_file(str(test_file))

    assert result.status == ScanStatus.DETECTED
    assert "yara" in result.detection_methods
    assert any("Spyware" in threat.category for threat in result.threats)


def test_spyware_screen_capture_detection(tmp_path):
    engine = DetectionEngine()
    test_file = tmp_path / "screen_spy.bin"
    test_file.write_text("GetDC BitBlt Screenshot")

    result = engine.analyze_file(str(test_file))

    assert result.status == ScanStatus.DETECTED
    assert "yara" in result.detection_methods
    assert any("Spyware" in threat.category for threat in result.threats)


def test_spyware_data_thief_detection(tmp_path):
    engine = DetectionEngine()
    test_file = tmp_path / "data_thief.bin"
    test_file.write_text("Cookie Password Email Clipboard")

    result = engine.analyze_file(str(test_file))

    assert result.status == ScanStatus.DETECTED
    assert "yara" in result.detection_methods
    assert any("Spyware" in threat.category for threat in result.threats)


def test_spyware_remote_access_detection(tmp_path):
    engine = DetectionEngine()
    test_file = tmp_path / "backdoor.bin"
    test_file.write_text("bind cmd.exe Remote")

    result = engine.analyze_file(str(test_file))

    assert result.status == ScanStatus.DETECTED
    assert "yara" in result.detection_methods
    assert any("Spyware" in threat.category for threat in result.threats)
