from antivirus.services.yara_service import YaraService


def test_yara_service_detects_ransomware_pattern(tmp_path):
    sample = tmp_path / "ransomware_test.txt"
    sample.write_text(
        "EDU_RANSOMWARE_PAYLOAD encrypt_all_files ransom_note", encoding="utf-8"
    )

    service = YaraService(rule_dir="antivirus/detection/rules")
    matches = service.scan_file(str(sample))

    assert "EducationalRansomware" in matches


def test_yara_service_detects_trojan_pattern(tmp_path):
    sample = tmp_path / "trojan_test.txt"
    sample.write_text(
        "EDU_TROJAN_PAYLOAD backdoor_loader persistence_beacon remote_payload",
        encoding="utf-8",
    )

    service = YaraService(rule_dir="antivirus/detection/rules")
    matches = service.scan_file(str(sample))

    assert "EducationalTrojan" in matches
