from antivirus.services.clamav_service import ClamAVService


class FakeClient:
    def scan(self, path):
        if path.endswith("infected.bin"):
            return {"Infected": "FOUND", "Result": "KNOWN_THREAT"}
        return {"Infected": False, "Result": "OK"}


def test_clamav_service_reports_clean_file(tmp_path):
    clean_file = tmp_path / "clean.bin"
    clean_file.write_bytes(b"safe content")

    service = ClamAVService(client=FakeClient())
    result = service.scan_file(str(clean_file))

    assert result["status"] == "clean"
    assert result["threats"] == []


def test_clamav_service_reports_detected_file(tmp_path):
    infected_file = tmp_path / "infected.bin"
    infected_file.write_bytes(b"dangerous pattern")

    service = ClamAVService(client=FakeClient())
    result = service.scan_file(str(infected_file))

    assert result["status"] == "detected"
    assert result["threats"]


def test_clamav_service_handles_missing_file():
    service = ClamAVService(client=FakeClient())
    result = service.scan_file("does_not_exist.bin")

    assert result["status"] == "error"
    assert "not found" in result["message"].lower()
