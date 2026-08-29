import pytest

from antivirus import api
from antivirus.model.scan_result import ScanResult
from antivirus.model.scan_status import ScanStatus
from antivirus.model.threat import Threat


class FakeScanner:
    """Deterministic scanner substitute for HTTP boundary tests."""

    def __init__(self):
        self.scanned_files = []
        self.scanned_directories = []

    def scan_file(self, path):
        self.scanned_files.append(path)
        return ScanResult(
            file_path=path,
            status=ScanStatus.CLEAN,
            sha256="test-sha256",
            detection_methods=["hash"],
        )

    def scan_directory(self, path):
        self.scanned_directories.append(path)
        from antivirus.model.scan_report import ScanReport

        report = ScanReport()
        report.add_result(
            ScanResult(
                file_path=f"{path}/sample.txt",
                status=ScanStatus.DETECTED,
                threats=[
                    Threat(
                        name="Educational.Test",
                        category="Test",
                        severity="Low",
                        source="yara",
                    )
                ],
                detection_methods=["yara"],
            )
        )
        return report


@pytest.fixture
def client(monkeypatch):
    fake_scanner = FakeScanner()
    monkeypatch.setattr(api, "scanner", fake_scanner)
    app = api.create_app()
    app.config.update(TESTING=True)
    with app.test_client() as client:
        yield client


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "healthy"


def test_scan_file_api_missing_target(client):
    response = client.post("/api/v1/scan", json={})
    assert response.status_code == 400
    assert "target" in response.data.decode()


def test_scan_file_api_rejects_non_json_or_invalid_target(client):
    response = client.post("/api/v1/scan", data="not json")
    assert response.status_code == 400

    response = client.post("/api/v1/scan", json={"target": 123})
    assert response.status_code == 400


def test_scan_file_api_nonexistent_target(client):
    response = client.post("/api/v1/scan", json={"target": "/nonexistent/file.bin"})
    assert response.status_code == 404


def test_scan_file_api_success(client, tmp_path):
    test_file = tmp_path / "clean_test.bin"
    test_file.write_text("clean content")

    response = client.post("/api/v1/scan", json={"target": str(test_file)})
    assert response.status_code == 200
    data = response.get_json()
    assert "summary" in data
    assert "results" in data


def test_scan_batch_api_missing_targets(client):
    response = client.post("/api/v1/scan/batch", json={})
    assert response.status_code == 400


def test_scan_batch_api_invalid_targets(client):
    response = client.post("/api/v1/scan/batch", json={"targets": "not_a_list"})
    assert response.status_code == 400


def test_scan_batch_api_success(client, tmp_path):
    file1 = tmp_path / "file1.bin"
    file2 = tmp_path / "file2.bin"
    file1.write_text("content1")
    file2.write_text("content2")

    response = client.post("/api/v1/scan/batch", json={"targets": [str(file1), str(file2)]})
    assert response.status_code == 200
    data = response.get_json()
    assert data["summary"]["total_files"] == 2


def test_scan_directory_and_batch_directory(client, tmp_path):
    directory = tmp_path / "samples"
    directory.mkdir()

    scan_response = client.post("/api/v1/scan", json={"target": str(directory)})
    assert scan_response.status_code == 200
    assert scan_response.get_json()["summary"]["threat_files"] == 1

    batch_response = client.post("/api/v1/scan/batch", json={"targets": [str(directory)]})
    assert batch_response.status_code == 200
    assert batch_response.get_json()["summary"]["threat_files"] == 1


def test_scan_batch_rejects_invalid_target_item(client):
    response = client.post("/api/v1/scan/batch", json={"targets": ["valid", 123]})
    assert response.status_code == 400


def test_export_report_json(client, tmp_path):
    test_file = tmp_path / "test.bin"
    test_file.write_text("clean")

    response = client.post("/api/v1/report/json", json={"target": str(test_file)})
    assert response.status_code == 200
    assert "Content-Type" in response.headers
    assert "application/json" in response.headers["Content-Type"]


def test_export_report_csv(client, tmp_path):
    test_file = tmp_path / "test.bin"
    test_file.write_text("clean")

    response = client.post("/api/v1/report/csv", json={"target": str(test_file)})
    assert response.status_code == 200
    assert "Content-Type" in response.headers
    assert "text/csv" in response.headers["Content-Type"]


def test_export_report_invalid_format(client, tmp_path):
    test_file = tmp_path / "test.bin"
    test_file.write_text("clean")

    response = client.post("/api/v1/report/xml", json={"target": str(test_file)})
    assert response.status_code == 400


def test_export_report_rejects_missing_or_non_json_payload(client):
    missing_target = client.post("/api/v1/report/json", json={})
    assert missing_target.status_code == 400

    non_json = client.post("/api/v1/report/json", data="not json")
    assert non_json.status_code == 400
