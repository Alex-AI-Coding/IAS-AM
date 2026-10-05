import pytest

from antivirus.api import create_app
from antivirus.model.scan_result import ScanResult

TOKEN = "classroom-test-token-" * 3


class CountingScanner:
    def __init__(self):
        self.paths = []

    def scan_file(self, path):
        self.paths.append(path)
        return ScanResult(path)


@pytest.fixture
def secured(tmp_path):
    service = CountingScanner()
    app = create_app(
        {"API_TOKEN": TOKEN, "SCAN_ROOT": str(tmp_path), "TESTING": True}, service
    )
    client = app.test_client()
    client.environ_base["HTTP_AUTHORIZATION"] = "Bearer " + TOKEN
    return app, client, service


def test_authentication_required_even_when_testing(secured):
    app, client, service = secured
    client.environ_base.pop("HTTP_AUTHORIZATION")
    assert client.get("/health").status_code == 200
    assert client.post("/api/v1/scan", json={"target": "file"}).status_code == 401
    assert not service.paths


def test_unconfigured_api_fails_closed(secured):
    app, client, service = secured
    app.config["API_TOKEN"] = ""
    assert client.post("/api/v1/scan", json={"target": "file"}).status_code == 503


@pytest.mark.parametrize(
    "value", [[], [1], "text", 42, None, {"target": "  "}, {"target": "x\x00x"}]
)
def test_invalid_json_shapes_do_not_reach_scanner(secured, value):
    app, client, service = secured
    assert client.post("/api/v1/scan", json=value).status_code == 400
    assert not service.paths


def test_path_outside_scope_is_forbidden(secured, tmp_path):
    app, client, service = secured
    outside = tmp_path.parent / "private.txt"
    outside.write_text("private")
    response = client.post("/api/v1/scan", json={"target": str(outside)})
    assert response.status_code == 403
    assert "private.txt" not in response.get_data(as_text=True)
    assert not service.paths


def test_relative_path_is_scoped_and_security_headers_are_set(secured, tmp_path):
    app, client, service = secured
    sample = tmp_path / "safe.txt"
    sample.write_text("safe")
    response = client.post("/api/v1/scan", json={"target": "safe.txt"})
    assert response.status_code == 200
    assert service.paths == [str(sample)]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_api_rejects_symlink_escape(secured, tmp_path):
    app, client, service = secured
    outside = tmp_path.parent / "private.bin"
    outside.write_bytes(b"private")
    link = tmp_path / "link.bin"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("Symlinks unavailable")
    assert client.post("/api/v1/scan", json={"target": "link.bin"}).status_code == 403
    assert not service.paths


def test_batch_validates_every_target_before_scanning(secured, tmp_path):
    app, client, service = secured
    (tmp_path / "safe.txt").write_text("safe")
    response = client.post(
        "/api/v1/scan/batch", json={"targets": ["safe.txt", "missing.txt"]}
    )
    assert response.status_code == 404
    assert not service.paths


@pytest.mark.parametrize("targets", [[], ["x"] * 33, ["x", 42]])
def test_empty_oversized_or_malformed_batch_is_rejected(secured, targets):
    app, client, service = secured
    assert (
        client.post("/api/v1/scan/batch", json={"targets": targets}).status_code == 400
    )
    assert not service.paths


def test_api_bounds_body_and_concurrent_work(secured, tmp_path):
    app, client, service = secured
    assert client.post("/api/v1/scan", json={"target": "x" * 20000}).status_code == 413
    (tmp_path / "safe.txt").write_text("safe")
    gate = app.extensions["scan_gate"]
    gate.acquire()
    try:
        assert (
            client.post("/api/v1/scan", json={"target": "safe.txt"}).status_code == 429
        )
        assert not service.paths
    finally:
        gate.release()


def test_unexpected_failure_does_not_leak_details(secured, tmp_path):
    app, client, service = secured

    class BrokenScanner:
        def scan_file(self, path):
            raise RuntimeError("secret credential value")

    app.config["SCANNER"] = BrokenScanner()
    (tmp_path / "safe.txt").write_text("safe")
    response = client.post("/api/v1/scan", json={"target": "safe.txt"})
    assert response.status_code == 500
    assert "secret credential" not in response.get_data(as_text=True)
    assert app.extensions["scan_gate"].acquire(blocking=False)
    app.extensions["scan_gate"].release()
