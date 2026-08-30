from antivirus.services.virustotal_service import VirusTotalService


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def read(self):
        import json

        return json.dumps(self.payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class FakeClient:
    def __init__(self, payload):
        self.payload = payload

    def __call__(self, *args, **kwargs):
        return FakeResponse(self.payload)


def test_virustotal_service_disabled_without_api_key(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    service = VirusTotalService(api_key=None)
    result = service.lookup_hash("abc123")

    assert result["status"] == "disabled"


def test_virustotal_service_parses_positive_result():
    response = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 10}
            }
        }
    }
    service = VirusTotalService(api_key="demo-key", http_client=FakeClient(response))
    result = service.lookup_hash("deadbeef")

    assert result["status"] == "detected"
    assert result["malicious_count"] == 5
