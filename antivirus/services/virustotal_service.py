from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional


class VirusTotalService:
    """Optional online enrichment layer. It is deliberately isolated and disabled by default."""

    def __init__(self, api_key: Optional[str] = None, http_client: Optional[Any] = None):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self.http_client = http_client or self._default_client()

    def _default_client(self) -> Any:
        class _HttpClient:
            def __call__(self, *args, **kwargs):
                raise RuntimeError("HTTP client is not configured.")

        return _HttpClient()

    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        if not self.api_key:
            return {"status": "disabled", "message": "VirusTotal API key not configured."}

        try:
            response = self.http_client("https://www.virustotal.com/api/v3/files/" + file_hash, headers={"x-apikey": self.api_key})
            if hasattr(response, "read"):
                payload = json.loads(response.read().decode("utf-8"))
            else:
                payload = response
        except Exception as exc:  # pragma: no cover - external call boundary
            return {"status": "error", "message": str(exc)}

        stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious_count = int(stats.get("malicious", 0))
        suspicious_count = int(stats.get("suspicious", 0))

        if malicious_count > 0 or suspicious_count > 0:
            return {
                "status": "detected",
                "malicious_count": malicious_count,
                "suspicious_count": suspicious_count,
                "message": "Hash is present in VirusTotal results.",
            }

        return {
            "status": "clean",
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "message": "Hash not flagged by VirusTotal.",
        }
