"""Opt-in hash reputation. Never uploads file contents or treats unknown as clean."""

from __future__ import annotations

import json
import os
import re
from threading import Lock
from time import monotonic
from typing import Any


class VirusTotalService:
    def __init__(self, api_key=None, http_client=None, min_interval=15.0):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self.http_client = http_client or self._default_client()
        self.min_interval = min_interval
        self._last_request = float("-inf")
        self._cache: dict[str, tuple[float, dict]] = {}
        self._lock = Lock()

    @staticmethod
    def _default_client():
        import requests

        return requests.get

    def lookup_hash(self, file_hash: str) -> dict[str, Any]:
        if not self.api_key:
            return {
                "status": "disabled",
                "message": "VirusTotal API key not configured.",
            }
        if not isinstance(file_hash, str) or not re.fullmatch(
            r"[a-fA-F0-9]{64}", file_hash
        ):
            return {"status": "error", "message": "A valid SHA-256 hash is required."}
        file_hash = file_hash.lower()
        with self._lock:
            now = monotonic()
            cached = self._cache.get(file_hash)
            if cached and now - cached[0] < 300:
                return dict(cached[1])
            if now - self._last_request < self.min_interval:
                return {
                    "status": "error",
                    "message": (
                        "VirusTotal rate limit: wait before another online lookup, "
                        "or disable it for bulk scans."
                    ),
                }
            self._last_request = now
            try:
                response = self.http_client(
                    "https://www.virustotal.com/api/v3/files/" + file_hash,
                    headers={"x-apikey": self.api_key},
                    timeout=8,
                    allow_redirects=False,
                )
                status = getattr(response, "status_code", 200)
                if status == 404:
                    return {
                        "status": "unknown",
                        "message": "Hash is not known to VirusTotal; no safety verdict is available.",
                    }
                if status == 429:
                    return {
                        "status": "error",
                        "message": "VirusTotal quota reached. Try later or disable online lookup.",
                    }
                if status != 200:
                    return {
                        "status": "error",
                        "message": f"VirusTotal returned HTTP {status}.",
                    }
                if hasattr(response, "json"):
                    payload = response.json()
                elif hasattr(response, "read"):
                    payload = json.loads(response.read().decode("utf-8"))
                else:
                    payload = response
                stats = payload["data"]["attributes"]["last_analysis_stats"]
                if not isinstance(stats, dict) or not stats:
                    raise ValueError("Missing analysis statistics")
                if any(type(value) is not int or value < 0 for value in stats.values()):
                    raise ValueError("Invalid analysis statistics")
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                observed = sum(
                    stats.get(k, 0)
                    for k in ("malicious", "suspicious", "undetected", "harmless")
                )
                verdict = (
                    "detected"
                    if malicious or suspicious
                    else ("clean" if observed else "unknown")
                )
                result = {
                    "status": verdict,
                    "malicious_count": malicious,
                    "suspicious_count": suspicious,
                    "message": "Reputation check completed; a lack of detections does not prove safety.",
                }
                if len(self._cache) >= 256:
                    self._cache.clear()
                self._cache[file_hash] = (monotonic(), result)
                return dict(result)
            except Exception:
                # Never put credentials, request headers or remote response bodies in a report.
                return {
                    "status": "error",
                    "message": "VirusTotal could not provide valid analysis. Check connectivity and configuration.",
                }
            finally:
                if "response" in locals() and hasattr(response, "close"):
                    response.close()
