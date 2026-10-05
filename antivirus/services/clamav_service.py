from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional


class ClamAVService:
    """Thin isolation layer around ClamAV scanning logic.

    This project is educational and offline-first, so missing ClamAV should not crash the
    application. The service exposes a safe dictionary result format instead of leaking
    ClamAV-specific objects to the rest of the backend.
    """

    def __init__(self, client: Optional[Any] = None):
        self.client = client if client is not None else self._create_default_client()

    @staticmethod
    def _create_default_client() -> Optional[Any]:
        """Connect to a local clamd daemon when pyclamd and clamd are available."""
        try:
            import pyclamd

            client = pyclamd.ClamdNetworkSocket(host="127.0.0.1", port=3310, timeout=5)
            client.ping()
            return client
        except Exception:
            return None

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        path = Path(file_path)
        if not path.exists():
            return {
                "status": "error",
                "message": f"File not found: {file_path}",
                "threats": [],
            }

        if self.client is None:
            return {
                "status": "unavailable",
                "message": "ClamAV client is not available.",
                "threats": [],
            }

        try:
            scan_method = getattr(self.client, "scan_file", None) or getattr(
                self.client, "scan", None
            )
            if scan_method is None:
                raise RuntimeError("ClamAV client does not provide a file scan method.")
            raw = scan_method(str(path))
        except Exception as exc:  # pragma: no cover - defensive boundary
            return {
                "status": "error",
                "message": str(exc),
                "threats": [],
            }

        if raw is None:
            return {"status": "clean", "message": "OK", "threats": []}
        if not isinstance(raw, dict):
            return {
                "status": "error",
                "message": "Unexpected ClamAV response.",
                "threats": [],
            }

        daemon_errors = [
            str(value[1]) if len(value) > 1 else "Daemon error"
            for value in raw.values()
            if isinstance(value, tuple) and value and value[0] == "ERROR"
        ]
        if daemon_errors or raw.get("Error"):
            return {
                "status": "error",
                "message": "; ".join(daemon_errors) or str(raw["Error"]),
                "threats": [],
            }

        infected = raw.get("Infected")
        result_text = str(raw.get("Result", "")).upper()
        daemon_matches = [
            value
            for value in raw.values()
            if isinstance(value, tuple) and value and value[0] == "FOUND"
        ]
        if (
            infected is True
            or infected in ("FOUND", "YES")
            or "FOUND" in result_text
            or "INFECTED" in result_text
            or daemon_matches
        ):
            name = (
                str(daemon_matches[0][1])
                if daemon_matches
                else raw.get("Result", "ClamAV.Detected")
            )
            return {
                "status": "detected",
                "message": raw.get("Result", "ClamAV detected a threat."),
                "threats": [
                    {
                        "name": name,
                        "category": "ClamAV",
                        "source": "ClamAV",
                    }
                ],
            }

        if raw.get("Infected") is False and raw.get("Result") == "OK":
            return {"status": "clean", "message": "OK", "threats": []}
        if raw and all(
            isinstance(value, tuple) and value and value[0] == "OK"
            for value in raw.values()
        ):
            return {"status": "clean", "message": "OK", "threats": []}
        return {
            "status": "error",
            "message": "Unrecognized ClamAV result.",
            "threats": [],
        }
