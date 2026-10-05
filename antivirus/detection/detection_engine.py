from __future__ import annotations

from pathlib import Path
import stat
import sqlite3
from time import monotonic
from datetime import datetime, timezone

from antivirus.model.scan_result import ScanResult
from antivirus.model.scan_status import ScanStatus
from antivirus.model.threat import Threat
from antivirus.services.clamav_service import ClamAVService
from antivirus.services.hash_service import HashService
from antivirus.services.yara_service import YaraService
from antivirus.services.virustotal_service import VirusTotalService
from antivirus.repository.threat_repository import ThreatRepository
from antivirus.config.settings import (
    RULE_DIR,
    THREAT_DB_PATH,
    MAX_FILE_BYTES,
    load_environment,
)


class DetectionEngine:
    """Combines hash, YARA, and ClamAV into a single result model."""

    def __init__(
        self,
        hash_service: HashService | None = None,
        yara_service: YaraService | None = None,
        clamav_service: ClamAVService | None = None,
        virustotal_service: VirusTotalService | None = None,
        threat_repository: ThreatRepository | None = None,
        hash_enabled: bool = True,
        yara_enabled: bool = True,
        clamav_enabled: bool | None = None,
        virustotal_enabled: bool = False,
        max_file_bytes: int = MAX_FILE_BYTES,
    ):
        load_environment()
        self.hash_service = hash_service or HashService()
        self.yara_service = yara_service or YaraService(rule_dir=str(RULE_DIR))
        self.clamav_service = clamav_service or ClamAVService()
        self.virustotal_service = virustotal_service or VirusTotalService()
        self.threat_repository = threat_repository or ThreatRepository(
            str(THREAT_DB_PATH)
        )
        self.hash_enabled = hash_enabled
        self.yara_enabled = yara_enabled
        self.clamav_enabled = (
            getattr(self.clamav_service, "client", None) is not None
            if clamav_enabled is None
            else clamav_enabled
        )
        self.virustotal_enabled = virustotal_enabled
        if max_file_bytes <= 0:
            raise ValueError("max_file_bytes must be positive")
        self.max_file_bytes = max_file_bytes

    def analyze_file(self, file_path: str) -> ScanResult:
        started = monotonic()
        started_at = datetime.now(timezone.utc).isoformat()
        result = self._analyze_file(file_path)
        result.scan_duration = monotonic() - started
        result.started_at = started_at
        result.completed_at = datetime.now(timezone.utc).isoformat()
        return result

    def _analyze_file(self, file_path: str) -> ScanResult:
        candidate = Path(file_path)
        try:
            original_stat = candidate.lstat()
        except FileNotFoundError:
            return ScanResult(
                file_path,
                ScanStatus.ERROR,
                error_message=f"File not found: {file_path}",
            )
        except (OSError, ValueError) as exc:
            return ScanResult(
                file_path=file_path,
                status=ScanStatus.ERROR,
                error_message=f"File cannot be accessed: {exc}",
            )
        if not stat.S_ISREG(original_stat.st_mode):
            return ScanResult(
                file_path=file_path,
                status=ScanStatus.SKIPPED,
                error_message="Only regular files are scanned; links and special files are skipped.",
            )
        if original_stat.st_size > self.max_file_bytes:
            return ScanResult(
                file_path=file_path,
                status=ScanStatus.SKIPPED,
                error_message=f"File exceeds the {self.max_file_bytes // (1024 * 1024)} MiB scan limit.",
            )

        result = ScanResult(file_path=file_path, status=ScanStatus.CLEAN)
        result.engine_results = {
            name: "disabled" for name in ("hash", "yara", "clamav", "virustotal")
        }
        try:
            result.sha256 = self.hash_service.calculate_sha256(str(candidate))
        except Exception as exc:  # pragma: no cover - defensive boundary
            result.status = ScanStatus.ERROR
            result.error_message = str(exc)
            return result

        try:
            existing = (
                self.threat_repository.find_by_hash(result.sha256)
                if self.hash_enabled
                else None
            )
            if self.hash_enabled:
                result.engine_results["hash"] = "detected" if existing else "clean"
        except Exception as exc:
            existing = None
            result.engine_results["hash"] = "error"
            self._add_error(result, f"Hash lookup failed: {exc}")
        if existing:
            result.status = ScanStatus.DETECTED
            result.threats.append(
                Threat(
                    name=existing["name"],
                    category=existing["category"],
                    severity=existing["severity"],
                    description=existing["description"],
                    source="hash",
                    hash_value=result.sha256,
                )
            )
            self._add_method(result, "hash")

        try:
            yara_matches = (
                self.yara_service.scan_file_details(str(candidate))
                if self.yara_enabled
                else []
            )
            if self.yara_enabled:
                result.engine_results["yara"] = "detected" if yara_matches else "clean"
        except Exception as exc:
            yara_matches = []
            result.engine_results["yara"] = "error"
            self._add_error(result, f"YARA scan failed: {exc}")
        for match in yara_matches:
            rule_name = match["name"]
            threat_name = self._rule_name_to_threat(rule_name)
            result.status = ScanStatus.DETECTED
            self._add_method(result, "yara")
            self._add_threat(
                result,
                Threat(
                    name=threat_name,
                    category=match.get("category")
                    or self._rule_name_to_category(rule_name),
                    severity=(match.get("severity") or "High").title(),
                    description="Educational signature match",
                    source="yara",
                    hash_value=result.sha256,
                ),
            )

        try:
            clamav_result = (
                self.clamav_service.scan_file(str(candidate))
                if self.clamav_enabled
                else {"status": "clean"}
            )
        except Exception as exc:
            clamav_result = {"status": "error", "message": str(exc)}
        if self.clamav_enabled:
            result.engine_results["clamav"] = clamav_result.get("status", "error")
        if self.clamav_enabled and clamav_result.get("status") not in (
            "clean",
            "detected",
        ):
            self._add_error(
                result,
                f"ClamAV scan failed: {clamav_result.get('message', 'unknown error')}",
            )
        if clamav_result.get("status") == "detected":
            result.status = ScanStatus.DETECTED
            self._add_method(result, "clamav")
            for threat in clamav_result.get("threats", []):
                self._add_threat(
                    result,
                    Threat(
                        name=threat.get("name", "ClamAV.Detected"),
                        category=threat.get("category", "ClamAV"),
                        severity="High",
                        description="Detected by ClamAV",
                        source="clamav",
                        hash_value=result.sha256,
                    ),
                )

        if self.virustotal_enabled:
            try:
                online_result = self.virustotal_service.lookup_hash(result.sha256)
            except Exception as exc:
                online_result = {"status": "error", "message": str(exc)}
            result.engine_results["virustotal"] = online_result.get("status", "error")
            if online_result.get("status") not in ("clean", "detected", "unknown"):
                self._add_error(
                    result,
                    f"VirusTotal lookup failed: {online_result.get('message', 'unknown error')}",
                )
            elif online_result.get("status") == "detected":
                malicious = int(online_result.get("malicious_count", 0))
                suspicious = int(online_result.get("suspicious_count", 0))
                result.status = ScanStatus.DETECTED
                self._add_method(result, "virustotal")
                self._add_threat(
                    result,
                    Threat(
                        name="VirusTotal.Consensus",
                        category="Online intelligence",
                        severity="High" if malicious else "Medium",
                        description=(
                            f"Flagged by {malicious} malicious and {suspicious} suspicious engines"
                        ),
                        source="virustotal",
                        hash_value=result.sha256,
                        metadata={
                            "malicious_count": malicious,
                            "suspicious_count": suspicious,
                        },
                    ),
                )

        try:
            current_stat = candidate.lstat()
            if (
                original_stat.st_ino,
                original_stat.st_dev,
                original_stat.st_size,
                original_stat.st_mtime_ns,
            ) != (
                current_stat.st_ino,
                current_stat.st_dev,
                current_stat.st_size,
                current_stat.st_mtime_ns,
            ):
                self._add_error(
                    result,
                    "File changed during scanning; rescan after writing finishes.",
                )
        except OSError:
            self._add_error(result, "File disappeared during scanning.")
        if result.error_message and not result.is_detected:
            result.status = ScanStatus.ERROR
        elif not result.checked_engines and not result.is_detected:
            result.status = ScanStatus.SKIPPED
            result.error_message = "No detection engine completed a check. Enable a local engine in Settings."

        return result

    def get_engine_states(self) -> dict[str, dict[str, object]]:
        """Return user-facing engine state without performing a scan."""

        hash_state: dict[str, object] = {
            "enabled": self.hash_enabled,
            "available": True,
        }
        try:
            hash_state["signature_count"] = (
                self.threat_repository.count()
                if hasattr(self.threat_repository, "count")
                else None
            )
        except (OSError, sqlite3.Error):
            hash_state.update(
                available=False,
                signature_count=None,
                error_message="The local hash catalogue cannot be read.",
            )
        return {
            "hash": hash_state,
            "yara": {
                "enabled": self.yara_enabled,
                "available": getattr(self.yara_service, "_compiler", None) is not None,
            },
            "clamav": {
                "enabled": self.clamav_enabled,
                "available": getattr(self.clamav_service, "client", None) is not None,
            },
            "virustotal": {
                "enabled": self.virustotal_enabled,
                "available": bool(getattr(self.virustotal_service, "api_key", None)),
            },
        }

    @staticmethod
    def _add_method(result: ScanResult, method: str) -> None:
        if method not in result.detection_methods:
            result.detection_methods.append(method)

    @staticmethod
    def _add_threat(result: ScanResult, threat: Threat) -> None:
        if not any(
            (item.name, item.source) == (threat.name, threat.source)
            for item in result.threats
        ):
            result.threats.append(threat)

    @staticmethod
    def _add_error(result: ScanResult, message: str) -> None:
        result.error_message = (
            f"{result.error_message}; {message}" if result.error_message else message
        )

    @staticmethod
    def _rule_name_to_threat(rule_name: str) -> str:
        mapping = {
            "EducationalRansomware": "Educational.Ransomware.Test",
            "EducationalTrojan": "Educational.Trojan.Test",
            "EducationalWorm": "Educational.Worm.Test",
            "EducationalSpyware": "Educational.Spyware.Test",
            "RansomwareSignature_Encryption": "Ransomware.Encryption",
            "RansomwareSignature_FileMarking": "Ransomware.FileMarking",
            "TrojanSignature_Backdoor": "Trojan.Backdoor",
            "TrojanSignature_PrivilegeEscalation": "Trojan.PrivilegeEscalation",
            "WormSignature_NetworkReplication": "Worm.NetworkReplication",
            "WormSignature_FileReplication": "Worm.FileReplication",
            "WormSignature_MassEmailer": "Worm.MassEmailer",
            "SpywareSignature_KeyLogger": "Spyware.KeyLogger",
            "SpywareSignature_ScreenCapture": "Spyware.ScreenCapture",
            "SpywareSignature_DataThief": "Spyware.DataThief",
            "SpywareSignature_RemoteAccess": "Spyware.RemoteAccess",
        }
        return mapping.get(rule_name, rule_name)

    @staticmethod
    def _rule_name_to_category(rule_name: str) -> str:
        mapping = {
            "EducationalRansomware": "Ransomware",
            "EducationalTrojan": "Trojan",
            "EducationalWorm": "Worm",
            "EducationalSpyware": "Spyware",
            "RansomwareSignature_Encryption": "Ransomware",
            "RansomwareSignature_FileMarking": "Ransomware",
            "TrojanSignature_Backdoor": "Trojan",
            "TrojanSignature_PrivilegeEscalation": "Trojan",
            "WormSignature_NetworkReplication": "Worm",
            "WormSignature_FileReplication": "Worm",
            "WormSignature_MassEmailer": "Worm",
            "SpywareSignature_KeyLogger": "Spyware",
            "SpywareSignature_ScreenCapture": "Spyware",
            "SpywareSignature_DataThief": "Spyware",
            "SpywareSignature_RemoteAccess": "Spyware",
        }
        return mapping.get(rule_name, "Unknown")
