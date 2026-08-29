from __future__ import annotations

from pathlib import Path

from antivirus.model.scan_result import ScanResult
from antivirus.model.scan_status import ScanStatus
from antivirus.model.threat import Threat
from antivirus.services.clamav_service import ClamAVService
from antivirus.services.hash_service import HashService
from antivirus.services.yara_service import YaraService
from antivirus.repository.threat_repository import ThreatRepository


class DetectionEngine:
    """Combines hash, YARA, and ClamAV into a single result model."""

    def __init__(
        self,
        hash_service: HashService | None = None,
        yara_service: YaraService | None = None,
        clamav_service: ClamAVService | None = None,
        threat_repository: ThreatRepository | None = None,
        hash_enabled: bool = True,
        yara_enabled: bool = True,
        clamav_enabled: bool = True,
    ):
        self.hash_service = hash_service or HashService()
        self.yara_service = yara_service or YaraService(rule_dir="antivirus/detection/rules")
        self.clamav_service = clamav_service or ClamAVService()
        self.threat_repository = threat_repository or ThreatRepository("antivirus_data/threats.db")
        self.hash_enabled = hash_enabled
        self.yara_enabled = yara_enabled
        self.clamav_enabled = clamav_enabled

    def analyze_file(self, file_path: str) -> ScanResult:
        candidate = Path(file_path)
        if not candidate.exists():
            return ScanResult(
                file_path=file_path,
                status=ScanStatus.ERROR,
                error_message=f"File not found: {file_path}",
            )

        result = ScanResult(file_path=file_path, status=ScanStatus.CLEAN)
        try:
            result.sha256 = self.hash_service.calculate_sha256(str(candidate))
        except Exception as exc:  # pragma: no cover - defensive boundary
            result.status = ScanStatus.ERROR
            result.error_message = str(exc)
            return result

        try:
            existing = self.threat_repository.find_by_hash(result.sha256) if self.hash_enabled else None
        except Exception as exc:
            existing = None
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
            yara_matches = self.yara_service.scan_file_details(str(candidate)) if self.yara_enabled else []
        except Exception as exc:
            yara_matches = []
            self._add_error(result, f"YARA scan failed: {exc}")
        for match in yara_matches:
            rule_name = match["name"]
            threat_name = self._rule_name_to_threat(rule_name)
            result.status = ScanStatus.DETECTED
            self._add_method(result, "yara")
            self._add_threat(result, Threat(
                name=threat_name,
                category=match.get("category") or self._rule_name_to_category(rule_name),
                severity=(match.get("severity") or "High").title(),
                description="Educational signature match",
                source="yara",
                hash_value=result.sha256,
            ))

        try:
            clamav_result = self.clamav_service.scan_file(str(candidate)) if self.clamav_enabled else {"status": "clean"}
        except Exception as exc:
            clamav_result = {"status": "error", "message": str(exc)}
        if clamav_result.get("status") == "error":
            self._add_error(result, f"ClamAV scan failed: {clamav_result.get('message', 'unknown error')}")
        if clamav_result.get("status") == "detected":
            result.status = ScanStatus.DETECTED
            self._add_method(result, "clamav")
            for threat in clamav_result.get("threats", []):
                self._add_threat(result, Threat(
                        name=threat.get("name", "ClamAV.Detected"),
                        category=threat.get("category", "ClamAV"),
                        severity="High",
                        description="Detected by ClamAV",
                        source="clamav",
                        hash_value=result.sha256,
                    ))

        if result.status == ScanStatus.CLEAN and not result.threats:
            result.status = ScanStatus.CLEAN

        return result

    @staticmethod
    def _add_method(result: ScanResult, method: str) -> None:
        if method not in result.detection_methods:
            result.detection_methods.append(method)

    @staticmethod
    def _add_threat(result: ScanResult, threat: Threat) -> None:
        if not any((item.name, item.source) == (threat.name, threat.source) for item in result.threats):
            result.threats.append(threat)

    @staticmethod
    def _add_error(result: ScanResult, message: str) -> None:
        result.error_message = f"{result.error_message}; {message}" if result.error_message else message

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
