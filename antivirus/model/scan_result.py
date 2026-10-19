from dataclasses import dataclass, field
from typing import List, Optional

from antivirus.model.scan_status import ScanStatus
from antivirus.model.threat import SEVERITY_RANKS, Threat


@dataclass
class ScanResult:
    """A result for a single scanned file."""

    file_path: str
    status: ScanStatus = ScanStatus.CLEAN
    threats: List[Threat] = field(default_factory=list)
    sha256: Optional[str] = None
    scan_duration: float = 0.0
    detection_methods: List[str] = field(default_factory=list)
    error_message: Optional[str] = None
    engine_results: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    started_at: str = ""
    completed_at: str = ""
    quarantine_state: str = ""
    quarantine_message: str = ""

    @property
    def checked_engines(self) -> list[str]:
        return [
            name
            for name, state in self.engine_results.items()
            if state in ("clean", "detected")
        ]

    @property
    def is_clean(self) -> bool:
        return (
            self.status == ScanStatus.CLEAN
            and not self.threats
            and not self.error_message
        )

    @property
    def is_detected(self) -> bool:
        return self.status == ScanStatus.DETECTED or bool(self.threats)

    @property
    def is_high_risk(self) -> bool:
        """High findings are confirmed enough for automatic isolation."""
        return self.is_detected and any(
            threat.severity == "High"
            for threat in self.threats
        )

    @property
    def is_suspicious(self) -> bool:
        """Low and Medium findings need review but are not automatically isolated."""
        return self.is_detected and not self.is_high_risk

    @property
    def severity(self) -> str:
        """The single, highest severity for this file's combined findings."""
        if not self.threats:
            return ""
        return max(
            (threat.severity for threat in self.threats),
            key=lambda label: SEVERITY_RANKS.get(label, SEVERITY_RANKS["Medium"]),
        )
