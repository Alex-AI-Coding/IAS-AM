from dataclasses import dataclass, field
from typing import List, Optional

from antivirus.model.scan_status import ScanStatus
from antivirus.model.threat import Threat


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
