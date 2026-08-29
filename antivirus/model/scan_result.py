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

    @property
    def is_clean(self) -> bool:
        return self.status == ScanStatus.CLEAN and not self.threats

    @property
    def is_detected(self) -> bool:
        return self.status == ScanStatus.DETECTED or bool(self.threats)
