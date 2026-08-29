from dataclasses import dataclass, field
from typing import List

from antivirus.model.scan_result import ScanResult


@dataclass
class ScanReport:
    """Aggregate result for a directory or batch scan."""

    total_files: int = 0
    clean_files: int = 0
    threat_files: int = 0
    error_files: int = 0
    results: List[ScanResult] = field(default_factory=list)
    duration: float = 0.0

    @property
    def threats_found(self) -> int:
        return sum(len(result.threats) for result in self.results)

    def add_result(self, result: ScanResult) -> None:
        self.results.append(result)
        self.total_files += 1
        if result.is_detected:
            self.threat_files += 1
        elif result.status.value == "error":
            self.error_files += 1
        else:
            self.clean_files += 1
