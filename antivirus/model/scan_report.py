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
    skipped_files: int = 0
    cancelled: bool = False
    warnings: list[str] = field(default_factory=list)
    started_at: str = ""
    completed_at: str = ""

    @property
    def outcome(self) -> str:
        if self.cancelled:
            return "cancelled"
        if self.threat_files:
            return "detected"
        if self.error_files or self.skipped_files or self.warnings:
            return "partial" if self.clean_files else "error"
        return "clean" if self.total_files else "empty"

    @property
    def threats_found(self) -> int:
        return sum(len(result.threats) for result in self.results)

    @property
    def incomplete_files(self) -> int:
        return (
            self.error_files
            + self.skipped_files
            + sum(
                1
                for result in self.results
                if result.is_detected and result.error_message
            )
        )

    def add_result(self, result: ScanResult) -> None:
        self.results.append(result)
        self.warnings.extend(result.warnings)
        if result.started_at and (
            not self.started_at or result.started_at < self.started_at
        ):
            self.started_at = result.started_at
        if result.completed_at and (
            not self.completed_at or result.completed_at > self.completed_at
        ):
            self.completed_at = result.completed_at
        self.duration += result.scan_duration
        self.total_files += 1
        if result.is_detected:
            self.threat_files += 1
            if result.error_message:
                self.warnings.append(
                    f"A suspicious file also had incomplete checks: {result.file_path}"
                )
        elif result.status.value == "error":
            self.error_files += 1
        elif result.status.value == "skipped":
            self.skipped_files += 1
        elif result.is_clean:
            self.clean_files += 1
        else:
            self.error_files += 1
