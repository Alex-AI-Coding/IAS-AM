"""Coordinates scan views with the existing backend scanner."""

from antivirus.model.scan_result import ScanResult
from antivirus.model.scan_report import ScanReport
from antivirus.services.scanner import Scanner
from antivirus.repository.scan_repository import ScanRepository
from pathlib import Path


class ScanController:
    def __init__(self, scanner: Scanner | None = None, repository: ScanRepository | None = None) -> None:
        self.scanner = scanner or Scanner()
        self.repository = repository or ScanRepository()

    def scan_file(self, file_path: str) -> ScanResult:
        result = self.scanner.scan_file(file_path)
        self.repository.record_scan(1, len(result.threats), int(result.is_clean), int(result.status.value == "error"), result.status.value)
        return result

    def scan_directory(self, directory_path: str) -> ScanReport:
        report = self.scanner.scan_directory(directory_path)
        self.repository.record_scan(report.total_files, report.threats_found, report.clean_files, report.error_files, "detected" if report.threat_files else "clean")
        return report

    def quick_scan(self, progress_callback=None, cancel_check=None) -> ScanReport:
        return self.scanner.scan_directory(str(Path.home()), progress_callback, cancel_check)
