"""Coordinates scan views with the existing backend scanner."""

from antivirus.model.scan_result import ScanResult
from antivirus.model.scan_report import ScanReport
from antivirus.services.scanner import Scanner
from antivirus.repository.scan_repository import ScanRepository
from pathlib import Path
from time import monotonic


class ScanController:
    def __init__(
        self, scanner: Scanner | None = None, repository: ScanRepository | None = None
    ) -> None:
        self.scanner = scanner or Scanner()
        self.repository = repository or ScanRepository()

    def scan_file(self, file_path: str) -> ScanResult:
        started = monotonic()
        result = self.scanner.scan_file(file_path)
        self._record_report(
            self._as_report(result),
            file_path,
            "file",
            monotonic() - started,
        )
        return result

    def scan_directory(
        self, directory_path: str, progress_callback=None, cancel_check=None
    ) -> ScanReport:
        started = monotonic()
        report = self.scanner.scan_directory(
            directory_path, progress_callback, cancel_check
        )
        self._record_report(
            report,
            directory_path,
            "folder",
            monotonic() - started,
            "cancelled" if cancel_check and cancel_check() else None,
        )
        return report

    def quick_scan(self, progress_callback=None, cancel_check=None) -> ScanReport:
        started = monotonic()
        home = Path.home()
        preferred = [home / name for name in ("Desktop", "Downloads", "Documents")]
        roots = [path for path in preferred if path.is_dir()]
        if not roots:
            roots = [home]
        report = self.scanner.scan_directories(
            [str(path) for path in roots], progress_callback, cancel_check
        )
        self._record_report(
            report,
            ", ".join(str(path) for path in roots),
            "quick",
            monotonic() - started,
            "cancelled" if cancel_check and cancel_check() else None,
        )
        return report

    @staticmethod
    def _as_report(result: ScanResult) -> ScanReport:
        report = ScanReport()
        report.add_result(result)
        return report

    def _record_report(
        self,
        report: ScanReport,
        target: str,
        scan_type: str,
        duration: float,
        status_override: str | None = None,
    ) -> None:
        if status_override:
            status = status_override
        elif report.total_files and report.error_files == report.total_files:
            status = "error"
        else:
            status = "detected" if report.threat_files else "clean"
        threats = [
            {
                "name": threat.name,
                "category": threat.category,
                "severity": threat.severity,
            }
            for result in report.results
            for threat in result.threats
        ]
        self.repository.record_scan(
            report.total_files,
            report.threats_found,
            report.clean_files,
            report.error_files,
            status,
            target=target,
            scan_type=scan_type,
            duration=duration,
            threats=threats,
        )
