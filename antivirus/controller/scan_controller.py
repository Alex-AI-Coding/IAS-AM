"""Coordinates scan views with the existing backend scanner."""

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from time import monotonic

from antivirus.model.scan_result import ScanResult
from antivirus.model.scan_report import ScanReport
from antivirus.services.report_formatter import ReportFormatter
from antivirus.services.scanner import Scanner
from antivirus.services.quarantine_service import QuarantineService
from antivirus.repository.scan_repository import ScanRepository
from antivirus.utils.logging import get_logger

logger = get_logger(__name__)


def _quick_scan_roots(home: Path) -> list[Path]:
    """Resolve Windows redirected known folders before using profile defaults."""
    folders = {}
    downloads_key = "{374DE290-123F-4565-9164-39C4925E467B}"
    if os.name == "nt":
        try:
            import winreg

            key_path = (
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
            )
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                for name in ("Desktop", "Personal", downloads_key):
                    try:
                        value, _kind = winreg.QueryValueEx(key, name)
                    except OSError:
                        continue
                    folders[name] = Path(os.path.expandvars(value)).expanduser()
        except (ImportError, OSError):
            pass

    preferred = [
        folders.get("Desktop", home / "Desktop"),
        folders.get(downloads_key, home / "Downloads"),
        folders.get("Personal", home / "Documents"),
    ]
    roots = []
    seen = set()
    for path in preferred:
        try:
            if path.is_dir():
                identity = os.path.normcase(str(path.resolve()))
                if identity not in seen:
                    roots.append(path)
                    seen.add(identity)
        except (OSError, RuntimeError):
            # An unavailable known folder is reported by the scan when applicable.
            continue
    return roots


class ScanController:
    def __init__(
        self,
        scanner: Scanner | None = None,
        repository: ScanRepository | None = None,
        quarantine_service: QuarantineService | None = None,
        auto_quarantine_high_risk: bool = True,
    ) -> None:
        self.scanner = scanner or Scanner()
        self.repository = repository or ScanRepository()
        self.quarantine_service = quarantine_service
        self.auto_quarantine_high_risk = auto_quarantine_high_risk

    def scan_file(self, file_path: str) -> ScanResult:
        started = monotonic()
        result = self.scanner.scan_file(file_path)
        self._auto_quarantine_high_risk(self._as_report(result))
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
        self._auto_quarantine_high_risk(report)
        self._record_report(
            report,
            directory_path,
            "folder",
            monotonic() - started,
            "cancelled" if report.cancelled else None,
        )
        return report

    def quick_scan(self, progress_callback=None, cancel_check=None) -> ScanReport:
        started = monotonic()
        home = Path.home()
        roots = _quick_scan_roots(home)
        if not roots:
            report = ScanReport(
                warnings=[
                    "No Desktop, Downloads, or Documents folders were found. Choose a folder manually."
                ]
            )
            self._record_report(report, str(home), "quick", monotonic() - started)
            return report
        report = self.scanner.scan_directories(
            [str(path) for path in roots], progress_callback, cancel_check
        )
        self._auto_quarantine_high_risk(report)
        self._record_report(
            report,
            ", ".join(str(path) for path in roots),
            "quick",
            monotonic() - started,
            "cancelled" if report.cancelled else None,
        )
        return report

    def scan_drives(
        self, roots: list[str], progress_callback=None, cancel_check=None
    ) -> ScanReport:
        """Scan only the explicitly chosen roots, sharing traversal and size limits."""
        started = monotonic()
        report = self.scanner.scan_directories(roots, progress_callback, cancel_check)
        self._auto_quarantine_high_risk(report)
        self._record_report(
            report,
            ", ".join(roots),
            "drives",
            monotonic() - started,
            "cancelled" if report.cancelled else None,
        )
        return report

    @staticmethod
    def _as_report(result: ScanResult) -> ScanReport:
        report = ScanReport()
        report.add_result(result)
        return report

    def _auto_quarantine_high_risk(self, report: ScanReport) -> None:
        """Move confirmed High detections to the encrypted vault.

        A failed isolation never changes the detection result. The report states
        whether the original was removed, retained, or could not be held.
        """
        if not self.auto_quarantine_high_risk:
            return
        candidates = [result for result in report.results if result.is_high_risk]
        if not candidates:
            return
        try:
            if self.quarantine_service is None:
                self.quarantine_service = QuarantineService()
        except Exception as exc:
            for result in candidates:
                result.quarantine_state = "failed"
                result.quarantine_message = (
                    f"Automatic quarantine could not start; the original file remains: {exc}"
                )
                result.warnings.append(result.quarantine_message)
                report.warnings.append(result.quarantine_message)
            logger.exception("Automatic quarantine vault could not be initialized")
            return
        for result in candidates:
            try:
                item = self.quarantine_service.quarantine(result)
            except Exception as exc:
                result.quarantine_state = "failed"
                result.quarantine_message = (
                    f"Automatic quarantine failed; the original file remains: {exc}"
                )
                result.warnings.append(result.quarantine_message)
                report.warnings.append(result.quarantine_message)
                logger.exception("Automatic quarantine failed for %s", result.file_path)
                continue
            if item.state == "active":
                result.quarantine_state = "quarantined"
                result.quarantine_message = (
                    "Automatically quarantined in the encrypted local vault."
                )
            else:
                result.quarantine_state = "copy_retained"
                result.quarantine_message = (
                    "An encrypted quarantine copy was created, but the original file "
                    "could not be removed. Retry isolation from Quarantine."
                )
            result.warnings.append(result.quarantine_message)

    def _record_report(
        self,
        report: ScanReport,
        target: str,
        scan_type: str,
        duration: float,
        status_override: str | None = None,
    ) -> None:
        status = status_override or report.outcome
        report.duration = duration
        completed = datetime.now(timezone.utc)
        report.started_at = (
            report.started_at or (completed - timedelta(seconds=duration)).isoformat()
        )
        report.completed_at = report.completed_at or completed.isoformat()
        threats = [
            {
                "name": threat.name,
                "category": threat.category,
                "severity": threat.severity,
            }
            for result in report.results
            for threat in result.threats
        ]
        try:
            self.repository.record_scan(
                report.total_files,
                report.threats_found,
                report.clean_files,
                report.error_files,
                status,
                started_at=report.started_at,
                completed_at=report.completed_at,
                target=target,
                scan_type=scan_type,
                duration=duration,
                threats=threats,
                skipped_files=report.skipped_files,
                warnings=report.warnings,
                report=ReportFormatter.to_dict(report),
            )
        except Exception:
            logger.exception("Could not persist scan history")
            report.warnings.append(
                "Results are available, but history could not be saved. Export this report."
            )
            if scan_type == "file" and report.results:
                report.results[0].warnings.extend(report.warnings)
