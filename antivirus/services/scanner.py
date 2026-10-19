"""Bounded, read-only traversal shared by desktop, API and CLI scans."""

from __future__ import annotations

import errno
import os
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic
from typing import Callable

from antivirus.config.settings import MAX_SCAN_FILES, QUARANTINE_DIR
from antivirus.detection.detection_engine import DetectionEngine
from antivirus.model.scan_report import ScanReport
from antivirus.model.scan_result import ScanResult
from antivirus.model.scan_status import ScanStatus


def _expected_access_message(message: str) -> bool:
    normalized = message.casefold()
    return any(
        marker in normalized
        for marker in (
            "file not found",
            "file cannot be accessed",
            "permission denied",
            "access is denied",
            "winerror 5",
            "winerror 2",
            "errno 13",
            "errno 2",
            "no such file",
            "system cannot find the file",
            "cannot open file",
            "being used by another process",
            "resource busy",
        )
    )


class Scanner:
    def __init__(
        self,
        detection_engine: DetectionEngine | None = None,
        max_files=MAX_SCAN_FILES,
        excluded_roots=None,
    ):
        self.detection_engine = detection_engine or DetectionEngine()
        if max_files is not None and max_files <= 0:
            raise ValueError("max_files must be positive")
        self.max_files = max_files
        self.excluded_roots = tuple(
            Path(path).absolute()
            for path in (
                excluded_roots if excluded_roots is not None else (QUARANTINE_DIR,)
            )
        )

    def _is_excluded(self, path):
        target = Path(os.path.abspath(path))
        for root in self.excluded_roots:
            if target.is_relative_to(root):
                return True
            try:
                if target.resolve().is_relative_to(root.resolve()):
                    return True
            except (OSError, RuntimeError):
                # The detection engine reports unreadable or looping linked paths.
                continue
        return False

    def scan_file(
        self, file_path: str, *, inaccessible_as_skipped: bool = False
    ) -> ScanResult:
        if self._is_excluded(file_path):
            return ScanResult(
                file_path,
                ScanStatus.SKIPPED,
                error_message="The protected quarantine area is excluded from scanning.",
            )
        result = self.detection_engine.analyze_file(file_path)
        if inaccessible_as_skipped and result.status == ScanStatus.ERROR:
            if _expected_access_message(result.error_message or ""):
                result.status = ScanStatus.SKIPPED
                result.error_message = f"File was not checked: {result.error_message}"
        return result

    def scan_directory(
        self, directory_path: str, progress_callback=None, cancel_check=None
    ) -> ScanReport:
        return self.scan_directories([directory_path], progress_callback, cancel_check)

    def scan_directories(
        self,
        directory_paths: list[str],
        progress_callback: Callable[[int, int, str], None] | None = None,
        cancel_check: Callable[[], bool] | None = None,
    ) -> ScanReport:
        started = monotonic()
        report = ScanReport(started_at=datetime.now(timezone.utc).isoformat())
        file_paths: list[Path] = []
        seen: set[Path] = set()
        root_identities: list[Path] = []

        def cancelled() -> bool:
            if cancel_check and cancel_check():
                report.cancelled = True
            return report.cancelled

        def traversal_error(path, message, status=ScanStatus.ERROR) -> None:
            report.add_result(
                ScanResult(file_path=str(path), status=status, error_message=message)
            )

        def expected_access_problem(exc: OSError) -> bool:
            return isinstance(exc, (FileNotFoundError, PermissionError)) or exc.errno in {
                errno.EACCES,
                errno.EPERM,
                errno.ENOENT,
                errno.ENOTDIR,
            }

        for directory_path in directory_paths:
            if cancelled():
                break
            root = Path(directory_path).absolute()
            if self._is_excluded(root):
                traversal_error(
                    root,
                    "The protected quarantine area is excluded from scanning.",
                    ScanStatus.SKIPPED,
                )
                continue
            if root.is_symlink() or (
                hasattr(root, "is_junction") and root.is_junction()
            ):
                traversal_error(
                    root, "Linked folders are not followed.", ScanStatus.SKIPPED
                )
                continue
            if not root.is_dir():
                traversal_error(root, "Folder does not exist or is not a directory.")
                continue
            try:
                root_identities.append(root.resolve())
            except OSError as exc:
                traversal_error(
                    root,
                    f"Folder was not checked: {exc}",
                    ScanStatus.SKIPPED
                    if expected_access_problem(exc)
                    else ScanStatus.ERROR,
                )
                continue

            def on_walk_error(error: OSError) -> None:
                traversal_error(
                    error.filename or root,
                    f"Folder was not checked: {error}",
                    ScanStatus.SKIPPED
                    if expected_access_problem(error)
                    else ScanStatus.ERROR,
                )

            for directory, subdirectories, filenames in os.walk(
                root, onerror=on_walk_error, followlinks=False
            ):
                if cancelled():
                    break
                subdirectories.sort()
                for name in subdirectories[:]:
                    child = Path(directory, name)
                    if self._is_excluded(child):
                        subdirectories.remove(name)
                        traversal_error(
                            child,
                            "Protected quarantine folder excluded.",
                            ScanStatus.SKIPPED,
                        )
                        continue
                    if child.is_symlink() or (
                        hasattr(child, "is_junction") and child.is_junction()
                    ):
                        subdirectories.remove(name)
                        traversal_error(
                            child,
                            "Linked folders are not followed.",
                            ScanStatus.SKIPPED,
                        )
                for filename in sorted(filenames):
                    if cancelled():
                        break
                    file_path = Path(directory, filename)
                    if file_path in seen:
                        continue
                    seen.add(file_path)
                    if self.max_files is not None and len(file_paths) >= self.max_files:
                        report.warnings.append(
                            f"Stopped discovering files at the {self.max_files} file limit."
                        )
                        break
                    file_paths.append(file_path)
                if report.warnings:
                    break
            if report.warnings:
                break

        total = len(file_paths)
        for current, file_path in enumerate(file_paths, start=1):
            if cancelled():
                break
            try:
                if not any(
                    file_path.resolve().is_relative_to(root) for root in root_identities
                ):
                    result = ScanResult(
                        str(file_path),
                        ScanStatus.SKIPPED,
                        error_message="File left the selected scan folders.",
                    )
                else:
                    result = self.scan_file(
                        str(file_path), inaccessible_as_skipped=True
                    )
            except (FileNotFoundError, PermissionError) as exc:
                result = ScanResult(
                    str(file_path),
                    ScanStatus.SKIPPED,
                    error_message=f"File was not checked: {exc}",
                )
            except OSError as exc:
                result = ScanResult(
                    str(file_path),
                    ScanStatus.SKIPPED
                    if expected_access_problem(exc)
                    else ScanStatus.ERROR,
                    error_message=(
                        f"File was not checked: {exc}"
                        if expected_access_problem(exc)
                        else str(exc)
                    ),
                )
            except Exception as exc:
                result = ScanResult(
                    str(file_path), ScanStatus.ERROR, error_message=str(exc)
                )
            report.add_result(result)
            if progress_callback:
                progress_callback(current, total, str(file_path))
        report.duration = monotonic() - started
        report.completed_at = datetime.now(timezone.utc).isoformat()
        return report
