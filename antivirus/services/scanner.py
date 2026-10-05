"""Bounded, read-only traversal shared by desktop, API and CLI scans."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic
from typing import Callable

from antivirus.config.settings import MAX_SCAN_FILES
from antivirus.detection.detection_engine import DetectionEngine
from antivirus.model.scan_report import ScanReport
from antivirus.model.scan_result import ScanResult
from antivirus.model.scan_status import ScanStatus


class Scanner:
    def __init__(
        self, detection_engine: DetectionEngine | None = None, max_files=MAX_SCAN_FILES
    ):
        self.detection_engine = detection_engine or DetectionEngine()
        if max_files <= 0:
            raise ValueError("max_files must be positive")
        self.max_files = max_files

    def scan_file(self, file_path: str) -> ScanResult:
        return self.detection_engine.analyze_file(file_path)

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

        for directory_path in directory_paths:
            if cancelled():
                break
            root = Path(directory_path).absolute()
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
            root_identities.append(root.resolve())

            def on_walk_error(error: OSError) -> None:
                traversal_error(error.filename or root, str(error))

            for directory, subdirectories, filenames in os.walk(
                root, onerror=on_walk_error, followlinks=False
            ):
                if cancelled():
                    break
                subdirectories.sort()
                for name in subdirectories[:]:
                    child = Path(directory, name)
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
                    if len(file_paths) >= self.max_files:
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
                    result = self.scan_file(str(file_path))
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
