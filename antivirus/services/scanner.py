from __future__ import annotations

import os
from pathlib import Path
from typing import Callable

from antivirus.detection.detection_engine import DetectionEngine
from antivirus.model.scan_report import ScanReport
from antivirus.model.scan_result import ScanResult
from antivirus.model.scan_status import ScanStatus


class Scanner:
    """High-level file and directory scanner for backend integration."""

    def __init__(self, detection_engine: DetectionEngine | None = None):
        self.detection_engine = detection_engine or DetectionEngine()

    def scan_file(self, file_path: str) -> ScanResult:
        return self.detection_engine.analyze_file(file_path)

    def scan_directory(
        self,
        directory_path: str,
        progress_callback: Callable[[int, int, str], None] | None = None,
        cancel_check: Callable[[], bool] | None = None,
    ) -> ScanReport:
        return self.scan_directories(
            [directory_path],
            progress_callback=progress_callback,
            cancel_check=cancel_check,
        )

    def scan_directories(
        self,
        directory_paths: list[str],
        progress_callback: Callable[[int, int, str], None] | None = None,
        cancel_check: Callable[[], bool] | None = None,
    ) -> ScanReport:
        """Scan one or more folders with accurate, cancellable progress."""

        report = ScanReport()
        file_paths: list[Path] = []
        seen: set[Path] = set()

        for directory_path in directory_paths:
            root = Path(directory_path)
            if not root.exists():
                continue

            def on_walk_error(error: OSError, fallback=root) -> None:
                report.add_result(
                    ScanResult(
                        file_path=str(error.filename or fallback),
                        status=ScanStatus.ERROR,
                        error_message=str(error),
                    )
                )

            for directory, _subdirectories, filenames in os.walk(
                root, onerror=on_walk_error, followlinks=False
            ):
                if cancel_check and cancel_check():
                    return report
                for filename in sorted(filenames):
                    file_path = Path(directory, filename)
                    try:
                        identity = file_path.resolve()
                    except OSError:
                        identity = file_path
                    if identity not in seen:
                        seen.add(identity)
                        file_paths.append(file_path)

        total = len(file_paths)
        for current, file_path in enumerate(file_paths, start=1):
            if cancel_check and cancel_check():
                return report
            try:
                result = self.scan_file(str(file_path))
            except Exception as exc:
                result = ScanResult(
                    file_path=str(file_path),
                    status=ScanStatus.ERROR,
                    error_message=str(exc),
                )
            report.add_result(result)
            if progress_callback:
                progress_callback(current, total, str(file_path))

        return report
