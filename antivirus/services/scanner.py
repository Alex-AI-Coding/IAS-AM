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

    def scan_directory(self, directory_path: str, progress_callback: Callable[[int, int, str], None] | None = None, cancel_check: Callable[[], bool] | None = None) -> ScanReport:
        root = Path(directory_path)
        report = ScanReport()

        if not root.exists():
            return report

        count = 0

        def on_walk_error(error: OSError) -> None:
            report.add_result(ScanResult(file_path=str(error.filename or root), status=ScanStatus.ERROR, error_message=str(error)))

        for directory, _subdirectories, filenames in os.walk(root, onerror=on_walk_error, followlinks=False):
            for filename in sorted(filenames):
                if cancel_check and cancel_check():
                    return report
                file_path = Path(directory, filename)
                count += 1
                try:
                    result = self.scan_file(str(file_path))
                except Exception as exc:
                    result = ScanResult(file_path=str(file_path), status=ScanStatus.ERROR, error_message=str(exc))
                report.add_result(result)
                if progress_callback:
                    progress_callback(count, 0, str(file_path))

        return report
