from __future__ import annotations

import os
import logging
from pathlib import Path
from typing import Callable

from antivirus.detection.detection_engine import DetectionEngine
from antivirus.model.scan_report import ScanReport
from antivirus.model.scan_result import ScanResult
from antivirus.model.scan_status import ScanStatus
from antivirus.services.download_watcher import DownloadWatcherService
from antivirus.view.notification_popup import NotificationSignalBridge

logger = logging.getLogger(__name__)

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

class AntimalwareEngineCoordinator:
    def __init__(self, signal_bridge: NotificationSignalBridge | None = None):
        self.scanner = Scanner()
        self.watcher_service = DownloadWatcherService(scanner_callback=self.handle_download_interception)
        self.signal_bridge = signal_bridge

    def handle_download_interception(self, filepath: str):
        """Callback executed immediately when a file lands in Downloads."""
        filename = os.path.basename(filepath)
        logger.info(f"[Watchdog] Scanning downloaded file: {filename}")

        scan_result = self.scanner.scan_file(filepath)

        scan_report = ScanReport()
        scan_report.add_result(scan_result)

        is_threat = (
            scan_result.status == ScanStatus.INFECTED 
            if hasattr(ScanStatus, 'INFECTED') 
            else str(scan_result.status).lower() in ['infected', 'threat', 'malicious']
        )

        if is_threat:
            logger.critical(f"[THREAT DETECTED] Malicious download caught: {filepath}")
            self.enforce_quarantine(filepath, scan_report)
            
            if self.signal_bridge:
                self.signal_bridge.trigger_popup.emit(
                    "⚠️ Threat Blocked!", 
                    f"Malicious file intercepted:\n{filename}", 
                    True
                )
        else:
            logger.info(f"[CLEAN] Intercepted download verified safe: {filepath}")
            if self.signal_bridge:
                self.signal_bridge.trigger_popup.emit(
                    "🛡️ Download Secure", 
                    f"File verified safe:\n{filename}", 
                    False
                )

    def enforce_quarantine(self, filepath: str, report: ScanReport):
        try:
            quarantine_dir = os.path.join(os.path.expanduser("~"), ".antivirus_quarantine")
            os.makedirs(quarantine_dir, exist_ok=True)
            
            filename = os.path.basename(filepath)
            dest_path = os.path.join(quarantine_dir, f"{filename}.quarantined")
            
            os.rename(filepath, dest_path)
            logger.info(f"Successfully isolated threat to: {dest_path}")
        except Exception as e:
            logger.error(f"Failed to quarantine threat file {filepath}: {e}")

    def start_protection(self):
        self.watcher_service.start()

    def stop_protection(self):
        self.watcher_service.stop()
