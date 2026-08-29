from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtWidgets import QFileDialog, QLabel, QProgressBar, QPushButton, QVBoxLayout, QWidget

from antivirus.model.scan_report import ScanReport
from antivirus.model.scan_result import ScanResult


class ScanWorker(QObject):
    finished = Signal(object)
    failed = Signal(str)
    progress = Signal(int, int, str)
    cancelled = Signal()

    def __init__(self, operation, path):
        super().__init__()
        self.operation = operation
        self.path = path
        self.cancel_requested = False

    @Slot()
    def run(self):
        try:
            if self.operation.__name__ in ("scan_directory", "quick_scan"):
                result = self.operation(self.path, self._progress, lambda: self.cancel_requested)
            else:
                result = self.operation(self.path)
            if self.cancel_requested:
                self.cancelled.emit()
            else:
                self.finished.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))

    def _progress(self, current, total, path):
        self.progress.emit(current, total, path)

    def cancel(self):
        self.cancel_requested = True


class ScanView(QWidget):
    scan_completed = Signal(object)

    def __init__(
        self,
        scan_file: Callable[[str], ScanResult] | None = None,
        scan_directory: Callable[[str], ScanReport] | None = None,
        quick_scan: Callable[[], ScanReport] | None = None,
        parent=None,
    ):
        super().__init__(parent)
        self._scan_file = scan_file
        self._scan_directory = scan_directory
        self._quick_scan = quick_scan
        self._thread = None
        self._worker = None
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Scan"))

        self.quick_scan_button = QPushButton("Quick Scan", self)
        self.quick_scan_button.clicked.connect(self._start_quick_scan)
        layout.addWidget(self.quick_scan_button)

        self.select_file_button = QPushButton("Select File", self)
        self.select_file_button.clicked.connect(self._select_file)
        layout.addWidget(self.select_file_button)

        self.select_folder_button = QPushButton("Select Folder", self)
        self.select_folder_button.clicked.connect(self._select_folder)
        layout.addWidget(self.select_folder_button)
        self.cancel_button = QPushButton("Cancel Scan", self)
        self.cancel_button.clicked.connect(self._cancel_scan)
        self.cancel_button.hide()
        layout.addWidget(self.cancel_button)

        self.status_label = QLabel("Select a file to begin.", self)
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        self.progress = QProgressBar(self)
        self.progress.setRange(0, 0)
        self.progress.hide()
        layout.addWidget(self.progress)
        layout.addStretch()

    def _select_file(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(self, "Select a file to scan")
        if not file_path:
            return
        if self._scan_file is None:
            self.status_label.setText("File scanning is not configured.")
            return

        self._start_scan(self._scan_file, file_path)

    def _start_quick_scan(self):
        if self._quick_scan is not None:
            self._start_scan(self._quick_scan, "home directory")

    def _select_folder(self) -> None:
        directory_path = QFileDialog.getExistingDirectory(self, "Select a folder to scan")
        if not directory_path:
            return
        if self._scan_directory is None:
            self.status_label.setText("Folder scanning is not configured.")
            return

        self._start_scan(self._scan_directory, directory_path)

    def _start_scan(self, operation, path):
        self._thread = QThread(self)
        self._worker = ScanWorker(operation, path)
        self._set_scan_controls_enabled(False)
        self.progress.show()
        self.cancel_button.show()
        self._worker.progress.connect(self._scan_progress)
        self.status_label.setText(f"Scanning: {path}")
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._scan_finished)
        self._worker.cancelled.connect(self._scan_cancelled)
        self._worker.failed.connect(self._scan_failed)
        self._worker.finished.connect(self._thread.quit)
        self._worker.failed.connect(self._thread.quit)
        self._worker.cancelled.connect(self._thread.quit)
        self._thread.finished.connect(self._scan_thread_finished)
        self._thread.start()

    def _scan_finished(self, result):
        if isinstance(result, ScanResult):
            self.status_label.setText(
                f"{result.status.value.title()}: {result.file_path}\n"
                f"Threats found: {len(result.threats)}"
            )
        else:
            self.status_label.setText(
                f"Folder scan complete: {result.total_files} files | "
                f"{result.threat_files} threats | {result.error_files} errors"
            )
        self.scan_completed.emit(result)

    def _scan_failed(self, _message):
        self.status_label.setText("Unable to complete the scan.")

    def _scan_cancelled(self):
        self.status_label.setText("Scan cancelled.")

    def _scan_progress(self, current, total, path):
        self.progress.setRange(0, max(total, 1))
        self.progress.setValue(current)
        self.status_label.setText(f"Scanning ({current}/{total}): {path}")

    def _cancel_scan(self):
        if self._worker:
            self._worker.cancel()
            self.status_label.setText("Cancelling scan...")

    def _scan_thread_finished(self):
        self._set_scan_controls_enabled(True)
        self.progress.hide()
        self.cancel_button.hide()
        self._worker.deleteLater()
        self._thread.deleteLater()
        self._worker = None
        self._thread = None

    def _set_scan_controls_enabled(self, enabled: bool) -> None:
        self.select_file_button.setEnabled(enabled)
        self.select_folder_button.setEnabled(enabled)
        self.quick_scan_button.setEnabled(enabled)
