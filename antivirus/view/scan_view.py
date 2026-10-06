"""Cancellable desktop scan workflow."""

from __future__ import annotations

from collections.abc import Callable
from threading import Event

from PySide6.QtCore import QObject, Qt, QThread, Signal, Slot
from PySide6.QtWidgets import (
    QFileDialog,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from antivirus.model.scan_report import ScanReport
from antivirus.model.scan_result import ScanResult
from antivirus.view.components import Card, page_header, section_title
from antivirus.view.radar import ScanRadar
from antivirus.view.drive_dialog import DriveSelectionDialog


class ScanWorker(QObject):
    finished = Signal(object)
    failed = Signal(str)
    progress = Signal(int, int, str)
    cancelled = Signal(object)
    done = Signal()

    def __init__(self, operation, path=None, supports_progress=False):
        super().__init__()
        self.operation = operation
        self.path = path
        self.supports_progress = supports_progress
        self._cancel_event = Event()

    @property
    def cancel_requested(self):
        return self._cancel_event.is_set()

    @Slot()
    def run(self):
        try:
            if self.supports_progress and self.path is None:
                result = self.operation(
                    progress_callback=self._progress,
                    cancel_check=lambda: self.cancel_requested,
                )
            elif self.supports_progress:
                result = self.operation(
                    self.path,
                    self._progress,
                    lambda: self.cancel_requested,
                )
            else:
                result = self.operation(self.path)
            if self.cancel_requested:
                if isinstance(result, ScanReport):
                    result.cancelled = True
                self.cancelled.emit(result)
            else:
                self.finished.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            self.done.emit()

    def _progress(self, current, total, path):
        self.progress.emit(current, total, path)

    def cancel(self):
        self._cancel_event.set()


class ScanChoice(QFrame):
    def __init__(self, symbol, title, description, button_text, parent=None):
        super().__init__(parent)
        self.setObjectName("ScanChoice")
        self.setFixedHeight(214)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 17)
        layout.setSpacing(8)
        icon = QLabel(symbol, self)
        icon.setProperty("role", "metricIcon")
        icon.setFixedSize(40, 40)
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label = QLabel(title, self)
        title_label.setProperty("role", "cardTitle")
        description_label = QLabel(description, self)
        description_label.setProperty("role", "muted")
        description_label.setWordWrap(True)
        description_label.setMinimumHeight(42)
        self.button = QPushButton(button_text, self)
        layout.addWidget(icon)
        layout.addWidget(title_label)
        layout.addWidget(description_label)
        layout.addStretch()
        layout.addWidget(self.button)


class ScanView(QWidget):
    scan_completed = Signal(object)
    scan_idle = Signal()
    scan_started = Signal()

    def __init__(
        self,
        scan_file: Callable[[str], ScanResult] | None = None,
        scan_directory: Callable[[str], ScanReport] | None = None,
        quick_scan: Callable[[], ScanReport] | None = None,
        parent=None,
        *,
        scan_drives: Callable[[list[str]], ScanReport] | None = None,
    ):
        super().__init__(parent)
        self._scan_file = scan_file
        self._scan_directory = scan_directory
        self._quick_scan = quick_scan
        self._scan_drives = scan_drives
        self._thread = None
        self._worker = None
        self._pending_result = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 27, 30, 26)
        layout.setSpacing(18)
        layout.addWidget(
            page_header(
                "Scan",
                "Choose the smallest scan that fits your need. You stay in control of every file checked.",
            )
        )

        choices = QHBoxLayout()
        choices.setSpacing(14)
        self.quick_choice = ScanChoice(
            "Q",
            "Quick scan",
            "Checks Desktop, Downloads, and Documents.",
            "Start quick scan",
            self,
        )
        self.file_choice = ScanChoice(
            "F",
            "Scan a file",
            "Inspect one file before opening, sharing, or submitting it.",
            "Choose file",
            self,
        )
        self.folder_choice = ScanChoice(
            "D",
            "Scan a folder",
            "Recursively inspect every file inside a folder you select.",
            "Choose folder",
            self,
        )
        self.drive_choice = ScanChoice(
            "S",
            "Scan drives",
            "Choose internal or USB drives, including D:, E:, or F:.",
            "Choose drives",
            self,
        )
        self.quick_scan_button = self.quick_choice.button
        self.select_file_button = self.file_choice.button
        self.select_folder_button = self.folder_choice.button
        self.select_drives_button = self.drive_choice.button
        self.select_drives_button.setEnabled(self._scan_drives is not None)
        self.quick_scan_button.setProperty("variant", "primary")
        self.quick_scan_button.clicked.connect(self.start_quick_scan)
        self.select_file_button.clicked.connect(self._select_file)
        self.select_folder_button.clicked.connect(self._select_folder)
        self.select_drives_button.clicked.connect(self._select_drives)
        for choice in (
            self.quick_choice,
            self.file_choice,
            self.folder_choice,
            self.drive_choice,
        ):
            choices.addWidget(choice, 1)
        layout.addLayout(choices)

        self.progress_card = Card(self, "ProgressCard")
        progress_layout = QVBoxLayout(self.progress_card)
        progress_layout.setContentsMargins(20, 17, 20, 17)
        progress_layout.setSpacing(10)
        progress_header = QHBoxLayout()
        self.progress_title = section_title("Ready when you are")
        self.cancel_button = QPushButton("Cancel scan", self.progress_card)
        self.cancel_button.setProperty("variant", "danger")
        self.cancel_button.setProperty("compact", True)
        self.cancel_button.clicked.connect(lambda: self._cancel_scan())
        self.cancel_button.hide()
        progress_header.addWidget(self.progress_title)
        progress_header.addStretch()
        progress_header.addWidget(self.cancel_button)
        self.status_label = QLabel(
            "Select a scan option above. Files are analyzed locally unless VirusTotal is explicitly enabled.",
            self.progress_card,
        )
        self.status_label.setProperty("role", "muted")
        self.status_label.setWordWrap(True)
        self.progress = QProgressBar(self.progress_card)
        self.progress.setTextVisible(False)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.hide()
        self.status_label.setTextFormat(Qt.TextFormat.PlainText)
        self.status_label.setMinimumWidth(200)
        self.radar = ScanRadar(self.progress_card)
        radar_row = QHBoxLayout()
        radar_row.setSpacing(22)
        radar_row.addWidget(self.radar)
        progress_text = QVBoxLayout()
        progress_text.setSpacing(10)
        progress_text.addLayout(progress_header)
        progress_text.addWidget(self.status_label)
        progress_text.addWidget(self.progress)
        radar_row.addLayout(progress_text, 1)
        progress_layout.addLayout(radar_row)
        layout.addWidget(self.progress_card)
        layout.addStretch(1)

        note = QLabel(
            "Educational note: Premiere Security demonstrates hash, signature, and optional third-party scanning. "
            "It is not a replacement for a maintained commercial antivirus product.",
            self,
        )
        note.setProperty("role", "hint")
        note.setWordWrap(True)
        layout.addWidget(note)

    def start_quick_scan(self) -> None:
        if self._quick_scan is None or self._thread is not None:
            return
        self._start_scan(
            self._quick_scan,
            None,
            "Quick scan",
            supports_progress=True,
        )

    def _select_file(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(self, "Select a file to scan")
        if not file_path:
            return
        if self._scan_file is None:
            self.status_label.setText("File scanning is not configured.")
            return
        self._start_scan(self._scan_file, file_path, "File scan")

    def _select_folder(self) -> None:
        directory_path = QFileDialog.getExistingDirectory(
            self, "Select a folder to scan"
        )
        if not directory_path:
            return
        if self._scan_directory is None:
            self.status_label.setText("Folder scanning is not configured.")
            return
        self._start_scan(
            self._scan_directory,
            directory_path,
            "Folder scan",
            supports_progress=True,
        )

    def _start_scan(self, operation, path, title, supports_progress=False):
        if not self.isEnabled():
            return
        if self._thread is not None:
            return
        self._thread = QThread(self)
        self._worker = ScanWorker(operation, path, supports_progress)
        self._pending_result = None
        self._set_scan_controls_enabled(False)
        self.progress_title.setText(f"{title} in progress")
        self.progress.show()
        self.cancel_button.setVisible(supports_progress)
        self.progress.setRange(0, 0)
        self.radar.set_state("scanning")
        self.scan_started.emit()
        target_label = (
            ", ".join(path) if isinstance(path, list) else (path or "common folders")
        )
        self.status_label.setText(f"Preparing to scan {target_label}…")
        self._worker.progress.connect(self._scan_progress)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._scan_finished)
        self._worker.cancelled.connect(self._scan_cancelled)
        self._worker.failed.connect(self._scan_failed)
        self._worker.done.connect(self._thread.quit)
        self._worker.done.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._scan_thread_finished)
        self._thread.start()

    @Slot(object)
    def _scan_finished(self, result):
        self._pending_result = result
        self.radar.set_state(
            "error"
            if (
                getattr(result, "error_files", 0)
                or getattr(result, "skipped_files", 0)
                or getattr(result, "error_message", None)
            )
            else "complete"
        )
        self.progress.setRange(0, 1)
        self.progress.setValue(1)
        if isinstance(result, ScanResult):
            threats = len(result.threats)
            self.status_label.setText(
                f"Result: {result.status.value}. {threats} detection(s). "
                + (
                    result.error_message
                    or "No matches means no known pattern was found; it does not prove safety."
                )
            )
        else:
            self.status_label.setText(
                f"Scan complete. {result.total_files} files checked, "
                f"{result.threat_files} suspicious, {result.error_files} errors, "
                f"and {result.skipped_files} skipped. " + " ".join(result.warnings)
            )
        self.progress_title.setText("Scan complete")

    @Slot(str)
    def _scan_failed(self, message):
        self.radar.set_state("error")
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.progress_title.setText("Scan could not finish")
        self.status_label.setText(
            f"Premiere Security could not complete this scan: {message}"
        )

    @Slot(object)
    def _scan_cancelled(self, result):
        self._pending_result = result
        self.radar.set_state("cancelled")
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.progress_title.setText("Scan cancelled")
        self.status_label.setText(
            "The scan stopped safely. Partial results are available in Results."
        )

    @Slot(int, int, str)
    def _scan_progress(self, current, total, path):
        self.progress.setRange(0, max(total, 1))
        self.progress.setValue(current)
        self.status_label.setText(f"Checking {current} of {total}: {path[-220:]}")
        self.status_label.setToolTip(path)

    def _cancel_scan(self, confirm: bool = True):
        if self._worker and self._thread and self._thread.isRunning():
            if confirm:
                answer = QMessageBox.question(
                    self,
                    "Stop current scan?",
                    "Do you wish to stop the scan safely after the current file?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                    QMessageBox.StandardButton.Cancel,
                )
                if answer != QMessageBox.StandardButton.Yes:
                    return
            try:
                self._worker.cancel()
            except RuntimeError:
                return
            self.cancel_button.setEnabled(False)
            self.status_label.setText("Stopping safely after the current file…")

    @Slot()
    def _scan_thread_finished(self):
        self._thread.wait()
        self._set_scan_controls_enabled(True)
        self.cancel_button.hide()
        self.cancel_button.setEnabled(True)
        self._thread.deleteLater()
        self._worker = None
        self._thread = None
        if self._pending_result is not None:
            self.scan_completed.emit(self._pending_result)
            self._pending_result = None
        self.scan_idle.emit()

    def _set_scan_controls_enabled(self, enabled: bool) -> None:
        self.select_file_button.setEnabled(enabled)
        self.select_folder_button.setEnabled(enabled)
        self.quick_scan_button.setEnabled(enabled)
        self.select_drives_button.setEnabled(enabled and self._scan_drives is not None)

    def _select_drives(self):
        if self._scan_drives is None or self.is_scanning() or not self.isEnabled():
            return
        dialog = DriveSelectionDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        paths = dialog.selected_paths()
        if paths:
            self._start_scan(
                self._scan_drives, paths, "Drive scan", supports_progress=True
            )

    def is_scanning(self) -> bool:
        return self._thread is not None

    def cancel_active_scan(self, confirm: bool = True) -> None:
        self._cancel_scan(confirm=confirm)
