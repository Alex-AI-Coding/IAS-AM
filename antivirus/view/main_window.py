"""Main application window and frontend navigation."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from antivirus.view.dashboard_view import DashboardView
from antivirus.view.history_view import HistoryView
from antivirus.view.quarantine_view import QuarantineView
from antivirus.view.scan_view import ScanView
from antivirus.view.settings_view import SettingsView
from antivirus.controller.scan_controller import ScanController
from antivirus.controller.quarantine_controller import QuarantineController
from antivirus.controller.history_controller import HistoryController
from antivirus.view.results_view import ResultsView
from antivirus.services.statistics_service import StatisticsService


class MainWindow(QMainWindow):
    """Application shell with sidebar navigation."""

    PAGE_NAMES = ("Dashboard", "Scan", "Scan Results", "Quarantine", "History", "Settings")

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Antivirus")
        self.resize(1000, 650)
        self._build_ui()

    def _build_ui(self) -> None:
        root = QWidget(self)
        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)

        sidebar = QWidget(root)
        sidebar.setFixedWidth(220)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(16, 20, 16, 16)

        title = QLabel("ANTIVIRUS", sidebar)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sidebar_layout.addWidget(title)

        self.navigation = QListWidget(sidebar)
        self.navigation.setObjectName("navigation")
        for page_name in self.PAGE_NAMES:
            QListWidgetItem(page_name, self.navigation)
        sidebar_layout.addWidget(self.navigation)

        self.pages = QStackedWidget(root)
        self.scan_controller = ScanController()
        self.quarantine_controller = QuarantineController()
        self.history_controller = HistoryController()
        self.scan_view = ScanView(
            self.scan_controller.scan_file,
            self.scan_controller.scan_directory,
            self.scan_controller.quick_scan,
            self.pages,
        )
        self.results_view = ResultsView(self.pages)
        self.quarantine_view = QuarantineView(self.quarantine_controller, self.pages)
        self.history_view = HistoryView(self.history_controller, self.pages)
        self.settings_view = SettingsView(self.pages)
        self.dashboard_view = DashboardView(self.pages)
        for page in (
            self.dashboard_view,
            self.scan_view,
            self.results_view,
            self.quarantine_view,
            self.history_view,
            self.settings_view,
        ):
            self.pages.addWidget(page)

        layout.addWidget(sidebar)
        layout.addWidget(self.pages, 1)
        self.setCentralWidget(root)

        self.navigation.currentRowChanged.connect(self.pages.setCurrentIndex)
        self.navigation.currentRowChanged.connect(self._page_changed)
        self.navigation.setCurrentRow(0)
        self.scan_view.scan_completed.connect(self._show_scan_result)
        self.results_view.quarantine_requested.connect(self._quarantine_result)
        self.dashboard_view.start_scan.connect(lambda: self.navigation.setCurrentRow(1))
        self.settings_view.setting_changed.connect(self._setting_changed)

    def _page_changed(self, row):
        if row == 3:
            self.quarantine_view.refresh()
        elif row == 4:
            self.history_view.refresh()
        elif row == 0:
            try:
                self.dashboard_view.update_statistics(StatisticsService().get_scan_statistics())
            except Exception:
                pass

    def _setting_changed(self, key, enabled):
        attribute = {"clamav_enabled": "clamav_enabled", "yara_enabled": "yara_enabled", "hash_detection_enabled": "hash_enabled"}.get(key)
        if attribute:
            setattr(self.scan_controller.scanner.detection_engine, attribute, enabled)

    def _quarantine_result(self, path, threat_name, sha256):
        try:
            self.quarantine_controller.quarantine(path, threat_name, sha256)
            self.quarantine_view.refresh()
        except (OSError, ValueError):
            pass

    def _show_scan_result(self, result):
        from antivirus.model.scan_report import ScanReport

        if hasattr(result, "results"):
            report = result
        else:
            report = ScanReport()
            report.add_result(result)
        self.results_view.show_report(report)
        self.navigation.setCurrentRow(2)
