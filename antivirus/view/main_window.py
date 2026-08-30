"""Main Premiere Security application shell and page coordination."""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from antivirus.controller.history_controller import HistoryController
from antivirus.controller.scan_controller import ScanController
from antivirus.model.scan_report import ScanReport
from antivirus.services.statistics_service import StatisticsService
from antivirus.view.branding import AppLogo
from antivirus.view.dashboard_view import DashboardView
from antivirus.view.history_view import HistoryView
from antivirus.view.results_view import ResultsView
from antivirus.view.scan_view import ScanView
from antivirus.view.settings_view import SettingsView


class TopNavigation(QWidget):
    """Predictable top navigation that never shortens page names."""

    currentChanged = Signal(int)

    def __init__(self, page_names, parent=None):
        super().__init__(parent)
        self._current_index = -1
        self._buttons: list[QPushButton] = []
        self._group = QButtonGroup(self)
        self._group.setExclusive(True)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        for index, name in enumerate(page_names):
            button = QPushButton(name, self)
            button.setCheckable(True)
            button.setProperty("nav", True)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.clicked.connect(
                lambda _checked=False, page=index: self.setCurrentIndex(page)
            )
            self._group.addButton(button, index)
            self._buttons.append(button)
            layout.addWidget(button)

    def setCurrentIndex(self, index: int) -> None:
        if not 0 <= index < len(self._buttons):
            return
        self._buttons[index].setChecked(True)
        if index == self._current_index:
            return
        self._current_index = index
        self.currentChanged.emit(index)

    def currentIndex(self) -> int:
        return self._current_index


class MainWindow(QMainWindow):
    """Application shell with a desktop-style top navigation bar."""

    PAGE_NAMES = ("Dashboard", "Scan", "Results", "History", "Settings")

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Premiere Security — Educational Antivirus")
        self.setMinimumSize(960, 640)
        self.resize(1180, 760)
        self._close_confirmed = False

        self.scan_controller = ScanController()
        self.history_controller = HistoryController(self.scan_controller.repository)
        self.statistics_service = StatisticsService(
            scan_repo=self.scan_controller.repository
        )
        self._build_ui()
        self._apply_saved_settings()
        self._refresh_dashboard()

    def _build_ui(self) -> None:
        root = QWidget(self)
        root.setObjectName("AppRoot")
        layout = QVBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        top_bar = QWidget(root)
        top_bar.setObjectName("TopBar")
        top_bar.setFixedHeight(78)
        top_layout = QHBoxLayout(top_bar)
        top_layout.setContentsMargins(22, 0, 22, 0)
        top_layout.setSpacing(16)

        mark = AppLogo(top_bar)

        brand_text = QVBoxLayout()
        brand_text.setSpacing(0)
        brand_title = QLabel("Premiere Security", top_bar)
        brand_title.setProperty("role", "brandTitle")
        brand_subtitle = QLabel("Educational antivirus", top_bar)
        brand_subtitle.setProperty("role", "brandSubtitle")
        brand_text.addWidget(brand_title)
        brand_text.addWidget(brand_subtitle)

        self.navigation = TopNavigation(self.PAGE_NAMES, top_bar)
        self.navigation.setObjectName("TopNavigation")

        top_layout.addWidget(mark)
        top_layout.addLayout(brand_text)
        top_layout.addSpacing(24)
        top_layout.addWidget(self.navigation)
        top_layout.addStretch()

        self.pages = QStackedWidget(root)
        self.pages.setObjectName("PageStack")
        self.dashboard_view = DashboardView(self.pages)
        self.scan_view = ScanView(
            self.scan_controller.scan_file,
            self.scan_controller.scan_directory,
            self.scan_controller.quick_scan,
            self.pages,
        )
        self.results_view = ResultsView(self.pages)
        self.history_view = HistoryView(self.history_controller, self.pages)
        self.settings_view = SettingsView(self.pages)
        for page in (
            self.dashboard_view,
            self.scan_view,
            self.results_view,
            self.history_view,
            self.settings_view,
        ):
            self.pages.addWidget(page)

        layout.addWidget(top_bar)
        layout.addWidget(self.pages, 1)
        self.setCentralWidget(root)

        self.navigation.currentChanged.connect(self._navigate)
        self.navigation.setCurrentIndex(0)
        self.pages.setCurrentIndex(0)
        self.scan_view.scan_completed.connect(self._show_scan_result)
        self.dashboard_view.start_scan.connect(self._quick_scan_from_dashboard)
        self.dashboard_view.open_history.connect(
            lambda: self.navigation.setCurrentIndex(3)
        )
        self.settings_view.setting_changed.connect(self._setting_changed)
        self.history_view.history_changed.connect(self._refresh_dashboard)

    def _navigate(self, row):
        current_row = self.pages.currentIndex()
        if (
            current_row == 4
            and row != 4
            and self.settings_view.has_unsaved_changes()
            and not self.settings_view.resolve_unsaved_changes()
        ):
            self.navigation.blockSignals(True)
            self.navigation.setCurrentIndex(current_row)
            self.navigation.blockSignals(False)
            return
        self.pages.setCurrentIndex(row)
        self._page_changed(row)

    def _apply_saved_settings(self):
        for key, enabled in self.settings_view.values().items():
            self._setting_changed(key, enabled)
        states = self.scan_controller.scanner.detection_engine.get_engine_states()
        self.settings_view.update_availability(states)

    def _page_changed(self, row):
        if row == 3:
            self.history_view.refresh()
        elif row == 0:
            self._refresh_dashboard()
        elif row == 4:
            states = self.scan_controller.scanner.detection_engine.get_engine_states()
            self.settings_view.update_availability(states)

    def _setting_changed(self, key, enabled):
        attribute = {
            "clamav_enabled": "clamav_enabled",
            "yara_enabled": "yara_enabled",
            "hash_detection_enabled": "hash_enabled",
            "virustotal_enabled": "virustotal_enabled",
        }.get(key)
        if attribute:
            setattr(self.scan_controller.scanner.detection_engine, attribute, enabled)
        if self.pages.currentIndex() == 0:
            self._refresh_dashboard()

    def _quick_scan_from_dashboard(self):
        self.navigation.setCurrentIndex(1)
        QTimer.singleShot(100, self.scan_view.start_quick_scan)

    def _show_scan_result(self, result):
        if hasattr(result, "results"):
            report = result
        else:
            report = ScanReport()
            report.add_result(result)
        self.results_view.show_report(report)
        self.navigation.setCurrentIndex(2)

    def _refresh_dashboard(self):
        try:
            statistics = self.statistics_service.get_scan_statistics(hours=None)
            recent_scans = self.history_controller.recent_scans(limit=4)
            engine_states = (
                self.scan_controller.scanner.detection_engine.get_engine_states()
            )
            self.dashboard_view.update_dashboard(
                statistics, recent_scans, engine_states
            )
        except (OSError, ValueError):
            self.dashboard_view.protection_title.setText("Scanner needs attention")
            self.dashboard_view.protection_detail.setText(
                "Protection details could not be loaded. Try reopening the application."
            )

    def closeEvent(self, event):
        if self._close_confirmed:
            event.accept()
            return

        if self.settings_view.has_unsaved_changes():
            if not self.settings_view.resolve_unsaved_changes():
                event.ignore()
                return

        if self.scan_view.is_scanning():
            answer = QMessageBox.question(
                self,
                "Stop scan and close?",
                "A scan is still running. Do you want to stop it safely and close Premiere Security?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self._close_confirmed = True
            self.scan_view.cancel_active_scan(confirm=False)
            self.scan_view.scan_idle.connect(self.close)
            event.ignore()
            return

        answer = QMessageBox.question(
            self,
            "Close Premiere Security?",
            "Do you wish to close the application?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer == QMessageBox.StandardButton.Yes:
            event.accept()
        else:
            event.ignore()
