"""Persistent scan-history view."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtGui import QColor
from antivirus.view.theme import status_color
from PySide6.QtWidgets import (
    QHBoxLayout,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from antivirus.view.components import (
    EmptyState,
    configure_table,
    display_datetime,
    page_header,
    short_target,
)


class HistoryView(QWidget):
    history_changed = Signal()

    def __init__(self, controller=None, parent=None):
        super().__init__(parent)
        self.controller = controller
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 27, 30, 26)
        layout.setSpacing(16)

        heading = QHBoxLayout()
        heading.addWidget(
            page_header(
                "Scan history",
                "A local record of completed scans. No file contents are stored here.",
            ),
            1,
        )
        self.clear_button = QPushButton("Clear history", self)
        self.clear_button.setProperty("variant", "danger")
        self.clear_button.clicked.connect(self._clear_history)
        self.clear_button.setEnabled(False)
        heading.addWidget(self.clear_button)
        layout.addLayout(heading)

        self.table = QTableWidget(0, 7, self)
        self.table.setHorizontalHeaderLabels(
            ["Started", "Type", "Target", "Files", "Threats", "Duration", "Result"]
        )
        configure_table(self.table)
        self.table.setColumnWidth(0, 165)
        self.table.setColumnWidth(1, 80)
        self.table.setColumnWidth(2, 280)
        self.table.setColumnWidth(3, 65)
        self.table.setColumnWidth(4, 70)
        self.table.setColumnWidth(5, 80)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.hide()
        layout.addWidget(self.table, 1)

        self.empty_state = EmptyState(
            "○",
            "No scan history yet",
            "Completed scans will be saved here automatically.",
            self,
        )
        layout.addWidget(self.empty_state, 1)

    def refresh(self):
        self.table.setRowCount(0)
        try:
            records = self.controller.recent_scans() if self.controller else []
        except Exception:
            self.empty_state.set_message(
                "History is unavailable",
                "Check access to the application data folder and try again.",
            )
            self.table.hide()
            self.empty_state.show()
            self.clear_button.setEnabled(False)
            return
        for record in records:
            row = self.table.rowCount()
            self.table.insertRow(row)
            duration = float(record.get("duration", 0) or 0)
            target = record.get("target", "")
            values = [
                display_datetime(record.get("started_at", "")),
                record.get("scan_type", "custom").title(),
                short_target(target),
                record.get("file_count", 0),
                record.get("threats_found", 0),
                f"{duration:.1f}s",
                record.get("status", "unknown").title(),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column == 2:
                    item.setToolTip(target)
                if column == 6:
                    item.setForeground(QColor(status_color(record.get("status", ""))))
                self.table.setItem(row, column, item)
        has_records = bool(records)
        if not has_records:
            self.empty_state.set_message(
                "No scan history yet",
                "Completed scans will be saved here automatically.",
            )
        self.table.setVisible(has_records)
        self.empty_state.setVisible(not has_records)
        self.clear_button.setEnabled(has_records)

    def _clear_history(self):
        if not self.controller:
            return
        answer = QMessageBox.question(
            self,
            "Clear scan history",
            "Remove all saved scan-history entries? This does not delete or change scanned files.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            self.controller.clear_history()
        except Exception:
            QMessageBox.warning(
                self,
                "History could not be cleared",
                "Check access to the application data folder and try again.",
            )
            return
        self.refresh()
        self.history_changed.emit()
