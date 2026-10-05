"""Scan-results table, details, filtering, and report export."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from antivirus.services.report_formatter import ReportFormatter
from antivirus.view.components import (
    EmptyState,
    MetricCard,
    configure_table,
    page_header,
)


class ResultsView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.report = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 27, 30, 26)
        layout.setSpacing(16)

        heading = QHBoxLayout()
        heading.addWidget(
            page_header(
                "Scan results",
                "Review what was checked, inspect detections, and export a clear report.",
            ),
            1,
        )
        self.export_json_button = QPushButton("Export JSON", self)
        self.export_csv_button = QPushButton("Export CSV", self)
        self.export_json_button.clicked.connect(lambda: self._export("json"))
        self.export_csv_button.clicked.connect(lambda: self._export("csv"))
        self.export_json_button.setEnabled(False)
        self.export_csv_button.setEnabled(False)
        heading.addWidget(self.export_json_button)
        heading.addWidget(self.export_csv_button)
        layout.addLayout(heading)

        metrics = QHBoxLayout()
        metrics.setSpacing(13)
        self.total_card = MetricCard("F", "Files checked")
        self.clean_card = MetricCard("✓", "Clean files")
        self.threat_card = MetricCard("!", "Suspicious files")
        self.error_card = MetricCard("E", "Scan errors")
        for card in (
            self.total_card,
            self.clean_card,
            self.threat_card,
            self.error_card,
        ):
            metrics.addWidget(card, 1)
        layout.addLayout(metrics)

        self.results_toolbar = QWidget(self)
        toolbar = QHBoxLayout(self.results_toolbar)
        toolbar.setContentsMargins(0, 0, 0, 0)
        self.summary = QLabel("", self.results_toolbar)
        self.summary.setProperty("role", "muted")
        self.filter_combo = QComboBox(self.results_toolbar)
        self.filter_combo.addItems(
            ["All results", "Threats only", "Clean only", "Errors only"]
        )
        self.filter_combo.currentIndexChanged.connect(self._render_rows)
        toolbar.addWidget(self.summary, 1)
        toolbar.addWidget(QLabel("Show:", self.results_toolbar))
        toolbar.addWidget(self.filter_combo)
        layout.addWidget(self.results_toolbar)
        self.results_toolbar.hide()

        self.table = QTableWidget(0, 5, self)
        self.table.setHorizontalHeaderLabels(
            ["File", "Status", "Threat", "Severity", "Detected by"]
        )
        configure_table(self.table)
        self.table.horizontalHeader().setStretchLastSection(False)
        self.table.setColumnWidth(0, 285)
        self.table.setColumnWidth(1, 85)
        self.table.setColumnWidth(2, 190)
        self.table.setColumnWidth(3, 85)
        self.table.setColumnWidth(4, 120)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.cellDoubleClicked.connect(self._show_details)
        self.table.hide()
        layout.addWidget(self.table, 1)

        self.empty_state = EmptyState(
            "○",
            "No scan results yet",
            "Run a quick scan or choose a file or folder to see results here.",
            self,
        )
        layout.addWidget(self.empty_state, 1)

    def show_report(self, report):
        self.report = report
        self.total_card.set_value(report.total_files)
        self.clean_card.set_value(report.clean_files)
        self.threat_card.set_value(report.threat_files)
        self.error_card.set_value(report.error_files)
        self.summary.setText(
            f"{report.total_files} file{'s' if report.total_files != 1 else ''} checked · "
            f"{report.threats_found} detection{'s' if report.threats_found != 1 else ''}"
        )
        self.export_json_button.setEnabled(True)
        self.export_csv_button.setEnabled(True)
        self.results_toolbar.show()
        self.filter_combo.setCurrentIndex(0)
        self._render_rows()

    def _render_rows(self, *_args):
        self.table.setRowCount(0)
        if self.report is None:
            self.table.hide()
            self.empty_state.show()
            return

        filter_index = self.filter_combo.currentIndex()
        results = [
            result
            for result in self.report.results
            if filter_index == 0
            or (filter_index == 1 and result.is_detected)
            or (filter_index == 2 and result.is_clean)
            or (filter_index == 3 and result.status.value == "error")
        ]

        for result in results:
            row = self.table.rowCount()
            self.table.insertRow(row)
            threats = ", ".join(threat.name for threat in result.threats) or "—"
            severities = (
                ", ".join(dict.fromkeys(threat.severity for threat in result.threats))
                or "—"
            )
            methods = ", ".join(result.detection_methods) or "Local scan"
            values = [
                result.file_path,
                result.status.value.title(),
                threats,
                severities,
                methods,
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column == 0:
                    item.setData(Qt.ItemDataRole.UserRole, result)
                    item.setToolTip(result.file_path)
                if column == 1:
                    color = {
                        "clean": "#15803D",
                        "detected": "#C53B3B",
                        "error": "#B76A05",
                    }.get(result.status.value, "#66736F")
                    item.setForeground(QColor(color))
                self.table.setItem(row, column, item)

        has_rows = bool(results)
        self.table.setVisible(has_rows)
        self.empty_state.setVisible(not has_rows)
        if self.report.results and not has_rows:
            self.empty_state.set_message(
                "No matching results", "Choose a different result filter to continue."
            )
        elif not self.report.results:
            self.empty_state.set_message(
                "No files found", "The selected location did not contain any files."
            )

    def _show_details(self, row, _column):
        item = self.table.item(row, 0)
        result = item.data(Qt.ItemDataRole.UserRole) if item else None
        if result is None:
            return
        threat_lines = []
        for threat in result.threats:
            threat_lines.append(
                f"• {threat.name} ({threat.severity})\n  {threat.description or 'No additional description.'}"
            )
        threat_text = "\n".join(threat_lines) or "No threats detected."
        QMessageBox.information(
            self,
            "Scan details",
            f"File\n{result.file_path}\n\nStatus\n{result.status.value.title()}\n\n"
            f"SHA-256\n{result.sha256 or 'Unavailable'}\n\nDetections\n{threat_text}\n\n"
            f"Engines\n{', '.join(result.detection_methods) or 'Local scan'}"
            + (f"\n\nNote\n{result.error_message}" if result.error_message else ""),
        )

    def _export(self, format_name: str):
        if self.report is None:
            return
        extension = format_name.lower()
        path, _ = QFileDialog.getSaveFileName(
            self,
            f"Export {format_name.upper()} report",
            f"premiere-security-report.{extension}",
            f"{format_name.upper()} files (*.{extension})",
        )
        if not path:
            return
        if not path.lower().endswith(f".{extension}"):
            path += f".{extension}"
        try:
            content = (
                ReportFormatter.to_json(self.report)
                if format_name == "json"
                else ReportFormatter.to_csv(self.report)
            )
            Path(path).write_text(content, encoding="utf-8")
        except OSError as exc:
            QMessageBox.warning(self, "Export failed", str(exc))
            return
        QMessageBox.information(self, "Report exported", f"Saved to:\n{path}")
