from PySide6.QtCore import Signal
from PySide6.QtWidgets import QLabel, QMessageBox, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget


class ResultsView(QWidget):
    quarantine_requested = Signal(str, str, object)
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self.summary = QLabel("No scan completed yet.", self)
        layout.addWidget(self.summary)
        self.table = QTableWidget(0, 5, self)
        self.table.setHorizontalHeaderLabels(["File", "Status", "Threat", "Detection", "Action"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.cellDoubleClicked.connect(self._show_details)
        layout.addWidget(self.table)

    def show_report(self, report):
        self.table.setRowCount(0)
        self.summary.setText(
            f"Files: {report.total_files} | Threats: {report.threat_files} | "
            f"Errors: {report.error_files}"
        )
        for result in report.results:
            threats = result.threats or [None]
            for threat in threats:
                row = self.table.rowCount()
                self.table.insertRow(row)
                values = [
                    result.file_path,
                    result.status.value,
                    threat.name if threat else "",
                    ", ".join(result.detection_methods),
                ]
                for column, value in enumerate(values):
                    self.table.setItem(row, column, QTableWidgetItem(str(value)))
                if threat:
                    button = QPushButton("Quarantine", self.table)
                    button.clicked.connect(
                        lambda _=False, r=result, t=threat: self.quarantine_requested.emit(
                            r.file_path, t.name, r.sha256
                        )
                    )
                    self.table.setCellWidget(row, 4, button)

    def _show_details(self, row, _column):
        details = [self.table.item(row, column).text() if self.table.item(row, column) else "" for column in range(4)]
        QMessageBox.information(
            self,
            "Threat details",
            f"File: {details[0]}\nStatus: {details[1]}\nThreat: {details[2]}\nDetection: {details[3]}",
        )
