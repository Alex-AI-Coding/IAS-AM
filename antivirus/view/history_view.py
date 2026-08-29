from PySide6.QtWidgets import QLabel, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget


class HistoryView(QWidget):
    def __init__(self, controller=None, parent=None):
        super().__init__(parent)
        self.controller = controller
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("History"))
        self.table = QTableWidget(0, 5, self)
        self.table.setHorizontalHeaderLabels(["Started", "Files", "Threats", "Errors", "Status"])
        layout.addWidget(self.table)
        layout.addStretch()

    def refresh(self):
        self.table.setRowCount(0)
        if not self.controller:
            return
        for record in self.controller.recent_scans():
            row = self.table.rowCount()
            self.table.insertRow(row)
            values = [record.get("started_at", ""), record.get("file_count", 0),
                      record.get("threats_found", 0), record.get("error_files", 0), record.get("status", "")]
            for column, value in enumerate(values):
                self.table.setItem(row, column, QTableWidgetItem(str(value)))
