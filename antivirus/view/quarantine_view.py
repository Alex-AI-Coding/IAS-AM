from PySide6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget


class QuarantineView(QWidget):
    def __init__(self, controller=None, parent=None):
        super().__init__(parent)
        self.controller = controller
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Quarantine"))
        self.table = QTableWidget(0, 4, self)
        self.table.setHorizontalHeaderLabels(["File", "Threat", "Created", "Actions"])
        layout.addWidget(self.table)
        layout.addStretch()

    def refresh(self):
        self.table.setRowCount(0)
        if not self.controller:
            return
        for record in self.controller.list_quarantined():
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(record.get("original_path", "")))
            self.table.setItem(row, 1, QTableWidgetItem(record.get("threat_name", "")))
            self.table.setItem(row, 2, QTableWidgetItem(record.get("created_at", "")))
            actions = QWidget(self.table)
            buttons = QHBoxLayout(actions)
            restore = QPushButton("Restore", actions)
            delete = QPushButton("Delete", actions)
            restore.clicked.connect(lambda _=False, i=record["id"]: self._restore(i))
            delete.clicked.connect(lambda _=False, i=record["id"]: self._delete(i))
            buttons.addWidget(restore)
            buttons.addWidget(delete)
            self.table.setCellWidget(row, 3, actions)

    def _restore(self, record_id):
        self.controller.restore(record_id)
        self.refresh()

    def _delete(self, record_id):
        self.controller.delete(record_id)
        self.refresh()
