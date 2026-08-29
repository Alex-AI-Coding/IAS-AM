from PySide6.QtCore import Signal
from PySide6.QtWidgets import QLabel, QPushButton, QVBoxLayout, QWidget


class DashboardView(QWidget):
    start_scan = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Dashboard"))
        layout.addWidget(QLabel("Protection status: Scanner ready"))
        layout.addWidget(QLabel("Last scan: Never"))
        layout.addWidget(QLabel("Files scanned: 0"))
        layout.addWidget(QLabel("Threats detected: 0"))
        button = QPushButton("Start Scan", self)
        button.clicked.connect(self.start_scan)
        layout.addWidget(button)
        layout.addStretch()

    def update_statistics(self, statistics):
        self.findChildren(QLabel)[1].setText("Protection status: Scanner ready")
        labels = self.findChildren(QLabel)
        if len(labels) >= 5:
            labels[2].setText(f"Scans in last 24 hours: {statistics.get('total_scans', 0)}")
            labels[3].setText(f"Files scanned: {statistics.get('clean_scans', 0) + statistics.get('threat_scans', 0)}")
            labels[4].setText(f"Threat scans: {statistics.get('threat_scans', 0)}")
