"""Read-only network visibility with asynchronous, on-demand refresh."""

from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtWidgets import (
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from antivirus.services.network_monitor_service import NetworkMonitorService
from antivirus.view.components import configure_table, page_header


class ConnectionWorker(QObject):
    ready = Signal(object)
    failed = Signal(str)
    done = Signal()

    @Slot()
    def run(self):
        try:
            self.ready.emit(NetworkMonitorService.connections())
        except Exception:
            self.failed.emit(
                "Connection information is unavailable for this OS account. File scanning remains available."
            )
        finally:
            self.done.emit()


class NetworkMonitorTab(QWidget):
    idle = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._thread = None
        self._worker = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 27, 30, 26)
        layout.setSpacing(16)
        layout.addWidget(
            page_header(
                "Network visibility",
                "Inspect active connections without capturing payloads or stopping applications.",
            )
        )
        self.status = QLabel(
            "An unfamiliar IP address or port is a reason to investigate, not proof of malware."
        )
        self.status.setWordWrap(True)
        self.status.setProperty("role", "muted")
        layout.addWidget(self.status)
        self.refresh_button = QPushButton("Refresh connections")
        self.refresh_button.setProperty("variant", "primary")
        self.refresh_button.clicked.connect(self.refresh_connections)
        layout.addWidget(self.refresh_button)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["Application", "PID", "Protocol", "Remote endpoint", "State"]
        )
        configure_table(self.table)
        self.table.setColumnWidth(0, 220)
        self.table.setColumnWidth(3, 260)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, 1)

    def refresh_connections(self):
        if self._thread:
            return
        self.refresh_button.setEnabled(False)
        self.status.setText("Reading the current connection snapshot…")
        self._thread = QThread(self)
        self._worker = ConnectionWorker()
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.ready.connect(self._show_rows)
        self._worker.failed.connect(self.status.setText)
        self._worker.done.connect(self._thread.quit)
        self._worker.done.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._finished)
        self._thread.start()

    def _show_rows(self, rows):
        self.table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            for column, key in enumerate(
                ("process", "pid", "protocol", "endpoint", "state")
            ):
                self.table.setItem(
                    index, column, QTableWidgetItem(str(row[key] or "—"))
                )
        self.status.setText(
            f"{len(rows)} active remote connections. This snapshot is informational; no traffic was blocked."
        )

    def _finished(self):
        self._thread.deleteLater()
        self._thread = self._worker = None
        self.refresh_button.setEnabled(True)
        self.idle.emit()

    def is_busy(self):
        return self._thread is not None
