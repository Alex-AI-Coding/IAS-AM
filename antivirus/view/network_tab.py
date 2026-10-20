"""Network visibility with confirmed process termination and async refresh."""

from PySide6.QtCore import QObject, QThread, Qt, QTimer, Signal, Slot
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QHBoxLayout,
    QVBoxLayout,
    QWidget,
)

from antivirus.services.network_monitor_service import NetworkMonitorService
from antivirus.view.components import (
    configure_table,
    page_header,
    set_table_row_numbers,
)
from antivirus.view.theme import COLORS


class ConnectionSpinner(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(24, 24)
        self.setAccessibleName("Refreshing network connections")
        self._angle = 0
        self._timer = QTimer(self)
        self._timer.setInterval(35)
        self._timer.timeout.connect(self._rotate)

    def start(self):
        self._angle = 0
        self._timer.start()
        self.show()

    def stop(self):
        self._timer.stop()
        self.hide()

    def _rotate(self):
        self._angle = (self._angle - 18) % 360
        self.update()

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        color = QColor(COLORS["highlight"])
        color.setAlpha(70)
        painter.setPen(QPen(color, 3, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(3, 3, 18, 18, 0, 360 * 16)
        color.setAlpha(255)
        painter.setPen(QPen(color, 3, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(3, 3, 18, 18, self._angle * 16, 245 * 16)
        painter.end()


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
        self._rows = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 27, 30, 26)
        layout.setSpacing(16)
        layout.addWidget(
            page_header(
                "Active network connections",
                "Review remote destinations, owning processes, local ports, and connection state. "
                "These details can help investigate activity but cannot prove an intrusion.",
            )
        )
        self.status = QLabel(
            "Select a connection and choose Details for its process path, account, start time, "
            "destination context, and port guidance. Termination closes the entire owning application."
        )
        self.status.setWordWrap(True)
        self.status.setProperty("role", "muted")
        layout.addWidget(self.status)
        actions = QHBoxLayout()
        self.refresh_button = QPushButton("Refresh connections")
        self.refresh_button.setProperty("variant", "primary")
        self.refresh_button.clicked.connect(self.refresh_connections)
        self.refresh_spinner = ConnectionSpinner(self)
        self.refresh_spinner.hide()
        self.details_button = QPushButton("Connection details")
        self.details_button.setEnabled(False)
        self.details_button.clicked.connect(self._show_selected_details)
        self.terminate_button = QPushButton("Terminate selected app(s)")
        self.terminate_button.setMinimumWidth(220)
        self.terminate_button.setEnabled(False)
        self.terminate_button.clicked.connect(self._terminate_selected)
        actions.addWidget(self.refresh_button)
        actions.addWidget(self.refresh_spinner)
        actions.addWidget(self.details_button)
        actions.addWidget(self.terminate_button)
        actions.addStretch()
        layout.addLayout(actions)
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            [
                "Application",
                "PID",
                "Protocol",
                "Local endpoint",
                "Remote endpoint",
                "Remote host",
                "State",
            ]
        )
        configure_table(self.table)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        header = self.table.horizontalHeader()
        self.table.setColumnWidth(3, 145)
        self.table.setColumnWidth(4, 160)
        for column in (1, 2, 6):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setDefaultSectionSize(46)
        self.table.itemSelectionChanged.connect(self._update_terminate_button)
        self.table.cellDoubleClicked.connect(lambda *_: self._show_selected_details())
        layout.addWidget(self.table, 1)

    def refresh_connections(self):
        if self._thread:
            return
        self.refresh_button.setEnabled(False)
        self.refresh_spinner.start()
        self.details_button.setEnabled(False)
        self.terminate_button.setEnabled(False)
        self.status.setText(
            "Refreshing the active network-connection snapshot…"
        )
        self._thread = QThread(self)
        self._worker = ConnectionWorker()
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.ready.connect(self._show_rows)
        self._worker.failed.connect(self._show_error)
        self._worker.done.connect(self._thread.quit)
        self._worker.done.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._finished)
        self._thread.start()

    @Slot(object)
    def _show_rows(self, rows):
        self._rows = list(rows)
        self.table.clearSelection()
        self.table.setRowCount(len(self._rows))
        for index, row in enumerate(self._rows):
            process_item = QTableWidgetItem(str(row["process"] or "—"))
            process_item.setData(
                Qt.ItemDataRole.UserRole,
                (row.get("pid"), row.get("process_create_time")),
            )
            self.table.setItem(index, 0, process_item)
            for column, key in enumerate(
                (
                    "pid",
                    "protocol",
                    "local_endpoint",
                    "endpoint",
                    "remote_host",
                    "state",
                ),
                start=1,
            ):
                item = QTableWidgetItem(str(row.get(key) or "—"))
                item.setToolTip(str(row.get(key) or "—"))
                self.table.setItem(index, column, item)
        set_table_row_numbers(self.table)
        self.status.setText(
            f"{len(self._rows)} active remote connections. Select a row for details; public IPs "
            "and unfamiliar ports are not, by themselves, evidence of an intrusion."
        )
        self._update_terminate_button()

    @Slot(str)
    def _show_error(self, message):
        self._rows = []
        self.table.clearSelection()
        self.table.setRowCount(0)
        set_table_row_numbers(self.table)
        self.status.setText(message)
        self._update_terminate_button()

    @Slot()
    def _update_terminate_button(self):
        selected_rows = self.table.selectionModel().selectedRows()
        self.details_button.setEnabled(bool(selected_rows) and not self.is_busy())
        self.terminate_button.setEnabled(
            bool(self._selected_connections()) and not self.is_busy()
        )

    def _show_selected_details(self):
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            return
        row_index = selected_rows[0].row()
        row = self._rows[row_index]
        self._show_connection_details(row)

    def _show_connection_details(self, row):
        remote_port = row.get("remote_port")
        port_guidance = {
            22: "SSH — commonly remote administration",
            53: "DNS — commonly name lookups",
            80: "HTTP — commonly unencrypted web traffic",
            123: "NTP — commonly time synchronization",
            443: "HTTPS/TLS — commonly encrypted web traffic",
            445: "SMB — commonly Windows file sharing",
            3389: "RDP — commonly Windows remote desktop",
        }.get(remote_port, "No common service label for this port")
        state_guidance = {
            "ESTABLISHED": "TCP session is currently established",
            "TIME_WAIT": "TCP session recently closed and is awaiting cleanup",
            "CLOSE_WAIT": "Remote TCP endpoint closed; local application has not closed yet",
            "SYN_SENT": "TCP connection attempt is in progress",
            "SYN_RECV": "TCP connection request was received",
            "LISTEN": "Application is waiting for inbound TCP connections",
            "NONE": "Often normal for UDP; UDP does not establish a TCP-style session",
        }.get(row.get("state"), "Operating-system connection state")
        if row.get("address_scope") == "Public internet":
            destination_guidance = (
                "Public internet address. Many legitimate applications connect to "
                "public services; this does not establish that the host is malicious."
            )
        else:
            destination_guidance = (
                f"{row.get('address_scope', 'Address scope unavailable')}. "
                "This classification alone does not establish whether the connection is safe."
            )
        details = [
            f"Application: {row.get('process', 'Unavailable')}",
            f"Process ID: {row.get('pid') or 'Unavailable'}",
            f"Executable: {row.get('executable_path', 'Unavailable')}",
            f"Running as: {row.get('username', 'Unavailable')}",
            f"Process started: {row.get('process_start_time', 'Unavailable')}",
            f"Direction: {row.get('direction', 'Unclear from connection snapshot')}",
            f"Local endpoint: {row.get('local_endpoint', 'Unavailable')}",
            f"Remote endpoint: {row.get('endpoint', 'Unavailable')}",
            f"Remote host: {row.get('remote_host', 'Unavailable')}",
            "Reverse-DNS names are optional owner-supplied labels and can be missing or misleading.",
            f"Destination context: {destination_guidance}",
            f"Remote port {remote_port}: {port_guidance}. Port numbers can be used by different services.",
            f"Protocol/state: {row.get('protocol', 'Unknown')} / {row.get('state', 'Unknown')} — {state_guidance}.",
            "",
            "This connection snapshot cannot confirm a hacker or determine whether traffic is malicious. "
            "Investigate an unexpected process, verify its executable and publisher, and compare "
            "the destination with activity you recognize.",
        ]
        QMessageBox.information(
            self,
            "Connection details",
            "\n".join(details),
        )

    def _selected_connections(self):
        selected_rows = sorted(
            {index.row() for index in self.table.selectionModel().selectedRows()}
        )
        connections = []
        for row_index in selected_rows:
            item = self.table.item(row_index, 0)
            if item is None:
                continue
            pid, process_create_time = item.data(Qt.ItemDataRole.UserRole)
            if pid is not None:
                connections.append(
                    {"pid": pid, "process_create_time": process_create_time}
                )
        return connections

    @Slot()
    def _terminate_selected(self):
        connections = self._selected_connections()
        if not connections:
            self.status.setText("Select at least one connection with a known process.")
            return

        applications = []
        for row_index in sorted(
            {index.row() for index in self.table.selectionModel().selectedRows()}
        ):
            item = self.table.item(row_index, 0)
            pid, _ = item.data(Qt.ItemDataRole.UserRole)
            if pid is not None:
                applications.append(f"{item.text()} (PID {pid})")
        answer = QMessageBox.warning(
            self,
            "Terminate owning application(s)?",
            "This will terminate the entire application process, not just its selected network connection:\n\n"
            + "\n".join(applications),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        results = NetworkMonitorService.terminate_processes(connections)
        succeeded = sum(result["success"] for result in results)
        failures = [result for result in results if not result["success"]]
        details = "\n".join(
            f"PID {result['pid']}: {result['message']}" for result in results
        )
        message = (
            f"Termination requested for {succeeded} application(s); "
            f"{len(failures)} could not be terminated."
        )
        self.status.setText(message)
        if failures:
            QMessageBox.warning(self, "Termination results", f"{message}\n\n{details}")
        else:
            QMessageBox.information(
                self, "Termination results", f"{message}\n\n{details}"
            )
        self.refresh_connections()

    @Slot()
    def _finished(self):
        self._thread.wait()
        self._thread.deleteLater()
        self._thread = self._worker = None
        self.refresh_button.setEnabled(True)
        self.refresh_spinner.stop()
        self._update_terminate_button()
        self.idle.emit()

    def is_busy(self):
        return self._thread is not None
