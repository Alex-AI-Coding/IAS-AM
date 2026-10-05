from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, 
    QTableWidgetItem, QPushButton, QLabel, QMessageBox
)
from PySide6.QtCore import QTimer, Qt
import psutil

class NetworkMonitorTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        
        # Auto-refresh timer (polls every 3 seconds)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh_connections)
        self.timer.start(3000)

    def init_ui(self):
        layout = QVBoxLayout(self)

        # Title Header
        title_label = QLabel("Active Network Connections & Threat Kill-Switch")
        title_label.setStyleSheet("font-size: 16px; font-weight: bold; margin-bottom: 5px;")
        layout.addWidget(title_label)

        # Connections Table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Process Name", "PID", "Protocol", "Remote Endpoint", "Actions"])
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)

        # Manual Refresh Control
        btn_layout = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh Now")
        self.refresh_btn.clicked.connect(self.refresh_connections)
        btn_layout.addWidget(self.refresh_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        # Initial load
        self.refresh_connections()

    def refresh_connections(self):
        """Populates the table with active network endpoints and process metadata."""
        self.table.setRowCount(0)
        try:
            # Fetch active internet connections
            connections = psutil.net_connections(kind='inet')
            row_idx = 0
            
            for conn in connections:
                # Filter for connections with active remote addresses
                if conn.raddr:
                    self.table.insertRow(row_idx)
                    
                    pid = conn.pid
                    proc_name = "Unknown"
                    if pid:
                        try:
                            proc_name = psutil.Process(pid).name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            proc_name = "Inaccessible"

                    proto = "TCP" if conn.type == 1 else "UDP"
                    remote_endpoint = f"{conn.raddr.ip}:{conn.raddr.port}"

                    # Populate Cells
                    self.table.setItem(row_idx, 0, QTableWidgetItem(proc_name))
                    self.table.setItem(row_idx, 1, QTableWidgetItem(str(pid) if pid else "N/A"))
                    self.table.setItem(row_idx, 2, QTableWidgetItem(proto))
                    self.table.setItem(row_idx, 3, QTableWidgetItem(remote_endpoint))

                    # Kill-Switch Action Button
                    kill_btn = QPushButton("Terminate")
                    kill_btn.setStyleSheet("background-color: #d9534f; color: white; font-weight: bold; border-radius: 3px;")
                    if pid:
                        kill_btn.clicked.connect(lambda checked, p=pid, name=proc_name: self.kill_process(p, name))
                    else:
                        kill_btn.setEnabled(False)
                    
                    self.table.setCellWidget(row_idx, 4, kill_btn)
                    row_idx += 1
                    
        except Exception as e:
            print(f"Error fetching network connections: {e}")

    def kill_process(self, pid, name):
        """Kill-switch action to forcefully terminate a malicious or suspicious process."""
        reply = QMessageBox.question(
            self, "Kill-Switch Warning",
            f"Are you sure you want to terminate process '{name}' (PID: {pid})?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            try:
                proc = psutil.Process(pid)
                proc.terminate()
                proc.wait(timeout=3)
                QMessageBox.information(self, "Success", f"Successfully terminated {name} (PID: {pid}).")
                self.refresh_connections()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to terminate process: {e}")