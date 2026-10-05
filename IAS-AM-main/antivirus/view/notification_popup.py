from PySide6.QtCore import Qt, QTimer, Signal, QObject
from PySide6.QtWidgets import QWidget, QLabel, QVBoxLayout, QPushButton, QApplication

class NotificationSignalBridge(QObject):
    """Bridge to safely emit UI notifications across background threads."""
    trigger_popup = Signal(str, str, bool)  # title, message, is_threat

class NotificationPopup(QWidget):
    def __init__(self, title: str, message: str, is_threat: bool = False):
        super().__init__()
        self.setWindowFlags(
            Qt.Window | 
            Qt.FramelessWindowHint | 
            Qt.WindowStaysOnTopHint | 
            Qt.Tool
        )
        self.setAttribute(Qt.WA_ShowWithoutActivating, False)

        layout = QVBoxLayout()
        self.title_label = QLabel(f"<b>{title}</b>")
        self.msg_label = QLabel(message)
        layout.addWidget(self.title_label)
        layout.addWidget(self.msg_label)

        if is_threat:
            self.setStyleSheet("""
                background-color: #ffebee; 
                color: #c62828; 
                border: 2px solid #c62828; 
                border-radius: 6px; 
                padding: 12px;
            """)
            close_btn = QPushButton("Acknowledge & Close")
            close_btn.setStyleSheet("background-color: #c62828; color: white; border-radius: 4px; padding: 6px;")
            close_btn.clicked.connect(self.close)
            layout.addWidget(close_btn)
        else:
            self.setStyleSheet("""
                background-color: #e8f5e9; 
                color: #2e7d32; 
                border: 1px solid #2e7d32; 
                border-radius: 6px; 
                padding: 12px;
            """)
            QTimer.singleShot(3500, self.close)

        self.setLayout(layout)
        self.adjustSize()
        self.position_in_corner()

    def position_in_corner(self):
        """Aligns the pop-up to the bottom-right corner of the main screen."""
        screen = QApplication.primaryScreen().availableGeometry()
        margin = 20
        self.move(
            screen.width() - self.width() - margin, 
            screen.height() - self.height() - margin
        )