"""Low-glare, accessible visual system for Premiere Security."""

from __future__ import annotations

from PySide6.QtGui import QColor, QFont, QPalette
from PySide6.QtWidgets import QApplication


COLORS = {
    "background": "#E3E9E6",
    "surface": "#EDF2EF",
    "nav": "#20312C",
    "primary": "#147763",
    "text": "#1B2723",
    "muted": "#55655F",
    "border": "#C5D0CB",
}


def apply_theme(application: QApplication) -> None:
    """Apply a readable cross-platform font, palette, and stylesheet."""

    application.setStyle("Fusion")
    font = QFont("Segoe UI")
    font.setPointSizeF(11.0)
    application.setFont(font)

    palette = application.palette()
    palette.setColor(QPalette.ColorRole.Window, QColor(COLORS["background"]))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(COLORS["text"]))
    palette.setColor(QPalette.ColorRole.Base, QColor(COLORS["surface"]))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#E6ECE9"))
    palette.setColor(QPalette.ColorRole.Text, QColor(COLORS["text"]))
    palette.setColor(QPalette.ColorRole.Button, QColor("#E7EDE9"))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(COLORS["text"]))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(COLORS["primary"]))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#F3F7F5"))
    application.setPalette(palette)
    application.setStyleSheet(STYLESHEET)


STYLESHEET = """
QMainWindow, QWidget#AppRoot, QStackedWidget#PageStack {
    background: #E3E9E6;
    color: #1B2723;
}

QWidget#TopBar {
    background: #20312C;
    border-bottom: 1px solid #385047;
}

QLabel[role="brandTitle"] {
    color: #F0F5F3;
    font-size: 16px;
    font-weight: 700;
}

QLabel[role="brandSubtitle"] {
    color: #AFC2BC;
    font-size: 10.5pt;
}

QTabBar#TopNavigation {
    background: transparent;
    border: 0;
}

QTabBar#TopNavigation::tab {
    min-width: 66px;
    min-height: 38px;
    margin: 0 2px;
    padding: 0 13px;
    border: 0;
    border-radius: 9px;
    background: transparent;
    color: #C9D6D2;
    font-size: 10.5pt;
    font-weight: 600;
}

QTabBar#TopNavigation::tab:hover {
    background: #2A423A;
    color: #F0F5F3;
}

QTabBar#TopNavigation::tab:selected {
    background: #3B6358;
    color: #F4F8F6;
}

QFrame#TopStatus {
    background: #2A423A;
    border: 1px solid #456158;
    border-radius: 10px;
}

QLabel[role="topStatusTitle"] {
    color: #BDE8D8;
    font-size: 10pt;
    font-weight: 700;
}

QLabel[role="topStatusText"] {
    color: #B8C8C3;
    font-size: 9.5pt;
}

QLabel[role="pageTitle"] {
    color: #1B2723;
    font-size: 25px;
    font-weight: 700;
}

QLabel[role="pageSubtitle"] {
    color: #55655F;
    font-size: 11pt;
}

QLabel[role="sectionTitle"] {
    color: #24322D;
    font-size: 13.5pt;
    font-weight: 650;
}

QLabel[role="cardTitle"] {
    color: #24322D;
    font-size: 11.5pt;
    font-weight: 650;
}

QLabel[role="body"], QLabel[role="muted"] {
    color: #55655F;
    font-size: 10.5pt;
}

QLabel[role="hint"] {
    color: #5D6C67;
    font-size: 10pt;
}

QLabel[role="metric"] {
    color: #1B2723;
    font-size: 25px;
    font-weight: 700;
}

QLabel[role="metricLabel"] {
    color: #55655F;
    font-size: 10.5pt;
}

QLabel[role="metricIcon"] {
    background: #D5E7E0;
    color: #126653;
    border-radius: 10px;
    font-size: 16px;
    font-weight: 700;
}

QFrame#Card, QFrame#MetricCard, QFrame#ScanChoice, QFrame#ProgressCard {
    background: #EDF2EF;
    border: 1px solid #C5D0CB;
    border-radius: 14px;
}

QFrame#ScanChoice:hover {
    border: 1px solid #82AA9E;
    background: #E8EFEB;
}

QFrame#ProtectionHero {
    background: #D6E8E0;
    border: 1px solid #AECEC2;
    border-radius: 16px;
}

QLabel[role="heroIcon"] {
    background: #147763;
    color: #F4F8F6;
    border-radius: 25px;
    font-size: 24px;
    font-weight: 700;
}

QLabel[role="heroTitle"] {
    color: #164A3E;
    font-size: 18px;
    font-weight: 700;
}

QLabel[role="heroText"] {
    color: #3F6258;
    font-size: 10.5pt;
}

QPushButton {
    min-height: 42px;
    padding: 0 17px;
    border: 1px solid #BBC8C3;
    border-radius: 9px;
    background: #E7EDE9;
    color: #24322D;
    font-size: 10.5pt;
    font-weight: 600;
}

QPushButton:hover {
    background: #DDE6E1;
    border-color: #95A8A1;
}

QPushButton:pressed {
    background: #D3DED9;
}

QPushButton:disabled {
    background: #DCE3DF;
    color: #7E8B86;
    border-color: #CFD7D3;
}

QPushButton[variant="primary"] {
    background: #147763;
    border-color: #147763;
    color: #F4F8F6;
}

QPushButton[variant="primary"]:hover {
    background: #0F6352;
    border-color: #0F6352;
}

QPushButton[variant="danger"] {
    background: #E9E0DE;
    border-color: #D4AAA4;
    color: #9D332D;
}

QPushButton[variant="danger"]:hover {
    background: #E5D5D2;
    border-color: #C98981;
}

QPushButton[variant="ghost"] {
    background: transparent;
    border-color: transparent;
    color: #4F5F59;
}

QPushButton[compact="true"] {
    min-height: 34px;
    padding: 0 12px;
    border-radius: 7px;
    font-size: 10pt;
}

QLabel[status="active"] {
    color: #176237;
    background: #D9EADD;
    border: 1px solid #ADD0B6;
    border-radius: 9px;
    padding: 4px 10px;
    font-size: 10pt;
    font-weight: 600;
}

QLabel[status="inactive"] {
    color: #56645F;
    background: #E1E6E3;
    border: 1px solid #C5CECA;
    border-radius: 9px;
    padding: 4px 10px;
    font-size: 10pt;
    font-weight: 600;
}

QLabel[status="warning"] {
    color: #80520C;
    background: #EEE2C8;
    border: 1px solid #D8BF87;
    border-radius: 9px;
    padding: 4px 10px;
    font-size: 10pt;
    font-weight: 600;
}

QLabel[status="danger"] {
    color: #94332E;
    background: #EAD8D5;
    border: 1px solid #D8AAA5;
    border-radius: 9px;
    padding: 4px 10px;
    font-size: 10pt;
    font-weight: 600;
}

QTableWidget {
    background: #EDF2EF;
    alternate-background-color: #E5EBE8;
    border: 1px solid #C5D0CB;
    border-radius: 11px;
    gridline-color: transparent;
    selection-background-color: #CFE3DA;
    selection-color: #1B2723;
    font-size: 10.5pt;
    outline: 0;
}

QTableWidget::item {
    border-bottom: 1px solid #D5DEDA;
    padding: 10px;
}

QHeaderView::section {
    background: #D9E2DE;
    color: #43534D;
    border: 0;
    border-bottom: 1px solid #BCC9C4;
    padding: 11px;
    font-size: 10pt;
    font-weight: 650;
}

QProgressBar {
    min-height: 11px;
    max-height: 11px;
    border: 0;
    border-radius: 5px;
    background: #CEDBD6;
    text-align: center;
}

QProgressBar::chunk {
    background: #147763;
    border-radius: 5px;
}

QComboBox, QLineEdit {
    min-height: 40px;
    padding: 0 12px;
    background: #EDF2EF;
    border: 1px solid #B8C6C1;
    border-radius: 8px;
    color: #24322D;
    font-size: 10.5pt;
}

QComboBox:hover, QLineEdit:hover, QComboBox:focus, QLineEdit:focus {
    border-color: #5D9385;
}

QCheckBox {
    spacing: 10px;
    color: #24322D;
    font-size: 10.5pt;
}

QCheckBox::indicator {
    width: 22px;
    height: 22px;
    border: 1px solid #91A19B;
    border-radius: 5px;
    background: #EDF2EF;
}

QCheckBox::indicator:checked {
    background: #147763;
    border-color: #147763;
}

QScrollBar:vertical {
    background: transparent;
    width: 13px;
    margin: 2px;
}

QScrollBar::handle:vertical {
    background: #AABAB4;
    min-height: 32px;
    border-radius: 5px;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}

QDialog, QMessageBox {
    background: #E7ECE9;
    color: #1B2723;
    font-size: 10.5pt;
}

QToolTip {
    background: #24352F;
    color: #F0F5F3;
    border: 1px solid #4B655C;
    padding: 7px;
    font-size: 10pt;
}
"""
