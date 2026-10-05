"""Complementary teal/coral visual system over navy and neutral surfaces for Premiere Security."""

from __future__ import annotations

from PySide6.QtGui import QColor, QFont, QPalette
from PySide6.QtWidgets import QApplication

COLORS = {
    "background": "#F1F5F6",
    "surface": "#FFFFFF",
    "surface_alt": "#F1F6F6",
    "nav": "#142E3F",
    "primary": "#0F766E",
    "text": "#173442",
    "muted": "#516774",
    "border": "#CCDADF",
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
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(COLORS["surface_alt"]))
    palette.setColor(QPalette.ColorRole.Text, QColor(COLORS["text"]))
    palette.setColor(QPalette.ColorRole.Button, QColor(COLORS["surface_alt"]))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(COLORS["text"]))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(COLORS["primary"]))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#FFFFFF"))
    application.setPalette(palette)
    application.setStyleSheet(STYLESHEET)


STYLESHEET = """
QMainWindow, QWidget#AppRoot, QStackedWidget#PageStack {
    background: #F1F5F6;
    color: #173442;
}

QWidget#TopBar {
    background: #142E3F;
    border-bottom: 1px solid #2D4B5D;
}

QLabel[role="brandTitle"] {
    color: #F5FAFA;
    font-size: 16px;
    font-weight: 700;
}

QLabel[role="brandSubtitle"] {
    color: #BED0D8;
    font-size: 10.5pt;
}

QLabel[role="pageTitle"] {
    color: #173442;
    font-size: 25px;
    font-weight: 700;
}

QLabel[role="pageSubtitle"] {
    color: #516774;
    font-size: 11pt;
}

QLabel[role="sectionTitle"] {
    color: #173442;
    font-size: 13.5pt;
    font-weight: 650;
}

QLabel[role="cardTitle"] {
    color: #173442;
    font-size: 11.5pt;
    font-weight: 650;
}

QLabel[role="body"], QLabel[role="muted"] {
    color: #516774;
    font-size: 10.5pt;
}

QLabel[role="hint"] {
    color: #546D79;
    font-size: 10pt;
}

QLabel[role="metric"] {
    color: #173442;
    font-size: 25px;
    font-weight: 700;
}

QLabel[role="metricLabel"] {
    color: #516774;
    font-size: 10.5pt;
}

QLabel[role="metricIcon"], QLabel[role="emptyIcon"] {
    background: #DCF2EE;
    color: #115E59;
    border-radius: 10px;
    font-size: 16px;
    font-weight: 700;
}

QLabel[role="emptyTitle"] {
    color: #173442;
    font-size: 13pt;
    font-weight: 650;
}

QFrame#Card, QFrame#MetricCard, QFrame#ScanChoice, QFrame#ProgressCard,
QFrame#EmptyState {
    background: #FFFFFF;
    border: 1px solid #CCDADF;
    border-radius: 14px;
}

QFrame#ScanChoice:hover {
    border: 1px solid #6CA79D;
    background: #F0FAF8;
}

QFrame#ProtectionHero {
    background: #DFF2EE;
    border: 1px solid #A2D1C8;
    border-radius: 16px;
}

QLabel[role="heroIcon"] {
    background: #0F766E;
    color: #FFFFFF;
    border-radius: 25px;
    font-size: 24px;
    font-weight: 700;
}

QLabel[role="heroTitle"] {
    color: #115E59;
    font-size: 18px;
    font-weight: 700;
}

QLabel[role="heroText"] {
    color: #365F5C;
    font-size: 10.5pt;
}

QPushButton {
    min-height: 42px;
    padding: 0 17px;
    border: 1px solid #C8D7DB;
    border-radius: 9px;
    background: #EDF4F5;
    color: #173442;
    font-size: 10.5pt;
    font-weight: 600;
}

QPushButton:hover {
    background: #E1EBEE;
    border-color: #91ABB6;
}

QPushButton:pressed {
    background: #D4E3E7;
}

QPushButton:disabled {
    background: #E5ECEF;
    color: #657D89;
    border-color: #CCDADF;
}

QPushButton[variant="primary"] {
    background: #0F766E;
    border-color: #0F766E;
    color: #FFFFFF;
}

QPushButton[variant="primary"]:hover {
    background: #115E59;
    border-color: #115E59;
}

QPushButton[variant="primary"]:disabled {
    background: #C7DDDA;
    border-color: #ABCCC6;
    color: #526F75;
}

QPushButton[variant="danger"] {
    background: #FBE8E2;
    border-color: #D5A093;
    color: #9D3F32;
}

QPushButton[variant="danger"]:hover {
    background: #F7DBD0;
    border-color: #BC7663;
}

QPushButton[variant="danger"]:disabled {
    background: #E5ECEF;
    border-color: #CCDADF;
    color: #657D89;
}

QPushButton[variant="ghost"] {
    background: transparent;
    border-color: transparent;
    color: #516774;
}

QPushButton[compact="true"] {
    min-height: 34px;
    padding: 0 12px;
    border-radius: 7px;
    font-size: 10pt;
}

QWidget#TopNavigation {
    background: transparent;
}

QPushButton[nav="true"] {
    min-width: 92px;
    max-width: 108px;
    min-height: 42px;
    max-height: 42px;
    padding: 0 10px;
    border: 0;
    border-radius: 9px;
    background: transparent;
    color: #D0E0E7;
    font-size: 10.5pt;
    font-weight: 600;
}

QPushButton[nav="true"]:hover {
    background: #244757;
    color: #F5FAFA;
}

QPushButton[nav="true"]:checked {
    background: #0F766E;
    color: #FFFFFF;
}

QPushButton[toggle="true"] {
    min-width: 76px;
    max-width: 76px;
    min-height: 36px;
    max-height: 36px;
    padding: 0;
    border: 1px solid #C8D7DB;
    border-radius: 18px;
    background: #E4EEF0;
    color: #516774;
    font-size: 10pt;
    font-weight: 700;
}

QPushButton[toggle="true"]:hover {
    border-color: #6CA79D;
}

QPushButton[toggle="true"]:checked {
    background: #0F766E;
    border-color: #0F766E;
    color: #FFFFFF;
}

QLabel[status="active"] {
    color: #115E59;
    background: #DCF2EE;
    border: 1px solid #A2D1C8;
    border-radius: 9px;
    padding: 4px 10px;
    font-size: 10pt;
    font-weight: 600;
}

QLabel[status="inactive"] {
    color: #516774;
    background: #EDF3F4;
    border: 1px solid #C8D7DB;
    border-radius: 9px;
    padding: 4px 10px;
    font-size: 10pt;
    font-weight: 600;
}

QLabel[status="warning"] {
    color: #7C4A14;
    background: #FFF0D6;
    border: 1px solid #D9BA7E;
    border-radius: 9px;
    padding: 4px 10px;
    font-size: 10pt;
    font-weight: 600;
}

QLabel[status="danger"] {
    color: #9D3F32;
    background: #FBE8E2;
    border: 1px solid #D5A093;
    border-radius: 9px;
    padding: 4px 10px;
    font-size: 10pt;
    font-weight: 600;
}

QTableWidget {
    background: #FFFFFF;
    alternate-background-color: #F2F7F8;
    border: 1px solid #CCDADF;
    border-radius: 11px;
    gridline-color: transparent;
    selection-background-color: #CDEBE5;
    selection-color: #173442;
    font-size: 10.5pt;
    outline: 0;
}

QTableWidget::item {
    border-bottom: 1px solid #E1EAEE;
    padding: 10px;
}

QHeaderView::section {
    background: #E4EDF0;
    color: #405F6C;
    border: 0;
    border-bottom: 1px solid #C8D7DB;
    padding: 11px;
    font-size: 10pt;
    font-weight: 650;
}

QProgressBar {
    min-height: 11px;
    max-height: 11px;
    border: 0;
    border-radius: 5px;
    background: #D4E4E8;
    text-align: center;
}

QProgressBar::chunk {
    background: #0F766E;
    border-radius: 5px;
}

QComboBox, QLineEdit {
    min-height: 40px;
    padding: 0 12px;
    background: #FFFFFF;
    border: 1px solid #C8D7DB;
    border-radius: 8px;
    color: #173442;
    font-size: 10.5pt;
}

QComboBox:hover, QLineEdit:hover, QComboBox:focus, QLineEdit:focus {
    border-color: #0F766E;
}

QScrollBar:vertical {
    background: transparent;
    width: 13px;
    margin: 2px;
}

QScrollBar::handle:vertical {
    background: #9BB3BD;
    min-height: 32px;
    border-radius: 5px;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}

QDialog, QMessageBox {
    background: #F7FAFA;
    color: #173442;
    font-size: 10.5pt;
}

QToolTip {
    background: #142E3F;
    color: #F5FAFA;
    border: 1px solid #446675;
    padding: 7px;
    font-size: 10pt;
}
"""

STYLESHEET += """
QPushButton:focus, QComboBox:focus, QLineEdit:focus { border: 2px solid #C4775F; }
QStatusBar { background: #142E3F; color: #D0E0E7; padding: 4px 10px; }
QScrollArea { background: transparent; border: 0; }
"""
