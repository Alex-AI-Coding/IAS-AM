"""Warm, low-glare visual system for Premiere Security."""

from __future__ import annotations

from PySide6.QtGui import QColor, QFont, QPalette
from PySide6.QtWidgets import QApplication


COLORS = {
    "background": "#DCD3C6",
    "surface": "#E9E2D8",
    "surface_alt": "#E3DBD0",
    "nav": "#263A33",
    "primary": "#2E7462",
    "text": "#27302C",
    "muted": "#5F655F",
    "border": "#BFB5A8",
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
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#F4EFE7"))
    application.setPalette(palette)
    application.setStyleSheet(STYLESHEET)


STYLESHEET = """
QMainWindow, QWidget#AppRoot, QStackedWidget#PageStack {
    background: #DCD3C6;
    color: #27302C;
}

QWidget#TopBar {
    background: #263A33;
    border-bottom: 1px solid #43574F;
}

QLabel[role="brandTitle"] {
    color: #F2ECE3;
    font-size: 16px;
    font-weight: 700;
}

QLabel[role="brandSubtitle"] {
    color: #C2C9C3;
    font-size: 10.5pt;
}

QLabel[role="pageTitle"] {
    color: #27302C;
    font-size: 25px;
    font-weight: 700;
}

QLabel[role="pageSubtitle"] {
    color: #5F655F;
    font-size: 11pt;
}

QLabel[role="sectionTitle"] {
    color: #303833;
    font-size: 13.5pt;
    font-weight: 650;
}

QLabel[role="cardTitle"] {
    color: #303833;
    font-size: 11.5pt;
    font-weight: 650;
}

QLabel[role="body"], QLabel[role="muted"] {
    color: #5F655F;
    font-size: 10.5pt;
}

QLabel[role="hint"] {
    color: #696D67;
    font-size: 10pt;
}

QLabel[role="metric"] {
    color: #27302C;
    font-size: 25px;
    font-weight: 700;
}

QLabel[role="metricLabel"] {
    color: #5F655F;
    font-size: 10.5pt;
}

QLabel[role="metricIcon"], QLabel[role="emptyIcon"] {
    background: #D1DDD4;
    color: #245F50;
    border-radius: 10px;
    font-size: 16px;
    font-weight: 700;
}

QLabel[role="emptyTitle"] {
    color: #303833;
    font-size: 13pt;
    font-weight: 650;
}

QFrame#Card, QFrame#MetricCard, QFrame#ScanChoice, QFrame#ProgressCard,
QFrame#EmptyState {
    background: #E9E2D8;
    border: 1px solid #BFB5A8;
    border-radius: 14px;
}

QFrame#ScanChoice:hover {
    border: 1px solid #819A8F;
    background: #E4DDD2;
}

QFrame#ProtectionHero {
    background: #D3DDD1;
    border: 1px solid #AEBBAE;
    border-radius: 16px;
}

QLabel[role="heroIcon"] {
    background: #2E7462;
    color: #F4EFE7;
    border-radius: 25px;
    font-size: 24px;
    font-weight: 700;
}

QLabel[role="heroTitle"] {
    color: #294B40;
    font-size: 18px;
    font-weight: 700;
}

QLabel[role="heroText"] {
    color: #4F665D;
    font-size: 10.5pt;
}

QPushButton {
    min-height: 42px;
    padding: 0 17px;
    border: 1px solid #B9AFA2;
    border-radius: 9px;
    background: #E2DACE;
    color: #303833;
    font-size: 10.5pt;
    font-weight: 600;
}

QPushButton:hover {
    background: #D9D0C4;
    border-color: #9F9487;
}

QPushButton:pressed {
    background: #CFC5B8;
}

QPushButton:disabled {
    background: #D9D1C6;
    color: #88877F;
    border-color: #C8BFB4;
}

QPushButton[variant="primary"] {
    background: #2E7462;
    border-color: #2E7462;
    color: #F4EFE7;
}

QPushButton[variant="primary"]:hover {
    background: #255F51;
    border-color: #255F51;
}

QPushButton[variant="primary"]:disabled {
    background: #BFC5BC;
    border-color: #B2B8AF;
    color: #777C75;
}

QPushButton[variant="danger"] {
    background: #E5D4CF;
    border-color: #C99E96;
    color: #903D36;
}

QPushButton[variant="danger"]:hover {
    background: #DDC8C2;
    border-color: #B9847B;
}

QPushButton[variant="danger"]:disabled {
    background: #D9D1C6;
    border-color: #C8BFB4;
    color: #88877F;
}

QPushButton[variant="ghost"] {
    background: transparent;
    border-color: transparent;
    color: #515B55;
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
    color: #D5DAD6;
    font-size: 10.5pt;
    font-weight: 600;
}

QPushButton[nav="true"]:hover {
    background: #344D44;
    color: #F2ECE3;
}

QPushButton[nav="true"]:checked {
    background: #496B60;
    color: #F6F1E9;
}

QPushButton[toggle="true"] {
    min-width: 76px;
    max-width: 76px;
    min-height: 36px;
    max-height: 36px;
    padding: 0;
    border: 1px solid #B2A99D;
    border-radius: 18px;
    background: #D8D0C5;
    color: #5C625D;
    font-size: 10pt;
    font-weight: 700;
}

QPushButton[toggle="true"]:hover {
    border-color: #7C9489;
}

QPushButton[toggle="true"]:checked {
    background: #2E7462;
    border-color: #2E7462;
    color: #F4EFE7;
}

QLabel[status="active"] {
    color: #285D37;
    background: #D4DFD1;
    border: 1px solid #A8BEA6;
    border-radius: 9px;
    padding: 4px 10px;
    font-size: 10pt;
    font-weight: 600;
}

QLabel[status="inactive"] {
    color: #5A605B;
    background: #DDD6CC;
    border: 1px solid #BEB5A9;
    border-radius: 9px;
    padding: 4px 10px;
    font-size: 10pt;
    font-weight: 600;
}

QLabel[status="warning"] {
    color: #76520F;
    background: #E8D8B9;
    border: 1px solid #CCAE71;
    border-radius: 9px;
    padding: 4px 10px;
    font-size: 10pt;
    font-weight: 600;
}

QLabel[status="danger"] {
    color: #893C36;
    background: #E3CDC8;
    border: 1px solid #C69B94;
    border-radius: 9px;
    padding: 4px 10px;
    font-size: 10pt;
    font-weight: 600;
}

QTableWidget {
    background: #E9E2D8;
    alternate-background-color: #E1D9CE;
    border: 1px solid #BFB5A8;
    border-radius: 11px;
    gridline-color: transparent;
    selection-background-color: #CBD8CF;
    selection-color: #27302C;
    font-size: 10.5pt;
    outline: 0;
}

QTableWidget::item {
    border-bottom: 1px solid #D1C7BA;
    padding: 10px;
}

QHeaderView::section {
    background: #D6CEC2;
    color: #48504B;
    border: 0;
    border-bottom: 1px solid #B7AC9F;
    padding: 11px;
    font-size: 10pt;
    font-weight: 650;
}

QProgressBar {
    min-height: 11px;
    max-height: 11px;
    border: 0;
    border-radius: 5px;
    background: #C8C1B6;
    text-align: center;
}

QProgressBar::chunk {
    background: #2E7462;
    border-radius: 5px;
}

QComboBox, QLineEdit {
    min-height: 40px;
    padding: 0 12px;
    background: #E9E2D8;
    border: 1px solid #B9AFA2;
    border-radius: 8px;
    color: #303833;
    font-size: 10.5pt;
}

QComboBox:hover, QLineEdit:hover, QComboBox:focus, QLineEdit:focus {
    border-color: #66877B;
}

QScrollBar:vertical {
    background: transparent;
    width: 13px;
    margin: 2px;
}

QScrollBar::handle:vertical {
    background: #A69D91;
    min-height: 32px;
    border-radius: 5px;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}

QDialog, QMessageBox {
    background: #E5DDD2;
    color: #27302C;
    font-size: 10.5pt;
}

QToolTip {
    background: #30443D;
    color: #F2ECE3;
    border: 1px solid #596E66;
    padding: 7px;
    font-size: 10pt;
}
"""
