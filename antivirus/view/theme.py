"""Ocean palette from the user's reference, shared by every widget and status."""

from string import Template
from PySide6.QtGui import QColor, QFont, QPalette
from PySide6.QtWidgets import QApplication

COLORS = {
    "background": "#031716",
    "surface": "#032F30",
    "surface_alt": "#0A3D40",
    "nav": "#031716",
    "primary": "#0A7075",
    "signal": "#0C969C",
    "accent": "#6BA3BE",
    "border": "#274D60",
    "text": "#E6F4F4",
    "muted": "#A8C8CE",
    "disabled": "#708E96",
    "highlight": "#89DDE0",
    "danger": "#FFB4AB",
    "danger_bg": "#472E33",
    "warning": "#F0D391",
    "warning_bg": "#3D3828",
    "white": "#FFFFFF",
}


def status_color(status):
    return COLORS[
        {
            "clean": "highlight",
            "detected": "danger",
            "error": "warning",
            "partial": "warning",
            "cancelled": "accent",
        }.get(status, "muted")
    ]


def apply_theme(application: QApplication) -> None:
    application.setStyle("Fusion")
    font = QFont("Segoe UI")
    font.setPointSizeF(11.0)
    application.setFont(font)
    palette = QPalette()
    roles = {
        QPalette.ColorRole.Window: "background",
        QPalette.ColorRole.WindowText: "text",
        QPalette.ColorRole.Base: "surface",
        QPalette.ColorRole.AlternateBase: "surface_alt",
        QPalette.ColorRole.Text: "text",
        QPalette.ColorRole.Button: "surface_alt",
        QPalette.ColorRole.ButtonText: "text",
        QPalette.ColorRole.Highlight: "primary",
        QPalette.ColorRole.HighlightedText: "white",
        QPalette.ColorRole.ToolTipBase: "surface",
        QPalette.ColorRole.ToolTipText: "text",
        QPalette.ColorRole.PlaceholderText: "muted",
        QPalette.ColorRole.Light: "accent",
        QPalette.ColorRole.Mid: "border",
        QPalette.ColorRole.Dark: "background",
        QPalette.ColorRole.Link: "highlight",
    }
    for role, name in roles.items():
        palette.setColor(role, QColor(COLORS[name]))
    for role in (
        QPalette.ColorRole.Text,
        QPalette.ColorRole.WindowText,
        QPalette.ColorRole.ButtonText,
    ):
        palette.setColor(QPalette.ColorGroup.Disabled, role, QColor(COLORS["disabled"]))
    application.setPalette(palette)
    application.setStyleSheet(STYLESHEET)


STYLESHEET = Template("""
QMainWindow, QWidget#AppRoot, QStackedWidget#PageStack {
    background: $background; color: $text;
}
QWidget#TopBar { background: $nav; border-bottom: 1px solid $border; }
QLabel { color: $text; }
QLabel[role="brandTitle"] { color: $white; font-size: 18px; font-weight: 700; }
QLabel[role="brandSubtitle"] { color: $accent; font-size: 10pt; }
QLabel[role="pageTitle"] { color: $text; font-size: 25px; font-weight: 700; }
QLabel[role="pageSubtitle"] { color: $muted; font-size: 11pt; }
QLabel[role="sectionTitle"] { color: $text; font-size: 13.5pt; font-weight: 650; }
QLabel[role="cardTitle"] { color: $text; font-size: 11.5pt; font-weight: 650; }
QLabel[role="body"], QLabel[role="muted"], QLabel[role="metricLabel"] {
    color: $muted; font-size: 10.5pt;
}
QLabel[role="hint"] { color: $muted; font-size: 10pt; }
QLabel[role="metric"] { color: $text; font-size: 25px; font-weight: 700; }
QLabel[role="metricIcon"], QLabel[role="emptyIcon"] {
    background: $surface_alt; color: $highlight; border: 1px solid $border;
    border-radius: 10px; font-size: 16px; font-weight: 700;
}
QLabel[role="emptyTitle"] { color: $text; font-size: 13pt; font-weight: 650; }
QFrame#Card, QFrame#MetricCard, QFrame#ScanChoice, QFrame#ProgressCard, QFrame#EmptyState {
    background: $surface; border: 1px solid $border; border-radius: 14px;
}
QFrame#ScanChoice:hover { border: 1px solid $signal; background: $surface_alt; }
QFrame#ProtectionHero { background: $surface_alt; border: 1px solid $primary; border-radius: 16px; }
QLabel[role="heroIcon"] {
    background: $primary; color: $white; border-radius: 25px; font-size: 24px; font-weight: 700;
}
QLabel[role="heroTitle"] { color: $highlight; font-size: 18px; font-weight: 700; }
QLabel[role="heroText"] { color: $muted; font-size: 10.5pt; }
QPushButton {
    min-height: 42px; padding: 0 17px; border: 1px solid $border; border-radius: 9px;
    background: $surface_alt; color: $text; font-size: 10.5pt; font-weight: 600;
}
QPushButton:hover { background: $border; border-color: $accent; }
QPushButton:pressed { background: $primary; }
QPushButton:disabled { background: $surface; color: $disabled; border-color: $border; }
QPushButton[variant="primary"] { background: $primary; border-color: $primary; color: $white; }
QPushButton[variant="primary"]:hover { background: $signal; color: $background; border-color: $signal; }
QPushButton[variant="primary"]:disabled { background: $surface_alt; color: $disabled; border-color: $border; }
QPushButton[variant="danger"] { background: $danger_bg; border-color: $danger; color: $danger; }
QPushButton[variant="danger"]:hover { background: $danger; color: $background; }
QPushButton[variant="danger"]:disabled { background: $surface; color: $disabled; border-color: $border; }
QPushButton[variant="ghost"] { background: transparent; border-color: transparent; color: $accent; }
QPushButton[compact="true"] { min-height: 34px; padding: 0 12px; border-radius: 7px; font-size: 10pt; }
QWidget#TopNavigation { background: transparent; }
QPushButton[nav="true"] {
    min-width: 80px; min-height: 40px; max-height: 40px; padding: 0 8px;
    border: 1px solid transparent; border-radius: 9px; background: transparent;
    color: $muted; font-size: 10.5pt; font-weight: 600;
}
QPushButton[nav="true"]:hover { background: $surface_alt; color: $white; }
QPushButton[nav="true"]:checked { background: $primary; color: $white; }
QPushButton[toggle="true"] {
    min-width: 76px; max-width: 76px; min-height: 36px; max-height: 36px; padding: 0;
    border: 1px solid $border; border-radius: 18px; background: $surface_alt;
    color: $muted; font-size: 10pt; font-weight: 700;
}
QPushButton[toggle="true"]:hover { border-color: $signal; }
QPushButton[toggle="true"]:checked { background: $primary; border-color: $signal; color: $white; }
QLabel[status="active"], QLabel[status="inactive"], QLabel[status="warning"], QLabel[status="danger"] {
    border: 1px solid $border; border-radius: 9px; padding: 4px 10px; font-size: 10pt; font-weight: 600;
}
QLabel[status="active"] { color: $highlight; background: $surface_alt; border-color: $primary; }
QLabel[status="inactive"] { color: $muted; background: $surface; }
QLabel[status="warning"] { color: $warning; background: $warning_bg; border-color: $warning; }
QLabel[status="danger"] { color: $danger; background: $danger_bg; border-color: $danger; }
QTableWidget {
    background: $surface; color: $text; alternate-background-color: $surface_alt;
    border: 1px solid $border; border-radius: 11px; gridline-color: transparent;
    selection-background-color: $border; selection-color: $white; font-size: 10.5pt; outline: 0;
}
QTableWidget::item { border-bottom: 1px solid $border; padding: 10px; }
QHeaderView::section {
    background: $border; color: $text; border: 0; border-bottom: 1px solid $accent;
    padding: 11px; font-size: 10pt; font-weight: 650;
}
QTableCornerButton::section { background: $border; border: 0; }
QProgressBar {
    min-height: 11px; max-height: 11px; border: 0; border-radius: 5px; background: $border; text-align: center;
}
QProgressBar::chunk { background: $signal; border-radius: 5px; }
QComboBox, QLineEdit, QTextEdit, QPlainTextEdit {
    min-height: 40px; padding: 0 12px; background: $surface; border: 1px solid $border;
    border-radius: 8px; color: $text; selection-background-color: $primary; font-size: 10.5pt;
}
QComboBox:hover, QLineEdit:hover { border-color: $signal; }
QComboBox QAbstractItemView, QMenu {
    background: $surface; color: $text; border: 1px solid $accent;
    selection-background-color: $primary; selection-color: $white;
}
QScrollBar:vertical { background: $background; width: 13px; margin: 2px; }
QScrollBar:horizontal { background: $background; height: 13px; margin: 2px; }
QScrollBar::handle:vertical { background: $border; min-height: 32px; border-radius: 5px; }
QScrollBar::handle:horizontal { background: $border; min-width: 32px; border-radius: 5px; }
QScrollBar::handle:hover { background: $accent; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
QDialog, QMessageBox { background: $background; color: $text; font-size: 10.5pt; }
QToolTip { background: $surface; color: $text; border: 1px solid $accent; padding: 7px; font-size: 10pt; }
QPushButton:focus, QComboBox:focus, QLineEdit:focus { border: 2px solid $accent; }
QStatusBar { background: $nav; color: $muted; padding: 4px 10px; }
QScrollArea { background: transparent; border: 0; }
""").substitute(COLORS)
