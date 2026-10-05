"""Premiere Security logo widgets and window icon."""

from __future__ import annotations

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap
from PySide6.QtWidgets import QWidget


def _draw_shield(painter: QPainter) -> None:
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)

    shield = QPainterPath()
    shield.moveTo(23, 4)
    shield.lineTo(39, 10)
    shield.lineTo(37, 27)
    shield.cubicTo(36, 35, 30, 40, 23, 43)
    shield.cubicTo(16, 40, 10, 35, 9, 27)
    shield.lineTo(7, 10)
    shield.closeSubpath()
    painter.fillPath(shield, QColor("#5EE4C1"))

    check = QPainterPath(QPointF(15, 23))
    check.lineTo(21, 29)
    check.lineTo(32, 17)
    painter.setPen(QPen(QColor("#F0F5F3"), 3.1, Qt.PenStyle.SolidLine))
    painter.drawPath(check)


class AppLogo(QWidget):
    """A shield mark that reads as application branding, not a user profile."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(46, 46)
        self.setAccessibleName("Premiere Security shield logo")
        self.setToolTip("Premiere Security")

    def paintEvent(self, event):
        painter = QPainter(self)
        _draw_shield(painter)


def create_app_icon() -> QIcon:
    """Create the same shield mark for the window and taskbar."""

    pixmap = QPixmap(64, 64)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.scale(64 / 46, 64 / 46)
    _draw_shield(painter)
    painter.end()
    return QIcon(pixmap)
