"""Native vector radar driven by scan state, with a reduced-motion option."""

from __future__ import annotations

import math
from time import monotonic

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer
from PySide6.QtGui import QColor, QConicalGradient, QPainter, QPen, QFont
from PySide6.QtWidgets import QWidget
from antivirus.view.theme import COLORS


class ScanRadar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(154, 154)
        self.setAccessibleName("File scan activity radar")
        self.setToolTip(
            "Scan activity indicator. Dots are decorative; file findings appear in Results."
        )
        self.state = "idle"
        self.reduced_motion = False
        self._started = monotonic()
        self._timer = QTimer(self)
        self._timer.setInterval(33)
        self._timer.timeout.connect(self.update)

    def set_state(self, state):
        self.state = state
        self._started = monotonic()
        self.setAccessibleDescription(f"Scan state: {state}")
        self._sync_timer()
        self.update()

    def set_reduced_motion(self, enabled):
        self.reduced_motion = bool(enabled)
        self._sync_timer()
        self.update()

    def _sync_timer(self):
        if self.state == "scanning" and not self.reduced_motion and self.isVisible():
            self._timer.start()
        else:
            self._timer.stop()

    def showEvent(self, event):
        super().showEvent(event)
        self._sync_timer()

    def hideEvent(self, event):
        self._timer.stop()
        super().hideEvent(event)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.translate(self.width() / 2, self.height() / 2)
        radius = min(self.width(), self.height()) / 2 - 7
        painter.setBrush(QColor(COLORS["background"]))
        painter.setPen(QPen(QColor(COLORS["border"]), 1))
        painter.drawEllipse(QPointF(0, 0), radius, radius)
        for fraction in (0.25, 0.5, 0.75, 1):
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawEllipse(QPointF(0, 0), radius * fraction, radius * fraction)
        for angle in range(0, 360, 45):
            radians = math.radians(angle)
            painter.drawLine(
                QPointF(0, 0),
                QPointF(radius * math.cos(radians), radius * math.sin(radians)),
            )
        scanning = self.state == "scanning"
        angle = (
            ((monotonic() - self._started) * 90) % 360
            if scanning and not self.reduced_motion
            else 45
        )
        if scanning:
            gradient = QConicalGradient(QPointF(0, 0), -angle)
            sweep = QColor(COLORS["signal"])
            sweep.setAlpha(165)
            gradient.setColorAt(0.0, sweep)
            sweep.setAlpha(0)
            gradient.setColorAt(0.23, sweep)
            gradient.setColorAt(1.0, sweep)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(gradient)
            painter.drawEllipse(QPointF(0, 0), radius - 1, radius - 1)
            painter.setPen(QPen(QColor(COLORS["highlight"]), 2))
            radians = math.radians(angle)
            painter.drawLine(
                QPointF(0, 0),
                QPointF(
                    (radius - 2) * math.cos(radians), (radius - 2) * math.sin(radians)
                ),
            )
            painter.setPen(Qt.PenStyle.NoPen)
            for x, y in ((22, -25), (-33, 9), (16, 45)):
                painter.setBrush(QColor(COLORS["accent"]))
                painter.drawEllipse(QPointF(x, y), 3, 3)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(
            QColor(
                COLORS["highlight"]
                if self.state in ("scanning", "complete")
                else COLORS["accent"]
            )
        )
        painter.drawEllipse(QPointF(0, 0), 4, 4)
        if self.state != "scanning":
            painter.setBrush(QColor(COLORS["background"]))
            painter.drawEllipse(QPointF(0, 0), 19, 19)
            painter.setPen(
                QColor(
                    COLORS["highlight"]
                    if self.state == "complete"
                    else COLORS["accent"]
                )
            )
            font = QFont("Segoe UI", 19)
            painter.setFont(font)
            symbol = {"complete": "✓", "error": "!", "cancelled": "■"}.get(
                self.state, "·"
            )
            painter.drawText(
                QRectF(-20, -21, 40, 42), Qt.AlignmentFlag.AlignCenter, symbol
            )
        painter.end()
