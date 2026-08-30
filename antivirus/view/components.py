"""Reusable, intentionally small widgets used by the desktop views."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QSizePolicy,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)


def page_header(title: str, subtitle: str) -> QWidget:
    container = QWidget()
    layout = QVBoxLayout(container)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(4)
    title_label = QLabel(title)
    title_label.setProperty("role", "pageTitle")
    subtitle_label = QLabel(subtitle)
    subtitle_label.setProperty("role", "pageSubtitle")
    subtitle_label.setWordWrap(True)
    layout.addWidget(title_label)
    layout.addWidget(subtitle_label)
    return container


def section_title(text: str) -> QLabel:
    label = QLabel(text)
    label.setProperty("role", "sectionTitle")
    return label


class Card(QFrame):
    def __init__(self, parent=None, object_name: str = "Card"):
        super().__init__(parent)
        self.setObjectName(object_name)


class MetricCard(Card):
    def __init__(self, symbol: str, label: str, value: str = "0", parent=None):
        super().__init__(parent, "MetricCard")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(17, 16, 17, 16)
        layout.setSpacing(13)

        icon = QLabel(symbol, self)
        icon.setProperty("role", "metricIcon")
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon.setFixedSize(40, 40)

        text_layout = QVBoxLayout()
        text_layout.setSpacing(1)
        self.value_label = QLabel(value, self)
        self.value_label.setProperty("role", "metric")
        caption = QLabel(label, self)
        caption.setProperty("role", "metricLabel")
        text_layout.addWidget(self.value_label)
        text_layout.addWidget(caption)
        layout.addWidget(icon)
        layout.addLayout(text_layout, 1)

    def set_value(self, value: object) -> None:
        self.value_label.setText(str(value))


def status_pill(text: str, status: str = "inactive") -> QLabel:
    label = QLabel(text)
    label.setProperty("status", status)
    label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    label.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
    return label


def configure_table(table: QTableWidget) -> None:
    table.setAlternatingRowColors(True)
    table.setShowGrid(False)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.verticalHeader().setVisible(False)
    table.verticalHeader().setDefaultSectionSize(58)
    table.horizontalHeader().setHighlightSections(False)
    table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)


def display_datetime(value: str) -> str:
    if not value:
        return "—"
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo:
            parsed = parsed.astimezone()
        return parsed.strftime("%b %d, %Y  %I:%M %p")
    except (TypeError, ValueError):
        return value


def short_target(value: str, max_length: int = 54) -> str:
    if not value:
        return "—"
    if ", " not in value:
        path = Path(value)
        display = str(path)
    else:
        display = value
    if len(display) <= max_length:
        return display
    return f"…{display[-(max_length - 1):]}"
