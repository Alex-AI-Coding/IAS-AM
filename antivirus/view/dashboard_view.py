"""Overview dashboard for protection state and recent scan activity."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from antivirus.view.components import (
    Card,
    MetricCard,
    configure_table,
    display_datetime,
    page_header,
    section_title,
    status_pill,
)


class DashboardView(QWidget):
    start_scan = Signal()
    open_history = Signal()

    ENGINE_COPY = {
        "hash": ("Known-file hashes", "Checks files against the local threat catalog"),
        "yara": ("YARA signatures", "Finds educational malware patterns and behaviors"),
        "clamav": ("ClamAV", "Uses the local ClamAV service when installed"),
        "virustotal": ("VirusTotal", "Optional online hash reputation lookup"),
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 27, 30, 26)
        layout.setSpacing(18)
        layout.addWidget(
            page_header(
                "Dashboard",
                "A clear view of your scanner, recent activity, and local protection engines.",
            )
        )

        hero = QFrame(self)
        hero.setObjectName("ProtectionHero")
        hero_layout = QHBoxLayout(hero)
        hero_layout.setContentsMargins(22, 20, 22, 20)
        hero_layout.setSpacing(16)
        icon = QLabel("✓", hero)
        icon.setProperty("role", "heroIcon")
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon.setFixedSize(50, 50)
        hero_text = QVBoxLayout()
        hero_text.setSpacing(4)
        self.protection_title = QLabel("Scanner is ready", hero)
        self.protection_title.setProperty("role", "heroTitle")
        self.protection_detail = QLabel(
            "Local detection is active. Run a scan whenever you want to check a file or folder.",
            hero,
        )
        self.protection_detail.setProperty("role", "heroText")
        self.protection_detail.setWordWrap(True)
        hero_text.addWidget(self.protection_title)
        hero_text.addWidget(self.protection_detail)
        quick_button = QPushButton("Run quick scan", hero)
        quick_button.setProperty("variant", "primary")
        quick_button.clicked.connect(self.start_scan)
        hero_layout.addWidget(icon)
        hero_layout.addLayout(hero_text, 1)
        hero_layout.addWidget(quick_button)
        layout.addWidget(hero)

        metrics = QHBoxLayout()
        metrics.setSpacing(13)
        self.total_scans = MetricCard("S", "Total scans")
        self.files_scanned = MetricCard("F", "Files scanned")
        self.clean_files = MetricCard("✓", "Clean files")
        self.threats_found = MetricCard("!", "Threats found")
        for card in (
            self.total_scans,
            self.files_scanned,
            self.clean_files,
            self.threats_found,
        ):
            metrics.addWidget(card, 1)
        layout.addLayout(metrics)

        lower = QHBoxLayout()
        lower.setSpacing(14)
        engines_card = Card(self)
        engines_layout = QVBoxLayout(engines_card)
        engines_layout.setContentsMargins(19, 17, 19, 16)
        engines_layout.setSpacing(8)
        engines_layout.addWidget(section_title("Protection engines"))
        self.engine_status_labels: dict[str, QLabel] = {}
        for key, (name, description) in self.ENGINE_COPY.items():
            row = QWidget(engines_card)
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(0, 7, 0, 7)
            row_layout.setSpacing(10)
            name_layout = QVBoxLayout()
            name_layout.setSpacing(1)
            name_label = QLabel(name, row)
            name_label.setProperty("role", "cardTitle")
            detail_label = QLabel(description, row)
            detail_label.setProperty("role", "hint")
            detail_label.setWordWrap(True)
            name_layout.addWidget(name_label)
            name_layout.addWidget(detail_label)
            pill = status_pill("Checking…")
            self.engine_status_labels[key] = pill
            row_layout.addLayout(name_layout, 1)
            row_layout.addWidget(pill)
            engines_layout.addWidget(row)
        lower.addWidget(engines_card, 5)

        activity_card = Card(self)
        activity_layout = QVBoxLayout(activity_card)
        activity_layout.setContentsMargins(19, 17, 19, 16)
        activity_layout.setSpacing(11)
        activity_header = QHBoxLayout()
        activity_header.addWidget(section_title("Recent activity"))
        activity_header.addStretch()
        history_button = QPushButton("View all", activity_card)
        history_button.setProperty("variant", "ghost")
        history_button.setProperty("compact", True)
        history_button.clicked.connect(self.open_history)
        activity_header.addWidget(history_button)
        activity_layout.addLayout(activity_header)
        self.activity_table = QTableWidget(0, 3, activity_card)
        self.activity_table.setHorizontalHeaderLabels(["When", "Scan", "Result"])
        configure_table(self.activity_table)
        self.activity_table.horizontalHeader().setStretchLastSection(True)
        self.activity_table.setMinimumHeight(205)
        self.activity_empty = QLabel(
            "No scans yet. Your first result will appear here."
        )
        self.activity_empty.setProperty("role", "muted")
        self.activity_empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        activity_layout.addWidget(self.activity_table, 1)
        activity_layout.addWidget(self.activity_empty)
        lower.addWidget(activity_card, 4)
        layout.addLayout(lower, 1)

    def update_dashboard(self, statistics, recent_scans, engine_states):
        self.total_scans.set_value(statistics.get("total_scans", 0))
        self.files_scanned.set_value(statistics.get("files_scanned", 0))
        self.clean_files.set_value(statistics.get("clean_files", 0))
        self.threats_found.set_value(statistics.get("threats_found", 0))

        if recent_scans:
            last = recent_scans[0]
            self.protection_detail.setText(
                f"Last scan: {display_datetime(last.get('completed_at', ''))}. "
                "Local detection is ready for another check."
            )
        else:
            self.protection_detail.setText(
                "Local detection is active. Run a scan whenever you want to check a file or folder."
            )

        for key, label in self.engine_status_labels.items():
            state = engine_states.get(key, {})
            enabled = bool(state.get("enabled"))
            available = bool(state.get("available"))
            if not available and key == "clamav":
                text, status = "Not installed", "warning"
            elif not available and key == "virustotal":
                text, status = "Key needed", "warning"
            elif not available:
                text, status = "Unavailable", "warning"
            elif enabled:
                text, status = "Active", "active"
            else:
                text, status = "Off", "inactive"
            label.setText(text)
            label.setProperty("status", status)
            label.style().unpolish(label)
            label.style().polish(label)

        self.activity_table.setRowCount(0)
        for record in recent_scans[:4]:
            row = self.activity_table.rowCount()
            self.activity_table.insertRow(row)
            status = record.get("status", "unknown").title()
            values = [
                display_datetime(record.get("started_at", "")),
                record.get("scan_type", "custom").title(),
                status,
            ]
            for column, value in enumerate(values):
                self.activity_table.setItem(row, column, QTableWidgetItem(str(value)))
        has_activity = bool(recent_scans)
        self.activity_table.setVisible(has_activity)
        self.activity_empty.setVisible(not has_activity)
