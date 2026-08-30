"""Detection-engine and privacy settings."""

from __future__ import annotations

from PySide6.QtCore import QSettings, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from antivirus.view.components import Card, page_header, section_title, status_pill


class SettingRow(QFrame):
    def __init__(self, key, title, description, checked, parent=None):
        super().__init__(parent)
        self.key = key
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 11, 0, 11)
        layout.setSpacing(12)
        text = QVBoxLayout()
        text.setSpacing(2)
        title_label = QLabel(title, self)
        title_label.setProperty("role", "cardTitle")
        description_label = QLabel(description, self)
        description_label.setProperty("role", "muted")
        description_label.setWordWrap(True)
        text.addWidget(title_label)
        text.addWidget(description_label)
        self.state_label = status_pill(
            "Enabled" if checked else "Off", "active" if checked else "inactive"
        )
        self.checkbox = QCheckBox(self)
        self.checkbox.setChecked(checked)
        self.checkbox.toggled.connect(self._toggle_display)
        layout.addLayout(text, 1)
        layout.addWidget(self.state_label)
        layout.addWidget(self.checkbox)

    def _toggle_display(self, checked):
        self.state_label.setText("Enabled" if checked else "Off")
        self.state_label.setProperty("status", "active" if checked else "inactive")
        self.state_label.style().unpolish(self.state_label)
        self.state_label.style().polish(self.state_label)

    def set_availability(self, available: bool, unavailable_text: str):
        if available:
            self.checkbox.setEnabled(True)
            self._toggle_display(self.checkbox.isChecked())
        else:
            self.checkbox.blockSignals(True)
            self.checkbox.setChecked(False)
            self.checkbox.blockSignals(False)
            self.checkbox.setEnabled(False)
            self.state_label.setText(unavailable_text)
            self.state_label.setProperty("status", "warning")
            self.state_label.style().unpolish(self.state_label)
            self.state_label.style().polish(self.state_label)


class SettingsView(QWidget):
    setting_changed = Signal(str, bool)

    SETTINGS = (
        (
            "hash_detection_enabled",
            "Known-file hash detection",
            "Compares SHA-256 hashes against the local threat database.",
            True,
        ),
        (
            "yara_enabled",
            "YARA signature detection",
            "Uses the included educational rules for trojan, ransomware, worm, and spyware patterns.",
            True,
        ),
        (
            "clamav_enabled",
            "ClamAV integration",
            "Adds scanning from a locally running ClamAV service when available.",
            True,
        ),
        (
            "virustotal_enabled",
            "VirusTotal reputation",
            "Sends only the file hash—not file contents—to VirusTotal when explicitly enabled.",
            False,
        ),
    )

    def __init__(self, parent=None):
        super().__init__(parent)
        self.settings = QSettings("IAS", "PremiereSecurity")
        self.rows: dict[str, SettingRow] = {}
        self._saved_values: dict[str, bool] = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 27, 30, 26)
        layout.setSpacing(16)

        heading = QHBoxLayout()
        heading.addWidget(
            page_header(
                "Settings",
                "Choose which detection engines participate in future scans, then save your changes.",
            ),
            1,
        )
        reset_button = QPushButton("Restore defaults", self)
        reset_button.clicked.connect(self.restore_defaults)
        heading.addWidget(reset_button)
        layout.addLayout(heading)

        engines = Card(self)
        engines_layout = QVBoxLayout(engines)
        engines_layout.setContentsMargins(20, 18, 20, 18)
        engines_layout.setSpacing(2)
        engines_layout.addWidget(section_title("Detection engines"))
        for key, title, description, default in self.SETTINGS:
            checked = self.settings.value(key, default, type=bool)
            self._saved_values[key] = checked
            row = SettingRow(key, title, description, checked, engines)
            row.checkbox.toggled.connect(lambda _checked: self._update_dirty_state())
            self.rows[key] = row
            engines_layout.addWidget(row)
        layout.addWidget(engines)

        privacy = Card(self)
        privacy_layout = QVBoxLayout(privacy)
        privacy_layout.setContentsMargins(20, 17, 20, 17)
        privacy_layout.setSpacing(7)
        privacy_layout.addWidget(section_title("Privacy and storage"))
        privacy_text = QLabel(
            "Scans run locally by default. History contains summary information only, "
            "and file contents are not stored by the application. VirusTotal is the only "
            "online option and requires a VIRUSTOTAL_API_KEY in the project .env file.",
            privacy,
        )
        privacy_text.setProperty("role", "muted")
        privacy_text.setWordWrap(True)
        privacy_layout.addWidget(privacy_text)
        layout.addWidget(privacy)

        actions = QHBoxLayout()
        actions.setSpacing(10)
        self.unsaved_label = QLabel("All changes saved", self)
        self.unsaved_label.setProperty("role", "muted")
        self.discard_button = QPushButton("Discard changes", self)
        self.discard_button.clicked.connect(lambda: self.discard_changes())
        self.save_button = QPushButton("Save changes", self)
        self.save_button.setProperty("variant", "primary")
        self.save_button.clicked.connect(lambda: self.save_changes())
        actions.addWidget(self.unsaved_label)
        actions.addStretch()
        actions.addWidget(self.discard_button)
        actions.addWidget(self.save_button)
        layout.addLayout(actions)
        layout.addStretch()
        self._update_dirty_state()

    def values(self) -> dict[str, bool]:
        return dict(self._saved_values)

    def _current_values(self) -> dict[str, bool]:
        return {key: row.checkbox.isChecked() for key, row in self.rows.items()}

    def has_unsaved_changes(self) -> bool:
        return self._current_values() != self._saved_values

    def update_availability(self, states):
        mapping = {
            "yara_enabled": ("yara", "Rules unavailable"),
            "clamav_enabled": ("clamav", "Not installed"),
            "virustotal_enabled": ("virustotal", "API key needed"),
        }
        for setting_key, (engine_key, message) in mapping.items():
            available = bool(states.get(engine_key, {}).get("available"))
            self.rows[setting_key].set_availability(available, message)
            if not available:
                if self._saved_values.get(setting_key) is not False:
                    self.settings.setValue(setting_key, False)
                    self._saved_values[setting_key] = False
                    self.setting_changed.emit(setting_key, False)
        self._update_dirty_state()

    def restore_defaults(self):
        answer = QMessageBox.question(
            self,
            "Restore default settings?",
            "This will prepare the recommended default engine settings. You can review them before saving.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        defaults = {
            key: default for key, _title, _description, default in self.SETTINGS
        }
        for key, row in self.rows.items():
            if row.checkbox.isEnabled():
                row.checkbox.setChecked(defaults[key])

    def save_changes(self, confirm: bool = True) -> bool:
        if not self.has_unsaved_changes():
            return True

        current = self._current_values()
        disabled_titles = [
            title
            for key, title, _description, _default in self.SETTINGS
            if self._saved_values.get(key) and not current[key]
        ]
        details = ""
        if disabled_titles:
            details += (
                "\n\nThe following protection will be disabled:\n• "
                + "\n• ".join(disabled_titles)
            )
        if current.get("virustotal_enabled") and not self._saved_values.get(
            "virustotal_enabled"
        ):
            details += (
                "\n\nVirusTotal will receive file hashes for reputation checks; "
                "file contents are not uploaded."
            )

        if confirm:
            answer = QMessageBox.question(
                self,
                "Save settings changes?",
                "Do you wish to apply these settings to future scans?" + details,
                QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Save:
                return False

        for key, enabled in current.items():
            if self._saved_values.get(key) != enabled:
                self.settings.setValue(key, enabled)
                self.setting_changed.emit(key, enabled)
        self.settings.sync()
        self._saved_values = current
        self._update_dirty_state()
        return True

    def discard_changes(self, confirm: bool = True) -> bool:
        if not self.has_unsaved_changes():
            return True
        if confirm:
            answer = QMessageBox.question(
                self,
                "Discard unsaved changes?",
                "Your settings will return to the last saved values.",
                QMessageBox.StandardButton.Discard | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Discard:
                return False

        for key, row in self.rows.items():
            row.checkbox.blockSignals(True)
            row.checkbox.setChecked(self._saved_values[key])
            row.checkbox.blockSignals(False)
            row._toggle_display(self._saved_values[key])
        self._update_dirty_state()
        return True

    def resolve_unsaved_changes(self) -> bool:
        if not self.has_unsaved_changes():
            return True

        dialog = QMessageBox(self)
        dialog.setIcon(QMessageBox.Icon.Question)
        dialog.setWindowTitle("Unsaved settings")
        dialog.setText("Do you wish to save your settings changes?")
        dialog.setInformativeText(
            "Choose Save to apply them, Discard to undo them, or Cancel to keep editing."
        )
        dialog.setStandardButtons(
            QMessageBox.StandardButton.Save
            | QMessageBox.StandardButton.Discard
            | QMessageBox.StandardButton.Cancel
        )
        dialog.setDefaultButton(QMessageBox.StandardButton.Save)
        choice = QMessageBox.StandardButton(dialog.exec())
        if choice == QMessageBox.StandardButton.Save:
            return self.save_changes(confirm=False)
        if choice == QMessageBox.StandardButton.Discard:
            return self.discard_changes(confirm=False)
        return False

    def _update_dirty_state(self):
        dirty = self.has_unsaved_changes()
        if hasattr(self, "unsaved_label"):
            self.unsaved_label.setText(
                "Unsaved changes" if dirty else "All changes saved"
            )
            self.unsaved_label.setProperty("status", "warning" if dirty else None)
            self.unsaved_label.style().unpolish(self.unsaved_label)
            self.unsaved_label.style().polish(self.unsaved_label)
            self.save_button.setEnabled(dirty)
            self.discard_button.setEnabled(dirty)
