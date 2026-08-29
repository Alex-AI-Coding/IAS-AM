from PySide6.QtCore import QSettings
from PySide6.QtCore import Signal
from PySide6.QtWidgets import QCheckBox, QLabel, QVBoxLayout, QWidget


class SettingsView(QWidget):
    setting_changed = Signal(str, bool)
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Settings"))
        self.settings = QSettings("EducationalAntivirus", "DesktopApp")
        for name in ("ClamAV Enabled", "YARA Enabled", "Hash Detection Enabled", "VirusTotal Enabled"):
            key = name.lower().replace(" ", "_")
            checkbox = QCheckBox(name, self)
            checkbox.setChecked(self.settings.value(key, True, type=bool))
            checkbox.toggled.connect(lambda checked, k=key: (self.settings.setValue(k, checked), self.setting_changed.emit(k, checked)))
            layout.addWidget(checkbox)
        layout.addStretch()
