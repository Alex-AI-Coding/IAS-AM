"""Explicit selection of mounted drives or user-chosen scan roots."""

import os

from PySide6.QtCore import QStorageInfo, Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
)

from antivirus.config.settings import MAX_SCAN_FILES


def available_drives():
    roots = []
    seen = set()
    for volume in QStorageInfo.mountedVolumes():
        path = volume.rootPath()
        key = os.path.normcase(os.path.abspath(path)) if path else ""
        if not path or key in seen or not volume.isValid() or not volume.isReady():
            continue
        if not os.path.isdir(path):
            continue
        seen.add(key)
        name = volume.displayName() or volume.name()
        roots.append((path, f"{path} · {name}" if name and name != path else path))
    return sorted(roots, key=lambda root: os.path.normcase(root[0]))


class DriveSelectionDialog(QDialog):
    def __init__(self, parent=None, roots=None):
        super().__init__(parent)
        self.setWindowTitle("Choose drives to scan")
        self.resize(520, 410)
        layout = QVBoxLayout(self)
        intro = QLabel(
            "Select one or more internal or USB drives. Each checked location is scanned recursively."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)
        self.list = QListWidget(self)
        self.list.setAccessibleName("Drives and folders to scan")
        layout.addWidget(self.list, 1)
        for path, label in (available_drives() if roots is None else roots):
            self._add_root(path, label)

        controls = QHBoxLayout()
        self.add_button = QPushButton("Add folder or drive…", self)
        self.add_button.clicked.connect(self._choose_folder)
        controls.addWidget(self.add_button)
        controls.addStretch()
        layout.addLayout(controls)
        note = QLabel(
            f"No drive is selected automatically. The scan limit is {MAX_SCAN_FILES:,} files "
            "across the selected locations; inaccessible files are reported."
        )
        note.setWordWrap(True)
        note.setProperty("role", "hint")
        layout.addWidget(note)
        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
            self,
        )
        self.scan_button = self.buttons.button(QDialogButtonBox.StandardButton.Ok)
        self.scan_button.setText("Scan selected drives")
        self.scan_button.setProperty("variant", "primary")
        self.scan_button.setEnabled(False)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        self.list.itemChanged.connect(self._update_action)
        layout.addWidget(self.buttons)

    def _add_root(self, path, label=None, checked=False):
        key = os.path.normcase(os.path.abspath(path))
        for index in range(self.list.count()):
            item = self.list.item(index)
            if (
                os.path.normcase(os.path.abspath(item.data(Qt.ItemDataRole.UserRole)))
                == key
            ):
                if checked:
                    item.setCheckState(Qt.CheckState.Checked)
                return
        item = QListWidgetItem(label or path)
        item.setData(Qt.ItemDataRole.UserRole, path)
        item.setToolTip(path)
        item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
        item.setCheckState(
            Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        )
        self.list.addItem(item)

    def _choose_folder(self):
        path = QFileDialog.getExistingDirectory(
            self, "Choose a drive root or folder to scan"
        )
        if path:
            self._add_root(path, checked=True)
            self._update_action()

    def _update_action(self, *_):
        self.scan_button.setEnabled(bool(self.selected_paths()))

    def selected_paths(self):
        return [
            self.list.item(index).data(Qt.ItemDataRole.UserRole)
            for index in range(self.list.count())
            if self.list.item(index).checkState() == Qt.CheckState.Checked
        ]
