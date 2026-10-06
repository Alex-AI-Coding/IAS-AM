"""Explicit quarantine actions, threat evidence and asynchronous vault work."""

import ntpath
from dataclasses import dataclass, field

from PySide6.QtCore import QObject, QThread, Qt, Signal, Slot
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from antivirus.services.quarantine_service import QuarantineService
from antivirus.view.components import (
    EmptyState,
    MetricCard,
    configure_table,
    display_datetime,
    page_header,
)
from antivirus.view.theme import COLORS


@dataclass
class VaultBatchResult:
    total: int
    expected_state: str
    items: list = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class VaultWorker(QObject):
    ready = Signal(object)
    failed = Signal(str)
    done = Signal()
    progress = Signal(int, int, str)

    def __init__(self, operation, entries=None, expected_state=""):
        super().__init__()
        self.operation = operation
        self.entries = entries
        self.expected_state = expected_state

    @Slot()
    def run(self):
        try:
            if self.entries is None:
                self.ready.emit(self.operation())
            else:
                result = VaultBatchResult(len(self.entries), self.expected_state)
                for number, entry in enumerate(self.entries, 1):
                    path = getattr(
                        entry,
                        "original_path",
                        getattr(entry, "file_path", "Selected file"),
                    )
                    try:
                        result.items.append(self.operation(entry))
                    except Exception as exc:
                        result.errors.append(f"{path}: {exc or 'Action failed'}")
                    self.progress.emit(number, result.total, path)
                self.ready.emit(result)
        except Exception as exc:
            self.failed.emit(
                str(exc) or "The quarantine action could not be completed."
            )
        finally:
            self.done.emit()


class QuarantineView(QWidget):
    busy_changed = Signal(bool)
    item_changed = Signal(object)

    def __init__(self, service=None, parent=None):
        super().__init__(parent)
        self.service = service or QuarantineService()
        self._thread = self._worker = None
        self._pending_result = None
        self._pending_error = ""
        self._items = []
        self._read_error = False
        self._page = 0
        self._page_size = 200
        self._action_message = ""
        self._last_batch_details = ""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 27, 30, 26)
        layout.setSpacing(16)
        heading = QHBoxLayout()
        heading.addWidget(
            page_header(
                "Quarantine",
                "Keep detected files encrypted, review the evidence, and choose what happens next.",
            ),
            1,
        )
        self.refresh_button = QPushButton("Refresh", self)
        self.refresh_button.clicked.connect(self.refresh)
        heading.addWidget(self.refresh_button)
        self.batch_details_button = QPushButton("Action summary", self)
        self.batch_details_button.clicked.connect(self.show_action_summary)
        self.batch_details_button.hide()
        heading.addWidget(self.batch_details_button)
        layout.addLayout(heading)

        metrics = QHBoxLayout()
        self.held_card = MetricCard("Q", "Isolated files")
        self.review_card = MetricCard("!", "Need attention")
        self.restored_card = MetricCard("↗", "Restored backups")
        for card in (self.held_card, self.review_card, self.restored_card):
            metrics.addWidget(card, 1)
        layout.addLayout(metrics)

        tools = QHBoxLayout()
        self.status = QLabel(
            "Choose a detected file in Results to quarantine it.", self
        )
        self.status.setWordWrap(True)
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setProperty("role", "muted")
        self.search = QLineEdit(self)
        self.search.setPlaceholderText("Find file or threat…")
        self.search.setAccessibleName("Search quarantine")
        self.search.setMaximumWidth(235)
        self.search.textChanged.connect(self._reset_page)
        self.filter = QComboBox(self)
        self.filter.addItems(
            ["Held files", "All activity", "Needs attention", "Restored", "Deleted"]
        )
        self.filter.currentIndexChanged.connect(self._reset_page)
        tools.addWidget(self.status, 1)
        tools.addWidget(self.search)
        tools.addWidget(self.filter)
        layout.addLayout(tools)

        self.table = QTableWidget(0, 6, self)
        self.table.setHorizontalHeaderLabels(
            ["Original file", "Threat type", "Severity", "State", "Detection", "Added"]
        )
        configure_table(self.table)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        for column, width in enumerate((230, 140, 95, 210, 200, 170)):
            self.table.setColumnWidth(column, width)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setMinimumHeight(210)
        self.table.itemSelectionChanged.connect(self._update_actions)
        self.table.cellDoubleClicked.connect(lambda *_: self.show_details())
        layout.addWidget(self.table, 1)
        self.empty = EmptyState(
            "◇",
            "Your quarantine is empty",
            "Detected files stay in place until you choose to quarantine them in Results.",
            self,
        )
        layout.addWidget(self.empty, 1)

        pagination = QHBoxLayout()
        self.page_label = QLabel(self)
        self.page_label.setProperty("role", "muted")
        self.previous = QPushButton("Previous", self)
        self.next = QPushButton("Next", self)
        self.previous.clicked.connect(lambda: self._change_page(-1))
        self.next.clicked.connect(lambda: self._change_page(1))
        pagination.addWidget(self.page_label, 1)
        pagination.addWidget(self.previous)
        pagination.addWidget(self.next)
        layout.addLayout(pagination)

        actions = QHBoxLayout()
        self.details_button = QPushButton("Details", self)
        self.restore_button = QPushButton("Restore original", self)
        self.restore_as_button = QPushButton("Restore as…", self)
        self.retry_button = QPushButton("Retry isolation", self)
        self.delete_button = QPushButton("Delete vault copy", self)
        self.restore_button.setProperty("variant", "primary")
        self.delete_button.setProperty("variant", "danger")
        self.details_button.clicked.connect(self.show_details)
        self.restore_button.clicked.connect(lambda: self.restore_selected())
        self.restore_as_button.clicked.connect(
            lambda: self.restore_selected(choose_path=True)
        )
        self.retry_button.clicked.connect(self.retry_selected)
        self.delete_button.clicked.connect(self.delete_selected)
        for button in (
            self.details_button,
            self.restore_button,
            self.restore_as_button,
            self.retry_button,
            self.delete_button,
        ):
            actions.addWidget(button)
        layout.insertLayout(3, actions)
        note = QLabel(
            "Ctrl-click to choose files, Shift-click for a range, or Ctrl+A for this page. "
            "Restore releases flagged files. Delete removes only encrypted vault copies; "
            "any original or restored file stays in place. Type and severity come from the detecting engines.",
            self,
        )
        note.setProperty("role", "hint")
        note.setWordWrap(True)
        layout.addWidget(note)
        self.refresh()

    def is_busy(self):
        return self._thread is not None

    def _selected(self):
        entries = self._selected_entries()
        return entries[0] if len(entries) == 1 else None

    def _selected_entries(self):
        entries = []
        for index in sorted(
            self.table.selectionModel().selectedRows(), key=lambda i: i.row()
        ):
            item = self.table.item(index.row(), 0)
            if item and item.data(Qt.ItemDataRole.UserRole) is not None:
                entries.append(item.data(Qt.ItemDataRole.UserRole))
        return entries

    def refresh(self):
        if self.is_busy():
            return
        try:
            self._items = self.service.items()
            self._read_error = False
        except Exception as exc:
            self.status.setText(f"Quarantine could not be read: {exc}")
            self._items = []
            self._read_error = True
            for card in (self.held_card, self.review_card, self.restored_card):
                card.set_value("—")
            self._render()
            return
        self.held_card.set_value(sum(i.state == "active" for i in self._items))
        self.review_card.set_value(
            sum(
                i.state in {"copy_retained", "incomplete", "pending", "deleting"}
                for i in self._items
            )
        )
        self.restored_card.set_value(sum(i.state == "restored" for i in self._items))
        self._render()

    def _reset_page(self, *_):
        self._page = 0
        self._render()

    def _change_page(self, difference):
        self._page = max(0, self._page + difference)
        self._render()

    def _render(self):
        selection = self.filter.currentIndex()
        query = self.search.text().casefold().strip()
        results = [
            i
            for i in self._items
            if (
                selection == 1
                or (selection == 0 and i.state != "deleted")
                or (
                    selection == 2
                    and i.state
                    in {"copy_retained", "incomplete", "pending", "deleting"}
                )
                or (selection == 3 and i.state == "restored")
                or (selection == 4 and i.state == "deleted")
            )
            and (
                not query
                or query
                in (
                    i.original_path
                    + i.categories
                    + " ".join(t.get("name", "") for t in i.threats)
                ).casefold()
            )
        ]
        pages = max(1, (len(results) + self._page_size - 1) // self._page_size)
        self._page = min(self._page, pages - 1)
        self.page_label.setText(
            f"Page {self._page + 1} of {pages} · {len(results)} matching items"
        )
        self.previous.setEnabled(not self.is_busy() and self._page > 0)
        self.next.setEnabled(not self.is_busy() and self._page + 1 < pages)
        self.previous.setVisible(pages > 1)
        self.next.setVisible(pages > 1)
        self.table.setRowCount(0)
        start = self._page * self._page_size
        for entry in results[start : start + self._page_size]:
            row = self.table.rowCount()
            self.table.insertRow(row)
            values = (
                ntpath.basename(entry.original_path),
                entry.categories,
                entry.severity,
                entry.state_label,
                ", ".join(t.get("name", "Unknown") for t in entry.threats),
                display_datetime(entry.added_at),
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                if column == 0:
                    item.setToolTip(entry.original_path)
                    item.setData(Qt.ItemDataRole.UserRole, entry)
                if column == 2:
                    item.setForeground(
                        QColor(
                            COLORS["danger"]
                            if entry.severity in {"High", "Critical"}
                            else (
                                COLORS["warning"]
                                if entry.severity == "Medium"
                                else COLORS["muted"]
                            )
                        )
                    )
                self.table.setItem(row, column, item)
        self.table.setVisible(bool(results))
        self.empty.setVisible(not results)
        if self._read_error:
            self.empty.set_message(
                "Quarantine needs attention",
                "The catalogue could not be read. See the message above.",
            )
        elif self._items and not results:
            self.empty.set_message(
                "No matching items", "Choose another filter or search term."
            )
        elif not self._items:
            self.empty.set_message(
                "Your quarantine is empty",
                "Detected files stay in place until you choose to quarantine them in Results.",
            )
        self._update_actions()

    def _update_actions(self):
        entries = self._selected_entries()
        ready = not self.is_busy()
        restorable = [
            entry for entry in entries if entry.state in {"active", "copy_retained"}
        ]
        retryable = [entry for entry in entries if entry.state == "copy_retained"]
        deletable = [entry for entry in entries if entry.state != "deleted"]
        self.details_button.setEnabled(ready and len(entries) == 1)
        self.restore_button.setEnabled(ready and bool(restorable))
        self.restore_as_button.setEnabled(
            ready and len(entries) == 1 and bool(restorable)
        )
        self.retry_button.setEnabled(ready and bool(retryable))
        self.delete_button.setEnabled(ready and bool(deletable))
        for button, label, eligible in (
            (self.restore_button, "Restore original", restorable),
            (self.retry_button, "Retry isolation", retryable),
            (
                self.delete_button,
                "Delete vault copies" if len(entries) > 1 else "Delete vault copy",
                deletable,
            ),
        ):
            button.setText(f"{label} ({len(eligible)})" if len(entries) > 1 else label)
            button.setToolTip(
                f"{len(eligible)} eligible of {len(entries)} selected items."
            )
        self.restore_as_button.setToolTip(
            "Select one file to choose its restore destination."
        )

    def _confirm(self, title, text):
        dialog = QMessageBox(self)
        dialog.setWindowTitle(title)
        dialog.setTextFormat(Qt.TextFormat.PlainText)
        dialog.setText(text)
        dialog.setStandardButtons(
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel
        )
        dialog.setDefaultButton(QMessageBox.StandardButton.Cancel)
        return dialog.exec() == QMessageBox.StandardButton.Yes

    def quarantine_result(self, result):
        return self.quarantine_results([result])

    def quarantine_results(self, results):
        eligible = [
            result for result in results if result.is_detected and result.sha256
        ]
        if self.is_busy() or not eligible:
            return False
        if not self._confirm(
            "Quarantine detected files?",
            self._batch_paths(eligible)
            + "\n\nEach file will be encrypted in your private quarantine. "
            "Its original is removed only after the stored copy passes verification. "
            "Changed files are kept. A failure is reported separately while other selected files continue.",
        ):
            return False
        self._start_batch(
            "Isolating detected files…", eligible, self.service.quarantine, "active"
        )
        return True

    @staticmethod
    def _batch_paths(entries):
        paths = [
            getattr(entry, "original_path", getattr(entry, "file_path", ""))
            for entry in entries
        ]
        preview = "\n".join(paths[:8])
        extra = f"\n…and {len(paths) - 8} more." if len(paths) > 8 else ""
        return f"Selected files: {len(paths)}\n{preview}{extra}"

    def restore_selected(self, choose_path=False):
        if not choose_path:
            entries = [
                entry
                for entry in self._selected_entries()
                if entry.state in {"active", "copy_retained"}
            ]
            if (
                not entries
                or self.is_busy()
                or not self._confirm(
                    "Restore flagged files?",
                    self._batch_paths(entries)
                    + "\n\nRestore each file to its original path? Restoring can reintroduce the detected threat. "
                    "Existing files are never overwritten. Encrypted backups remain until you delete them. "
                    "Other selected items with ineligible states are left as they are.",
                )
            ):
                return
            self._start_batch(
                "Verifying and restoring files…",
                entries,
                lambda entry: self.service.restore(entry.entry_id),
                "restored",
            )
            return
        entry = self._selected()
        if (
            entry is None
            or entry.state not in {"active", "copy_retained"}
            or self.is_busy()
        ):
            return
        destination = entry.original_path
        if choose_path:
            destination, _ = QFileDialog.getSaveFileName(
                self,
                "Restore flagged file as",
                entry.original_path,
                options=QFileDialog.Option.DontConfirmOverwrite,
            )
            if not destination:
                return
        if not self._confirm(
            "Restore a flagged file?",
            f"Restore to:\n{destination}\n\nReported type: {entry.categories}\nSeverity: {entry.severity}\n\n"
            "Restoring can reintroduce the detected threat. Existing files will not be overwritten. "
            "An encrypted backup will remain until you delete it.",
        ):
            return
        self._start(
            "Verifying and restoring file…",
            lambda: self.service.restore(entry.entry_id, destination),
        )

    def retry_selected(self):
        entries = [
            entry
            for entry in self._selected_entries()
            if entry.state == "copy_retained"
        ]
        if (
            entries
            and not self.is_busy()
            and self._confirm(
                "Retry original removal?",
                self._batch_paths(entries)
                + "\n\nEach vault copy and original will be reverified "
                "before removing the original. "
                "A changed original will be kept.",
            )
        ):
            self._start_batch(
                "Retrying verified isolation…",
                entries,
                lambda entry: self.service.retry_isolation(entry.entry_id),
                "active",
            )

    def delete_selected(self):
        entries = [
            entry for entry in self._selected_entries() if entry.state != "deleted"
        ]
        if (
            entries
            and not self.is_busy()
            and self._confirm(
                "Permanently delete vault copies?",
                self._batch_paths(entries)
                + "\n\nThis permanently removes the selected encrypted quarantine copies. "
                "Activity records remain. Original and restored files are left in place.",
            )
        ):
            self._start_batch(
                "Deleting encrypted vault copies…",
                entries,
                lambda entry: self.service.delete(entry.entry_id),
                "deleted",
            )

    def show_details(self):
        entry = self._selected()
        if entry is None:
            return
        detections = "\n".join(
            f"• {t.get('name')} · {t.get('category')} · {t.get('severity')} · {t.get('source')}\n  "
            f"{t.get('description') or 'No additional description.'}"
            for t in entry.threats
        )
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Quarantine evidence")
        dialog.setTextFormat(Qt.TextFormat.PlainText)
        dialog.setText(
            f"Original file\n{entry.original_path}\n\nType: {entry.categories}\n"
            f"Highest reported severity: {entry.severity}\nState: {entry.state_label}\n"
            f"Size: {entry.file_size:,} bytes\n\nSHA-256\n{entry.sha256}\n\nDetections\n{detections}\n\n"
            f"Added: {display_datetime(entry.added_at)}"
            + (f"\nRestored to: {entry.restored_path}" if entry.restored_path else "")
            + (f"\n\nAttention\n{entry.error_message}" if entry.error_message else "")
        )
        dialog.exec()

    def show_action_summary(self):
        if not self._last_batch_details:
            return
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Quarantine action summary")
        dialog.setTextFormat(Qt.TextFormat.PlainText)
        dialog.setText(self.status.text())
        dialog.setDetailedText(self._last_batch_details)
        dialog.exec()

    def _start_batch(self, message, entries, operation, expected_state):
        if len(entries) == 1:
            self._start(message, lambda: operation(entries[0]))
        else:
            self._start(message, operation, list(entries), expected_state)

    def _start(self, message, operation, entries=None, expected_state=""):
        if self.is_busy():
            return
        self._pending_result = None
        self._pending_error = ""
        self._action_message = message.rstrip("…")
        self._last_batch_details = ""
        self.batch_details_button.hide()
        self.status.setText(message)
        self._thread = QThread(self)
        self._worker = VaultWorker(operation, entries, expected_state)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.ready.connect(self._capture_result)
        self._worker.failed.connect(self._capture_error)
        self._worker.progress.connect(self._batch_progress)
        self._worker.done.connect(self._thread.quit)
        self._worker.done.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._finished)
        self.refresh_button.setEnabled(False)
        for control in (self.table, self.search, self.filter, self.previous, self.next):
            control.setEnabled(False)
        self._update_actions()
        self.busy_changed.emit(True)
        self._thread.start()

    @Slot(int, int, str)
    def _batch_progress(self, current, total, path):
        self.status.setText(
            f"{self._action_message}: {current} of {total} · {ntpath.basename(path)}"
        )

    @Slot(object)
    def _capture_result(self, result):
        self._pending_result = result

    @Slot(str)
    def _capture_error(self, error):
        self._pending_error = error

    @Slot()
    def _finished(self):
        # finished can precede native thread-local cleanup. Join before releasing
        # Python worker references or allowing a new file-changing operation.
        self._thread.wait()
        self._thread.deleteLater()
        self._thread = self._worker = None
        self.refresh_button.setEnabled(True)
        for control in (self.table, self.search, self.filter):
            control.setEnabled(True)
        self.refresh()
        self.busy_changed.emit(False)
        if self._pending_error:
            self.status.setText(self._pending_error)
        elif isinstance(self._pending_result, VaultBatchResult):
            result = self._pending_result
            completed = sum(
                entry.state == result.expected_state for entry in result.items
            )
            attention = len(result.items) - completed
            self.status.setText(
                f"Processed {result.total} selected files: {completed} completed, "
                f"{attention} need attention, {len(result.errors)} failed. Open Action summary for details."
            )
            details = [
                f"{entry.original_path}: {entry.state_label}"
                + (f" — {entry.error_message}" if entry.error_message else "")
                for entry in result.items
            ]
            details.extend(f"FAILED — {error}" for error in result.errors)
            self._last_batch_details = "\n".join(details)
            self.batch_details_button.show()
            for entry in result.items:
                self.item_changed.emit(entry)
        elif self._pending_result:
            entry = self._pending_result
            messages = {
                "active": "File isolated. Its original has been removed.",
                "restored": "File restored. Its encrypted backup remains until you delete it.",
                "deleted": "Encrypted vault copy deleted. Original and restored files were left in place.",
            }
            self.status.setText(
                messages.get(entry.state, entry.error_message or entry.state_label)
            )
            self.item_changed.emit(entry)
        self._update_actions()
