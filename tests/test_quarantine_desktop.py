"""Real Qt worker, selection, failure, and safe-closing quarantine workflows."""

from dataclasses import replace
import hashlib
from threading import Event
from time import monotonic

import pytest
from PySide6.QtCore import QSettings, Qt, QThread
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QMessageBox

from antivirus.model.scan_report import ScanReport
from antivirus.model.scan_result import ScanResult
from antivirus.model.scan_status import ScanStatus
from antivirus.model.threat import Threat
from antivirus.services.quarantine_service import QuarantineService
from antivirus.view.main_window import MainWindow
from antivirus.view.quarantine_view import QuarantineView
from antivirus.view.results_view import ResultsView


def until(qapp, predicate, timeout=5):
    deadline = monotonic() + timeout
    while not predicate() and monotonic() < deadline:
        qapp.processEvents()
        QTest.qWait(10)
    assert predicate(), "Quarantine workflow did not finish before the deadline"


def detection(path):
    content = b"Harmless desktop quarantine fixture"
    path.write_bytes(content)
    return ScanResult(
        str(path),
        ScanStatus.DETECTED,
        [Threat("Educational.Test", "Trojan", "High", source="yara")],
        hashlib.sha256(content).hexdigest(),
    )


@pytest.fixture
def view(qapp, tmp_path):
    widget = QuarantineView(QuarantineService(tmp_path / "vault"))
    widget.show()
    yield widget
    until(qapp, lambda: not widget.is_busy())
    widget.close()


def test_results_enable_quarantine_only_for_selected_detected_hashed_file(
    qapp, tmp_path
):
    view = ResultsView()
    report = ScanReport()
    report.add_result(ScanResult("clean.txt", sha256="a" * 64))
    report.add_result(ScanResult("no-hash.txt", ScanStatus.DETECTED))
    report.add_result(detection(tmp_path / "detected.txt"))
    view.show_report(report)
    for row in (0, 1):
        view.table.selectRow(row)
        assert not view.quarantine_button.isEnabled()
    view.table.selectRow(2)
    assert view.quarantine_button.isEnabled()
    received = []
    view.quarantine_requested.connect(received.append)
    view.quarantine_button.click()
    assert received == [report.results[2]]
    view.set_vault_busy(True)
    assert not view.quarantine_button.isEnabled()
    view.close()


def test_isolation_button_tracks_absolute_and_relative_paths_and_rescans(
    qapp, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    result = detection(tmp_path / "relative.txt")
    result.file_path = "relative.txt"
    view = ResultsView()
    report = ScanReport(results=[result])
    view.show_report(report)
    view.table.selectRow(0)
    item = QuarantineService(tmp_path / "vault").quarantine(result)
    view.quarantine_changed(item)
    assert not view.quarantine_button.isEnabled()
    assert view.quarantine_button.text() == "Already isolated"
    view.quarantine_changed(replace(item, state="restored"))
    assert view.quarantine_button.isEnabled()
    view.quarantine_changed(item)
    view.show_report(report)
    view.table.selectRow(0)
    assert view.quarantine_button.isEnabled()
    view.close()


def test_cancel_quarantine_confirmation_keeps_original_and_empty_vault(
    view, tmp_path, monkeypatch
):
    original = tmp_path / "cancel.txt"
    result = detection(original)
    monkeypatch.setattr(view, "_confirm", lambda *_: False)
    assert not view.quarantine_result(result)
    assert original.exists() and not view.service.items() and not view.is_busy()


def test_quarantine_restore_and_delete_buttons_complete_after_worker_idle(
    qapp, view, tmp_path, monkeypatch
):
    original = tmp_path / "desktop.txt"
    result = detection(original)
    content = original.read_bytes()
    monkeypatch.setattr(view, "_confirm", lambda *_: True)
    changes, busy = [], []
    view.item_changed.connect(lambda item: changes.append((item.state, view.is_busy())))
    view.busy_changed.connect(busy.append)
    assert view.quarantine_result(result)
    assert view.is_busy() and not view.refresh_button.isEnabled()
    until(qapp, lambda: not view.is_busy())
    assert not original.exists() and view.held_card.value_label.text() == "1"
    assert view.table.item(0, 1).text() == "Trojan"
    assert view.table.item(0, 2).text() == "High"
    view.table.selectRow(0)
    assert view.restore_button.isEnabled() and not view.retry_button.isEnabled()
    view.restore_button.click()
    until(qapp, lambda: not view.is_busy())
    assert original.read_bytes() == content
    assert view.restored_card.value_label.text() == "1"
    view.table.selectRow(0)
    assert not view.restore_button.isEnabled() and view.delete_button.isEnabled()
    view.delete_button.click()
    until(qapp, lambda: not view.is_busy())
    assert original.read_bytes() == content and view.table.rowCount() == 0
    view.filter.setCurrentIndex(4)
    assert view.table.rowCount() == 1 and view.table.item(0, 3).text() == "Deleted"
    view.table.selectRow(0)
    assert not view.delete_button.isEnabled() and view.details_button.isEnabled()
    assert changes == [("active", False), ("restored", False), ("deleted", False)]
    assert busy == [True, False, True, False, True, False]


def test_restore_conflict_reports_error_unlocks_controls_and_keeps_data(
    qapp, view, tmp_path, monkeypatch
):
    original = tmp_path / "conflict.txt"
    view.service.quarantine(detection(original))
    original.write_bytes(b"Newer user content")
    view.refresh()
    view.table.selectRow(0)
    monkeypatch.setattr(view, "_confirm", lambda *_: True)
    view.restore_button.click()
    until(qapp, lambda: not view.is_busy())
    assert "already exists" in view.status.text() and view.refresh_button.isEnabled()
    assert original.read_bytes() == b"Newer user content"
    assert view.held_card.value_label.text() == "1"
    assert view.status.textFormat() == Qt.TextFormat.PlainText


def test_broken_catalogue_shows_unavailable_instead_of_empty(view, monkeypatch):
    def unreadable():
        raise ValueError("Catalogue is unavailable")

    monkeypatch.setattr(view.service, "items", unreadable)
    view.refresh()
    assert "could not be read" in view.status.text()
    assert view.held_card.value_label.text() == "—"
    assert view.empty.title_label.text() == "Quarantine needs attention"
    assert not view.restore_button.isEnabled()


def test_repeated_worker_starts_deliver_results_on_gui_thread(qapp, view, tmp_path):
    delivered_on_gui = []
    view.item_changed.connect(
        lambda _: delivered_on_gui.append(QThread.currentThread() == qapp.thread())
    )
    for number in range(8):
        result = detection(tmp_path / f"repeat-{number}.txt")
        view._start(
            "Isolating test fixture…", lambda scan=result: view.service.quarantine(scan)
        )
        until(qapp, lambda: not view.is_busy())
    assert delivered_on_gui == [True] * 8
    assert view.held_card.value_label.text() == "8"


def test_search_and_filter_keep_quarantine_evidence_consistent(view, tmp_path):
    item = view.service.quarantine(detection(tmp_path / "specific.txt"))
    view.refresh()
    view.search.setText("trojan")
    assert view.table.rowCount() == 1
    view.search.setText("not in any entry")
    assert (
        view.table.rowCount() == 0
        and view.empty.title_label.text() == "No matching items"
    )
    view.search.clear()
    view.filter.setCurrentIndex(2)
    assert view.table.rowCount() == 0
    view.service.repository.update_state(
        item.entry_id, "copy_retained", "Test removal failure"
    )
    view.refresh()
    assert view.table.rowCount() == 1 and view.review_card.value_label.text() == "1"
    view.table.selectRow(0)
    assert view.retry_button.isEnabled()


def test_all_confirmation_dialogs_use_plain_text_and_default_cancel(
    qapp, view, monkeypatch
):
    observed = []

    def cancel(dialog):
        observed.append((dialog.textFormat(), dialog.defaultButton().text()))
        return QMessageBox.StandardButton.Cancel

    monkeypatch.setattr(QMessageBox, "exec", cancel)
    assert not view._confirm("Test", "<untrusted filename>")
    assert observed == [(Qt.TextFormat.PlainText, "Cancel")]


def test_scanning_disables_vault_actions_and_old_result_actions(qapp, tmp_path):
    settings = QSettings("IAS", "PremiereSecurity")
    settings.clear()
    window = MainWindow()
    release = Event()
    result = detection(tmp_path / "scan-lock.txt")
    window.results_view.show_report(ScanReport(results=[result]))
    window.results_view.table.selectRow(0)
    window.scan_view._start_scan(
        lambda _: (release.wait(2), result)[1], "fixture", "Test scan"
    )
    assert not window.quarantine_view.isEnabled()
    assert not window.results_view.quarantine_button.isEnabled()
    window._quarantine_result(result)
    assert "Wait for the scan" in window.statusBar().currentMessage()
    release.set()
    until(qapp, lambda: not window.scan_view.is_scanning())
    assert window.quarantine_view.isEnabled()
    window.close()
    settings.clear()


def test_vault_action_blocks_dashboard_scan_and_main_window_waits_before_close(
    qapp, tmp_path
):
    settings = QSettings("IAS", "PremiereSecurity")
    settings.clear()
    window = MainWindow()
    window.show()
    release = Event()
    window.quarantine_view.service = QuarantineService(tmp_path / "vault")
    result = detection(tmp_path / "closing.txt")

    def slow_quarantine():
        release.wait(2)
        return window.quarantine_view.service.quarantine(result)

    window.quarantine_view._start("Isolating…", slow_quarantine)
    assert not window.scan_view.isEnabled()
    window._quick_scan_from_dashboard()
    assert not window.scan_view.is_scanning()
    assert "quarantine action" in window.statusBar().currentMessage()
    window.close()
    assert window._closing and window.isVisible()  # Worker is not abandoned.
    release.set()
    until(qapp, lambda: not window.isVisible())
    assert not window.quarantine_view.is_busy()
    assert window.quarantine_view.service.items()[0].state == "active"
    settings.clear()
