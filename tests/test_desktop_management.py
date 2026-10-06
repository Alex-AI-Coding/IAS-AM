"""Real selection gestures, batch file actions, drive roots and history removal."""

from pathlib import Path
from threading import Event
from time import monotonic

import pytest
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QDialog, QMessageBox

from antivirus.controller.history_controller import HistoryController
from antivirus.controller.scan_controller import ScanController
from antivirus.detection.detection_engine import DetectionEngine
from antivirus.model.scan_report import ScanReport
from antivirus.model.scan_result import ScanResult
from antivirus.model.scan_status import ScanStatus
from antivirus.repository.scan_repository import ScanRepository
from antivirus.repository.threat_repository import ThreatRepository
from antivirus.services.quarantine_service import QuarantineService
from antivirus.services.scanner import Scanner
from antivirus.services.statistics_service import StatisticsService
from antivirus.view.drive_dialog import DriveSelectionDialog
from antivirus.view.history_view import HistoryView
from antivirus.view.quarantine_view import QuarantineView
from antivirus.view.results_view import ResultsView
from antivirus.view.scan_view import ScanView

ROOT = Path(__file__).resolve().parents[1]


def until(qapp, predicate):
    deadline = monotonic() + 5
    while not predicate() and monotonic() < deadline:
        qapp.processEvents()
        QTest.qWait(10)
    assert predicate(), "Desktop operation did not finish"


def click_row(table, row, modifier=Qt.KeyboardModifier.NoModifier):
    item = table.item(row, 0)
    table.scrollToItem(item)
    QTest.mouseClick(
        table.viewport(),
        Qt.MouseButton.LeftButton,
        modifier,
        table.visualItemRect(item).center(),
    )


def select_all(table):
    table.setFocus()
    QTest.keyClick(table, Qt.Key.Key_A, Qt.KeyboardModifier.ControlModifier)


def engine(tmp_path):
    return DetectionEngine(
        threat_repository=ThreatRepository(str(tmp_path / "threats.db")),
        clamav_enabled=False,
        virustotal_enabled=False,
    )


def detected_samples(tmp_path):
    detector = engine(tmp_path)
    results = []
    for index, name in enumerate(("ransomware", "trojan", "spyware")):
        path = tmp_path / f"{index}-{name}.txt"
        path.write_bytes((ROOT / "demo_samples" / f"{name}-demo.txt").read_bytes())
        result = detector.analyze_file(str(path))
        assert result.is_detected and result.detection_methods == ["yara"]
        results.append(result)
    return results


def test_results_control_shift_and_select_all_emit_only_eligible_detections(
    qapp, tmp_path
):
    detected = detected_samples(tmp_path)
    report = ScanReport(
        results=[detected[0], ScanResult("clean.txt"), detected[1], detected[2]]
    )
    view = ResultsView()
    view.resize(1180, 760)
    view.show_report(report)
    view.show()
    qapp.processEvents()
    click_row(view.table, 0)
    click_row(view.table, 2, Qt.KeyboardModifier.ControlModifier)
    assert view._eligible_results() == [detected[0], detected[1]]
    click_row(view.table, 1)
    click_row(view.table, 3, Qt.KeyboardModifier.ShiftModifier)
    assert {index.row() for index in view.table.selectionModel().selectedRows()} == {
        1,
        2,
        3,
    }
    select_all(view.table)
    assert len(view._selected_results()) == 4
    received = []
    view.quarantine_requested.connect(received.append)
    view.quarantine_button.click()
    assert received == [detected]
    view.table.clearSelection()
    assert not view.quarantine_button.isEnabled()
    view.close()


def test_batch_quarantine_restore_conflict_and_delete_keep_unselected_content(
    qapp, tmp_path, monkeypatch
):
    detected = detected_samples(tmp_path)
    original_bytes = [Path(result.file_path).read_bytes() for result in detected]
    view = QuarantineView(QuarantineService(tmp_path / "vault"))
    view.resize(1180, 760)
    view.show()
    monkeypatch.setattr(view, "_confirm", lambda *_: True)
    changes = []
    view.item_changed.connect(lambda item: changes.append((item.state, view.is_busy())))
    assert view.quarantine_results(detected)
    assert not view.table.isEnabled()
    until(qapp, lambda: not view.is_busy())
    assert view.held_card.value_label.text() == "3"
    assert all(not Path(result.file_path).exists() for result in detected)
    assert view.batch_details_button.isVisible()
    click_row(view.table, 0)
    click_row(view.table, 2, Qt.KeyboardModifier.ControlModifier)
    assert len(view._selected_entries()) == 2
    click_row(view.table, 0)
    click_row(view.table, 2, Qt.KeyboardModifier.ShiftModifier)
    assert len(view._selected_entries()) == 3
    select_all(view.table)
    assert len(view._selected_entries()) == 3
    assert view.restore_button.isEnabled() and not view.restore_as_button.isEnabled()
    conflict = Path(detected[0].file_path)
    conflict.write_bytes(b"Newer user content")
    view.restore_button.click()
    until(qapp, lambda: not view.is_busy())
    assert conflict.read_bytes() == b"Newer user content"
    assert view.held_card.value_label.text() == "1"
    assert view.restored_card.value_label.text() == "2"
    assert (
        "1 failed" in view.status.text()
        and "already exists" in view._last_batch_details
    )
    for index in (1, 2):
        assert Path(detected[index].file_path).read_bytes() == original_bytes[index]
    select_all(view.table)
    view.delete_button.click()
    until(qapp, lambda: not view.is_busy())
    assert view.table.rowCount() == 0
    assert all(item.state == "deleted" for item in view.service.items())
    assert conflict.read_bytes() == b"Newer user content"
    for index in (1, 2):
        assert Path(detected[index].file_path).read_bytes() == original_bytes[index]
    assert all(not busy for _, busy in changes)
    view.close()


def test_batch_isolation_continues_after_a_changed_original(
    qapp, tmp_path, monkeypatch
):
    detected = detected_samples(tmp_path)
    changed = Path(detected[1].file_path)
    changed.write_bytes(b"Changed after the scan")
    view = QuarantineView(QuarantineService(tmp_path / "vault"))
    monkeypatch.setattr(view, "_confirm", lambda *_: True)
    assert view.quarantine_results(detected)
    until(qapp, lambda: not view.is_busy())
    assert changed.read_bytes() == b"Changed after the scan"
    assert not Path(detected[0].file_path).exists()
    assert not Path(detected[2].file_path).exists()
    items = view.service.items()
    assert sum(item.state == "active" for item in items) == 2
    assert sum(item.state == "incomplete" for item in items) == 1
    assert "2 completed" in view.status.text() and "1 failed" in view.status.text()
    assert str(changed) in view._last_batch_details
    view.close()


def test_batch_confirmation_cancel_keeps_all_files_and_deselection_disables_actions(
    qapp, tmp_path, monkeypatch
):
    detected = detected_samples(tmp_path)
    view = QuarantineView(QuarantineService(tmp_path / "vault"))
    monkeypatch.setattr(view, "_confirm", lambda *_: False)
    assert not view.quarantine_results(detected)
    assert all(Path(result.file_path).exists() for result in detected)
    assert not view.service.items() and not view.is_busy()
    view.service.quarantine(detected[0])
    view.refresh()
    view.table.selectRow(0)
    view.table.clearSelection()
    assert not view.delete_button.isEnabled()
    view.delete_selected()
    assert view.service.items()[0].state == "active"
    view.close()


def test_batch_retry_isolation_handles_verified_copies_with_unremoved_originals(
    qapp, tmp_path, monkeypatch
):
    detected = detected_samples(tmp_path)
    service = QuarantineService(tmp_path / "vault")
    remove_original = service._remove_original

    def retain(item, _info):
        return service.repository.update_state(
            item.entry_id, "copy_retained", "Fixture locked file"
        )

    monkeypatch.setattr(service, "_remove_original", retain)
    view = QuarantineView(service)
    monkeypatch.setattr(view, "_confirm", lambda *_: True)
    assert view.quarantine_results(detected)
    until(qapp, lambda: not view.is_busy())
    assert "3 need attention" in view.status.text()
    assert all(Path(result.file_path).exists() for result in detected)
    monkeypatch.setattr(service, "_remove_original", remove_original)
    select_all(view.table)
    assert view.retry_button.isEnabled()
    view.retry_button.click()
    until(qapp, lambda: not view.is_busy())
    assert all(item.state == "active" for item in service.items())
    assert all(not Path(result.file_path).exists() for result in detected)
    view.close()


def test_quarantine_select_all_is_limited_to_current_page(qapp, tmp_path):
    from antivirus.model.quarantine_item import QuarantineItem

    class Catalogue:
        def items(self):
            return [
                QuarantineItem(
                    str(index), f"item-{index}.txt", "a" * 64, 1, state="active"
                )
                for index in range(205)
            ]

    view = QuarantineView(Catalogue())
    select_all(view.table)
    assert len(view._selected_entries()) == 200
    view._change_page(1)
    assert not view._selected_entries() and not view.delete_button.isEnabled()
    select_all(view.table)
    assert len(view._selected_entries()) == 5
    view.close()


def record(repository, target="fixture"):
    return repository.record_scan(1, 0, 1, 0, "clean", target=target)


def test_selected_history_removal_uses_ids_and_preserves_newer_scan(
    qapp, tmp_path, monkeypatch
):
    repository = ScanRepository(str(tmp_path / "history.db"))
    rows = [record(repository) for _ in range(3)]
    view = HistoryView(HistoryController(repository))
    view.resize(1180, 760)
    view.refresh()
    view.show()
    qapp.processEvents()
    click_row(view.table, 0)
    click_row(view.table, 2, Qt.KeyboardModifier.ControlModifier)
    expected = {rows[0]["id"], rows[2]["id"]}
    assert set(view._selected_ids()) == expected

    def confirm(*_):
        record(repository, "Completed while the dialog was open")
        return QMessageBox.StandardButton.Yes

    monkeypatch.setattr(QMessageBox, "question", confirm)
    statistics = StatisticsService(scan_repo=repository)
    updated_counts = []
    view.history_changed.connect(
        lambda: updated_counts.append(
            statistics.get_scan_statistics(None)["total_scans"]
        )
    )
    view.clear_selected_button.click()
    remaining = repository.get_recent_scans(limit=None)
    assert len(remaining) == 2
    assert not expected & {row["id"] for row in remaining}
    assert remaining[1]["id"] == rows[1]["id"]
    assert updated_counts == [2]
    view.close()


def test_clear_all_history_removes_older_hidden_rows_after_confirmation(
    qapp, tmp_path, monkeypatch
):
    repository = ScanRepository(str(tmp_path / "history.db"))
    for _ in range(105):
        record(repository)
    scanned_file = tmp_path / "scanned.txt"
    scanned_file.write_bytes(b"Keep original")
    detected = detected_samples(tmp_path)
    service = QuarantineService(tmp_path / "vault")
    item = service.quarantine(detected[0])
    view = HistoryView(HistoryController(repository))
    view.refresh()
    assert view.table.rowCount() == 100
    monkeypatch.setattr(
        QMessageBox, "question", lambda *_: QMessageBox.StandardButton.Cancel
    )
    view.clear_button.click()
    assert len(repository.get_recent_scans(None)) == 105
    monkeypatch.setattr(
        QMessageBox, "question", lambda *_: QMessageBox.StandardButton.Yes
    )
    view.clear_button.click()
    assert not repository.get_recent_scans(None)
    assert view.table.rowCount() == 0 and not view.clear_button.isEnabled()
    assert scanned_file.read_bytes() == b"Keep original"
    assert service.items()[0].entry_id == item.entry_id
    assert service.restore(item.entry_id).state == "restored"
    view.close()


def test_history_repository_chunks_large_selections_and_rejects_invalid_ids(tmp_path):
    repository = ScanRepository(str(tmp_path / "history.db"))
    rows = [record(repository) for _ in range(505)]
    with pytest.raises(ValueError):
        repository.delete_scans([rows[0]["id"], True])
    assert len(repository.get_recent_scans(None)) == 505
    ids = [row["id"] for row in rows[:502]]
    assert repository.delete_scans(ids + ids[:2] + [999999]) == 502
    assert len(repository.get_recent_scans(None)) == 3
    assert repository.delete_scans([]) == 0


def test_drive_chooser_does_not_default_to_c_and_keeps_explicit_roots(qapp):
    dialog = DriveSelectionDialog(
        roots=[("C:\\", "System"), ("E:\\", "Data"), ("F:\\", "USB")]
    )
    assert not dialog.selected_paths() and not dialog.scan_button.isEnabled()
    dialog.list.item(1).setCheckState(Qt.CheckState.Checked)
    dialog.list.item(2).setCheckState(Qt.CheckState.Checked)
    assert dialog.selected_paths() == ["E:\\", "F:\\"]
    assert dialog.scan_button.isEnabled()
    dialog.close()


def test_drive_scan_checks_multiple_roots_with_real_engines_and_saves_history(
    qapp, tmp_path, monkeypatch
):
    roots = [tmp_path / "E drive", tmp_path / "F drive"]
    for root in roots:
        root.mkdir()
        (root / "clean.txt").write_bytes((ROOT / "demo_samples/clean.txt").read_bytes())
        (root / "demo.txt").write_bytes(
            (ROOT / "demo_samples/ransomware-demo.txt").read_bytes()
        )
    repository = ScanRepository(str(tmp_path / "history.db"))
    controller = ScanController(Scanner(engine(tmp_path)), repository)
    dialog = DriveSelectionDialog(roots=[(str(root), str(root)) for root in roots])
    for index in range(2):
        dialog.list.item(index).setCheckState(Qt.CheckState.Checked)
    monkeypatch.setattr(dialog, "exec", lambda: QDialog.DialogCode.Accepted)
    monkeypatch.setattr(
        "antivirus.view.scan_view.DriveSelectionDialog", lambda _: dialog
    )
    view = ScanView(scan_drives=controller.scan_drives)
    received = []
    view.scan_completed.connect(received.append)
    view._select_drives()
    assert not view.select_drives_button.isEnabled()
    until(qapp, lambda: not view.is_scanning())
    assert received[0].total_files == 4 and received[0].threat_files == 2
    saved = repository.get_recent_scans()[0]
    assert saved["scan_type"] == "drives"
    assert saved["target"] == ", ".join(str(root) for root in roots)
    assert view.select_drives_button.isEnabled()
    view.close()


def test_drive_scan_cancellation_preserves_partial_results(qapp):
    requested = []

    def scan(roots, progress_callback, cancel_check):
        requested.extend(roots)
        report = ScanReport()
        report.add_result(ScanResult("E:\\checked.txt", ScanStatus.CLEAN))
        while not cancel_check():
            Event().wait(0.01)
        return report

    view = ScanView(scan_drives=scan)
    received = []
    view.scan_completed.connect(received.append)
    view._start_scan(scan, ["E:\\", "F:\\"], "Drive scan", True)
    view.cancel_active_scan(confirm=False)
    until(qapp, lambda: not view.is_scanning())
    assert requested == ["E:\\", "F:\\"]
    assert received[0].cancelled and received[0].total_files == 1
    assert view.radar.state == "cancelled" and view.select_drives_button.isEnabled()
    view.close()


def test_unavailable_drive_is_reported_without_scanning_a_different_root(tmp_path):
    repository = ScanRepository(str(tmp_path / "history.db"))
    controller = ScanController(Scanner(engine(tmp_path)), repository)
    absent = str(tmp_path / "Disconnected USB")
    report = controller.scan_drives([absent])
    assert report.error_files == 1 and report.clean_files == 0
    assert report.results[0].file_path == absent
    assert repository.get_recent_scans()[0]["target"] == absent
