"""Real offscreen Qt event-loop checks for radar and worker lifetimes."""

from time import monotonic
from threading import Event

from PySide6.QtTest import QTest
from PySide6.QtCore import QEvent, QPoint, QSettings, Qt, QVariantAnimation
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QGraphicsDropShadowEffect,
    QHeaderView,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
)

from antivirus.model.scan_report import ScanReport
from antivirus.model.scan_result import ScanResult
from antivirus.model.scan_status import ScanStatus
from antivirus.model.threat import Threat
from antivirus.view.scan_view import ScanView
from antivirus.view.components import configure_table, set_table_row_numbers
from antivirus.view.results_view import ResultsDialog, ResultsView
from antivirus.view.main_window import MainWindow
from antivirus.view.theme import COLORS, apply_theme


def until(qapp, predicate, timeout=5):
    deadline = monotonic() + timeout
    while not predicate() and monotonic() < deadline:
        qapp.processEvents()
        QTest.qWait(10)
    assert predicate(), "Qt workflow did not finish within the deadline"


def test_radar_tracks_scan_lifecycle_and_results_are_emitted_after_idle(qapp):
    release = Event()

    def scan(path):
        release.wait(timeout=2)
        return ScanResult(path)

    view = ScanView(scan_file=scan)
    view.resize(1100, 640)
    view.show()
    qapp.processEvents()
    received = []
    view.scan_completed.connect(
        lambda result: received.append((result, view.is_scanning()))
    )
    view._start_scan(scan, "safe.txt", "File scan")
    assert view.radar.state == "scanning"
    assert view.radar._timer.isActive()
    assert not view.select_file_button.isEnabled()
    assert view.loading_label.text() == "Loading reality..."
    assert view.loading_label.isVisible()
    assert not view.panic_label.isVisible()
    view.set_reduced_motion(True)
    assert isinstance(view.progress, QProgressBar)
    assert view.progress_glow_animation.state() != QVariantAnimation.State.Running
    assert not view.progress_glow.isEnabled()
    assert not view.radar._timer.isActive()
    release.set()
    until(qapp, lambda: not view.is_scanning())
    assert view.radar.state == "complete"
    assert not view.radar._timer.isActive()
    assert not view.loading_label.isVisible()
    assert not view.panic_label.isVisible()
    assert view.select_file_button.isEnabled()
    assert len(received) == 1
    assert received[0][1] is False
    view.close()


def test_cancelled_scan_does_not_emit_results_and_stops_radar(qapp):
    def folder(path, progress_callback, cancel_check):
        report = ScanReport()
        report.add_result(ScanResult("one.txt"))
        deadline = monotonic() + 2
        while not cancel_check() and monotonic() < deadline:
            Event().wait(0.01)
        report.cancelled = cancel_check()
        return report

    view = ScanView(scan_directory=folder)
    view.show()
    received = []
    view.scan_completed.connect(received.append)
    view._start_scan(folder, "folder", "Folder scan", True)
    view.cancel_active_scan(confirm=False)
    until(qapp, lambda: not view.is_scanning())
    assert view.radar.state == "cancelled"
    assert received == []
    assert "No results page" in view.status_label.text()
    view.close()


def test_scan_loading_bar_shows_panic_message_only_near_completion(qapp):
    view = ScanView(scan_directory=lambda *_args: ScanReport())
    view.show()
    qapp.processEvents()

    view._scan_progress(98, 100, "almost-there.txt")
    assert not view.panic_label.isVisible()

    view._scan_progress(99, 100, "last-file.txt")
    assert view.panic_label.text() == "PANIC MODE ENGAGED at 99%"
    assert view.panic_label.isVisible()

    view._scan_progress(100, 100, "last-file.txt")
    assert view.panic_label.text() == "PANIC MODE ENGAGED at 100%"
    view.close()


def test_scan_progress_glow_pulses_and_respects_reduced_motion(qapp):
    view = ScanView(scan_directory=lambda *_args: ScanReport())
    view.show()
    qapp.processEvents()
    progress = view.progress
    progress.show()
    assert progress.__class__ is QProgressBar
    assert "border-radius: 8px" in qapp.styleSheet()

    view._sync_progress_glow(True)
    animation = view.progress_glow_animation
    assert animation.state() == QVariantAnimation.State.Running
    assert view.progress_glow.isEnabled()

    animation.setCurrentTime(animation.duration() // 2)
    peak_blur = view.progress_glow.blurRadius()
    peak_alpha = view.progress_glow.color().alpha()
    assert peak_blur > 20
    assert peak_alpha > 150

    animation.setCurrentTime(animation.duration() * 3 // 4)
    fade_blur = view.progress_glow.blurRadius()
    fade_alpha = view.progress_glow.color().alpha()
    assert fade_blur < peak_blur
    assert fade_alpha < peak_alpha

    view.set_reduced_motion(True)
    assert animation.state() != QVariantAnimation.State.Running
    assert not view.progress_glow.isEnabled()
    view.set_reduced_motion(False)
    view._sync_progress_glow(True)
    assert animation.state() == QVariantAnimation.State.Running
    view._sync_progress_glow(False)
    assert animation.state() != QVariantAnimation.State.Running
    assert not view.progress_glow.isEnabled()
    apply_theme(qapp, "light")
    view.update_progress_glow_color()
    assert view.progress_glow.color().name() == COLORS["signal"].lower()
    apply_theme(qapp, "dark")
    view.update_progress_glow_color()
    view.close()


def test_failed_scan_stops_radar_and_unlocks_controls(qapp):
    def broken(path):
        raise RuntimeError("cannot read target")

    view = ScanView(scan_file=broken)
    view.show()
    view._start_scan(broken, "target", "File scan")
    until(qapp, lambda: not view.is_scanning())
    assert view.radar.state == "error"
    assert view.quick_scan_button.isEnabled()
    assert "cannot read" in view.status_label.text()
    view.close()


def test_skipped_results_filter_and_exports(qapp):
    view = ResultsView()
    report = ScanReport(cancelled=True)
    report.add_result(ScanResult("safe", ScanStatus.CLEAN))
    report.add_result(ScanResult("big", ScanStatus.SKIPPED))
    view.show_report(report)
    assert view.error_card.value_label.text() == "0"
    assert view.skipped_card.value_label.text() == "1"
    assert "Cancelled" in view.summary.text()
    view.filter_combo.setCurrentIndex(5)
    assert view.table.rowCount() == 1
    assert view.table.item(0, 0).text() == "big"
    assert view.export_signed_button.isEnabled()
    assert "QComboBox::down-arrow" in qapp.styleSheet()
    assert "border-top: 6px solid" in qapp.styleSheet()
    view.close()


def test_results_summary_counts_high_risk_files_once_and_lists_every_warning(qapp):
    report = ScanReport(warnings=["first warning", "second warning"])
    report.add_result(
        ScanResult(
            "suspicious.exe",
            ScanStatus.DETECTED,
            threats=[
                Threat("A", "Trojan", severity="High"),
                Threat("B", "Exploit", severity="Critical"),
            ],
        )
    )
    report.add_result(
        ScanResult(
            "moderate.exe",
            ScanStatus.DETECTED,
            threats=[Threat("C", "Heuristic", severity="Medium")],
        )
    )
    view = ResultsView()
    view.show_report(report)

    assert view.total_card.value_label.text() == "2"
    assert view.threat_card.value_label.text() == "1"
    assert view.high_risk_card.value_label.text() == "1"
    assert view.match_card.value_label.text() == "3"
    assert "1 suspicious" in view.summary.text()
    assert "3 detection matches" in view.summary.text()
    assert "1 high risk" in view.summary.text()
    assert not view.table.verticalHeader().isHidden()
    assert view.table.verticalHeaderItem(0).text() == "1"
    assert "first warning" in view.summary.toolTip()
    assert "second warning" in view.summary.toolTip()
    view.close()


def test_results_dialog_is_modal_and_populates_saved_report(qapp):
    report = ScanReport()
    report.add_result(ScanResult("safe.txt"))
    dialog = ResultsDialog(report)
    assert dialog.isModal()
    assert dialog.windowState() & Qt.WindowState.WindowMaximized
    assert dialog.results_view.report is report
    assert dialog.results_view.table.rowCount() == 1
    dialog.close()


def test_results_table_gives_space_to_file_threat_and_severity(qapp):
    view = ResultsView()
    header = view.table.horizontalHeader()

    assert not header.stretchLastSection()
    for column in (0, 2):
        assert (
            header.sectionResizeMode(column) == QHeaderView.ResizeMode.Stretch
        )
    for column in (1, 3, 4):
        assert (
            header.sectionResizeMode(column)
            == QHeaderView.ResizeMode.ResizeToContents
        )
    view.close()


def test_results_filter_fits_longest_option_and_dropdown(qapp):
    view = ResultsView()
    view.show()
    qapp.processEvents()

    longest_option = max(
        (
            view.filter_combo.itemText(index)
            for index in range(view.filter_combo.count())
        ),
        key=view.filter_combo.fontMetrics().horizontalAdvance,
    )
    required_text_width = view.filter_combo.fontMetrics().horizontalAdvance(
        longest_option
    )
    assert view.filter_combo.width() >= required_text_width + 48
    assert view.filter_combo.sizeAdjustPolicy() == (
        view.filter_combo.SizeAdjustPolicy.AdjustToContents
    )

    view.filter_combo.setCurrentIndex(2)
    assert view.filter_combo.currentText() == longest_option
    view.close()


def test_results_search_box_and_button_hover_effects_support_both_themes(qapp):
    view = ResultsView()
    assert "file path" in view.search_box.placeholderText().lower()
    assert "threat name" in view.search_box.placeholderText().lower()
    assert view.search_box.minimumWidth() == 340
    assert "file path" in view.search_box.toolTip().lower()

    regular_button = QPushButton("Regular")
    delete_button = QPushButton("Delete")

    for mode in ("dark", "light"):
        apply_theme(qapp, mode)
        stylesheet = qapp.styleSheet()
        if mode == "light":
            assert (
                'QPushButton[nav="true"]:hover { background: #DDE4E9; color: #172B3A; }'
                in stylesheet
            )
            assert "QPushButton[variant=\"primary\"]:hover { background: #D97832; color: #172B3A;" in stylesheet
            assert "QPushButton[variant=\"danger\"]:hover { background: #B42318; color: #FFFFFF; }" in stylesheet
        else:
            assert (
                'QPushButton[nav="true"]:hover { background: #1C1C1C; color: #FFFFFF; }'
                in stylesheet
            )

        qapp.sendEvent(regular_button, QEvent(QEvent.Type.Enter))
        glow = regular_button.graphicsEffect()
        assert isinstance(glow, QGraphicsDropShadowEffect)
        assert glow.isEnabled()
        assert glow.color() == QColor(COLORS["highlight"])
        qapp.sendEvent(regular_button, QEvent(QEvent.Type.Leave))
        assert not glow.isEnabled()

        qapp.sendEvent(delete_button, QEvent(QEvent.Type.Enter))
        delete_glow = delete_button.graphicsEffect()
        assert isinstance(delete_glow, QGraphicsDropShadowEffect)
        assert delete_glow.isEnabled()
        assert delete_glow.color() == QColor(COLORS["highlight"])
        qapp.sendEvent(delete_button, QEvent(QEvent.Type.Leave))
        assert not delete_glow.isEnabled()

    apply_theme(qapp, "light")
    assert COLORS["background"] == "#E4E9ED"
    assert COLORS["surface"] == "#F3F5F6"
    apply_theme(qapp, "dark")
    view.close()


def test_navigation_uses_named_page_indices_and_keeps_settings_preferences(qapp):
    settings = QSettings("IAS", "PremiereSecurity")
    settings.clear()
    window = MainWindow()
    window.show()
    assert "Results" not in [button.text() for button in window.navigation._buttons]
    for index in window.NAVIGATION_PAGES:
        window.navigation.setCurrentIndex(index)
        assert window.pages.currentIndex() == index
    saved = window.settings_view.values()
    window.settings_view.update_availability({})
    assert window.settings_view.values() == saved
    assert not window.settings_view.has_unsaved_changes()
    assert window.network_tab.table.columnCount() == 7
    window.close()
    settings.clear()


def test_large_result_set_is_paged_and_searchable_without_losing_exports(qapp):
    from antivirus.services.report_formatter import ReportFormatter

    view = ResultsView()
    report = ScanReport()
    for i in range(620):
        report.add_result(ScanResult(f"file-{i:04}.txt"))
    view.show_report(report)
    view.show()
    qapp.processEvents()
    assert view.table.rowCount() == 250
    assert view.table.verticalHeaderItem(0).text() == "1"
    assert view.next_button.isEnabled()
    view.table.verticalScrollBar().setValue(
        view.table.verticalScrollBar().maximum()
    )
    assert view.table.verticalScrollBar().value() > 0
    view._change_page(1)
    assert view.table.item(0, 0).text() == "file-0250.txt"
    assert view.table.verticalHeaderItem(0).text() == "251"
    assert view.table.verticalScrollBar().value() == 0
    view.search_box.setText("file-0619")
    assert view.table.rowCount() == 1
    assert view.table.item(0, 0).text() == "file-0619.txt"
    assert view.table.verticalHeaderItem(0).text() == "1"
    assert len(ReportFormatter.to_dict(report)["results"]) == 620
    view.close()


def test_numbered_table_header_background_matches_both_themes(qapp):
    table = QTableWidget(3, 1)
    configure_table(table)
    table.setHorizontalHeaderLabels(["Activity"])
    table.setItem(0, 0, QTableWidgetItem("Recent scan"))
    set_table_row_numbers(table)
    table.resize(360, 240)
    table.show()

    try:
        for mode, expected in (
            ("dark", "#1C1C1C"),
            ("light", "#DDE4E9"),
        ):
            apply_theme(qapp, mode)
            qapp.processEvents()
            image = table.grab().toImage()
            header_rect = table.verticalHeader().geometry()
            blank_header_pixel = QPoint(
                header_rect.right() - 4,
                header_rect.bottom() - 8,
            )
            assert image.pixelColor(blank_header_pixel).name().upper() == expected
    finally:
        table.close()
        apply_theme(qapp, "dark")
