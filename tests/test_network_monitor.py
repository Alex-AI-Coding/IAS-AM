from threading import Event
from time import monotonic
import socket
from types import SimpleNamespace

from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QMessageBox,
    QStyleOptionViewItem,
)

from antivirus.services import network_monitor_service
from antivirus.services.network_monitor_service import NetworkMonitorService
from antivirus.view.network_tab import ConnectionSpinner, NetworkMonitorTab


def test_connection_snapshot_includes_process_and_remote_context(monkeypatch):
    network_monitor_service._reverse_dns_name.cache_clear()
    connection = SimpleNamespace(
        raddr=SimpleNamespace(ip="8.8.8.8", port=443),
        laddr=SimpleNamespace(ip="192.168.1.20", port=52345),
        pid=101,
        type=socket.SOCK_STREAM,
        status="ESTABLISHED",
    )
    second_connection = SimpleNamespace(
        raddr=SimpleNamespace(ip="8.8.8.8", port=8443),
        laddr=SimpleNamespace(ip="192.168.1.20", port=52346),
        pid=101,
        type=socket.SOCK_STREAM,
        status="ESTABLISHED",
    )
    process_instances = []
    dns_lookups = []

    class Process:
        def __init__(self, pid):
            assert pid == 101
            process_instances.append(pid)

        def name(self):
            return "browser.exe"

        def exe(self):
            return "C:\\Apps\\Browser\\browser.exe"

        def username(self):
            return "DESKTOP\\alice"

        def create_time(self):
            return 1_700_000_000

    monkeypatch.setattr(
        network_monitor_service.psutil,
        "net_connections",
        lambda kind: [connection, second_connection],
    )
    monkeypatch.setattr(network_monitor_service.psutil, "Process", Process)
    monkeypatch.setattr(
        socket,
        "gethostbyaddr",
        lambda address: dns_lookups.append(address)
        or ("dns.google", [], [address]),
    )

    rows = NetworkMonitorService.connections()

    assert len(rows) == 2
    assert rows[0]["local_endpoint"] == "192.168.1.20:52345"
    assert rows[0]["endpoint"] == "8.8.8.8:443"
    assert rows[0]["remote_host"] == "dns.google"
    assert rows[0]["address_scope"] == "Public internet"
    assert rows[0]["direction"] == "Likely outbound"
    assert rows[0]["executable_path"] == "C:\\Apps\\Browser\\browser.exe"
    assert rows[0]["username"] == "DESKTOP\\alice"
    assert rows[0]["process_start_time"].startswith("2023-")
    assert process_instances == [101]
    assert dns_lookups == ["8.8.8.8"]


def test_termination_deduplicates_processes_and_rejects_reused_pid(monkeypatch):
    terminated = []

    class Process:
        def __init__(self, pid):
            self.pid = pid

        def create_time(self):
            return {101: 10.0, 202: 22.0}[self.pid]

        def terminate(self):
            terminated.append(self.pid)

    monkeypatch.setattr(network_monitor_service.psutil, "Process", Process)
    monkeypatch.setattr(network_monitor_service.os, "getpid", lambda: 999)

    results = NetworkMonitorService.terminate_processes(
        [
            {"pid": 101, "process_create_time": 10.0},
            {"pid": 101, "process_create_time": 10.0},
            {"pid": 202, "process_create_time": 21.0},
        ]
    )

    assert terminated == [101]
    assert results[0]["success"]
    assert not results[1]["success"]
    assert "changed" in results[1]["message"]


def test_network_table_supports_selected_app_termination(qapp, monkeypatch):
    tab = NetworkMonitorTab()
    tab._show_rows(
        [
            {
                "process": "browser.exe",
                "pid": 101,
                "protocol": "TCP",
                "local_endpoint": "192.168.1.20:52345",
                "endpoint": "192.0.2.1:443",
                "remote_host": "example.test",
                "state": "ESTABLISHED",
                "process_create_time": 10.0,
            },
            {
                "process": "mail.exe",
                "pid": 202,
                "protocol": "TCP",
                "local_endpoint": "192.168.1.20:52346",
                "endpoint": "192.0.2.2:443",
                "remote_host": "mail.example.test",
                "state": "ESTABLISHED",
                "process_create_time": 22.0,
            },
        ]
    )
    assert (
        tab.table.selectionMode() == QAbstractItemView.SelectionMode.ExtendedSelection
    )
    assert (
        tab.table.horizontalHeader().sectionResizeMode(0)
        == QHeaderView.ResizeMode.Stretch
    )
    assert (
        tab.table.horizontalHeader().sectionResizeMode(5)
        == QHeaderView.ResizeMode.Stretch
    )
    assert tab.table.columnWidth(4) == 160
    assert tab.table.columnCount() == 7
    assert tab.table.item(0, 3).text() == "192.168.1.20:52345"
    assert tab.table.item(0, 5).text() == "example.test"
    assert tab.terminate_button.minimumWidth() == 220
    for column in range(tab.table.columnCount()):
        assert (
            tab.table.horizontalHeaderItem(column).textAlignment()
            == Qt.AlignmentFlag.AlignCenter
        )
        option = QStyleOptionViewItem()
        tab.table.itemDelegate().initStyleOption(
            option, tab.table.model().index(0, column)
        )
        assert option.displayAlignment == Qt.AlignmentFlag.AlignCenter

    selection = tab.table.selectionModel()
    selection.select(
        tab.table.model().index(0, 0),
        selection.SelectionFlag.Select | selection.SelectionFlag.Rows,
    )
    assert len(tab._selected_connections()) == 1
    selection.select(
        tab.table.model().index(1, 0),
        selection.SelectionFlag.Select | selection.SelectionFlag.Rows,
    )
    assert len(tab._selected_connections()) == 2
    assert tab.terminate_button.isEnabled()

    confirmation = []
    selected_connections = []
    result_messages = []

    def terminate(connections):
        selected_connections.extend(connections)
        return [
            {
                "pid": row["pid"],
                "success": True,
                "message": "Termination requested.",
            }
            for row in connections
        ]

    monkeypatch.setattr(
        QMessageBox,
        "warning",
        lambda *args: confirmation.append(args[2]) or QMessageBox.StandardButton.Yes,
    )
    monkeypatch.setattr(
        QMessageBox, "information", lambda *args: result_messages.append(args[2])
    )
    monkeypatch.setattr(tab, "refresh_connections", lambda: None)
    monkeypatch.setattr(NetworkMonitorService, "terminate_processes", terminate)

    tab._terminate_selected()

    assert len(confirmation) == 1
    assert "browser.exe (PID 101)" in confirmation[0]
    assert "mail.exe (PID 202)" in confirmation[0]
    assert selected_connections == [
        {"pid": 101, "process_create_time": 10.0},
        {"pid": 202, "process_create_time": 22.0},
    ]
    assert "2 application(s)" in result_messages[0]
    tab.close()


def test_refresh_shows_progress_and_restores_controls(qapp, monkeypatch):
    started = Event()
    release = Event()

    def connections():
        started.set()
        release.wait(timeout=2)
        return []

    monkeypatch.setattr(NetworkMonitorService, "connections", connections)
    tab = NetworkMonitorTab()
    tab.show()
    qapp.processEvents()
    tab.refresh_connections()

    try:
        assert started.wait(timeout=1)
        qapp.processEvents()
        assert tab.refresh_spinner.isVisible()
        assert tab.refresh_spinner._timer.isActive()
        assert not tab.refresh_button.isEnabled()
        assert "Refreshing" in tab.status.text()

        release.set()
        deadline = monotonic() + 3
        while tab.is_busy() and monotonic() < deadline:
            qapp.processEvents()
            QTest.qWait(10)

        assert not tab.is_busy()
        assert not tab.refresh_spinner.isVisible()
        assert not tab.refresh_spinner._timer.isActive()
        assert tab.refresh_button.isEnabled()
        assert "0 active remote connections" in tab.status.text()
    finally:
        release.set()
        tab.close()


def test_connection_spinner_rotates_while_active(qapp):
    spinner = ConnectionSpinner()
    spinner.start()

    assert spinner.isVisible()
    assert spinner._timer.isActive()
    initial_angle = spinner._angle
    spinner._rotate()
    assert spinner._angle != initial_angle

    spinner.stop()
    assert not spinner.isVisible()
    assert not spinner._timer.isActive()


def test_connection_details_explain_context_without_claiming_intrusion(
    qapp, monkeypatch
):
    tab = NetworkMonitorTab()
    tab._show_rows(
        [
            {
                "process": "browser.exe",
                "pid": 101,
                "protocol": "TCP",
                "local_endpoint": "192.168.1.20:52345",
                "endpoint": "8.8.8.8:443",
                "remote_host": "dns.google",
                "state": "ESTABLISHED",
                "process_create_time": 1_700_000_000,
                "process_start_time": "2023-11-14 22:13:20 UTC",
                "executable_path": "C:\\Apps\\Browser\\browser.exe",
                "username": "DESKTOP\\alice",
                "direction": "Likely outbound",
                "address_scope": "Public internet",
                "remote_port": 443,
            }
        ]
    )
    selection = tab.table.selectionModel()
    selection.select(
        tab.table.model().index(0, 0),
        selection.SelectionFlag.Select | selection.SelectionFlag.Rows,
    )

    messages = []
    monkeypatch.setattr(
        QMessageBox, "information", lambda *args: messages.append(args[2])
    )
    tab._show_selected_details()

    assert tab.details_button.isEnabled()
    assert len(messages) == 1
    assert "C:\\Apps\\Browser\\browser.exe" in messages[0]
    assert "Likely outbound" in messages[0]
    assert "HTTPS/TLS" in messages[0]
    assert "Public internet address" in messages[0]
    assert "cannot confirm a hacker" in messages[0]
    tab.close()
