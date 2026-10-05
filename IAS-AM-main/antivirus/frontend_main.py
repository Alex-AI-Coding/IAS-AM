"""Entry point for the Premiere Security desktop frontend."""

from __future__ import annotations

from email.mime import message
import sys
import asyncio
import threading
from turtle import title

from PySide6.QtWidgets import QApplication

from antivirus.view.branding import create_app_icon
from antivirus.view.main_window import MainWindow
from antivirus.view.theme import apply_theme

from antivirus.services.network_monitor_service import NetworkMonitorService
from antivirus.services.proxy_interceptor import AntimalwareProxyServer
from antivirus.services.scanner import AntimalwareEngineCoordinator
from antivirus.view.notification_popup import NotificationSignalBridge, NotificationPopup

def run_proxy_server():
    """Run the proxy server in a dedicated background thread or async loop."""
    proxy = AntimalwareProxyServer(host="127.0.0.1", port=8080)
    asyncio.run(proxy.start())

def main() -> int:
    """Start the desktop application."""
    application = QApplication(sys.argv)
    application.setApplicationName("Premiere Security")
    application.setOrganizationName("IAS")
    application.setApplicationVersion("1.0.0")
    application.setWindowIcon(create_app_icon())
    apply_theme(application)

    signal_bridge = NotificationSignalBridge()

    def show_popup(title, message, is_threat):
        global _active_popup
        _active_popup = NotificationPopup(title, message, is_threat)
        _active_popup.show()

    signal_bridge.trigger_popup.connect(show_popup)

    net_monitor = NetworkMonitorService(alert_callback=handle_ui_alert, poll_interval=5)
    net_monitor.start()

    coordinator = AntimalwareEngineCoordinator(signal_bridge=signal_bridge)
    coordinator.start_protection()

    proxy_thread = threading.Thread(target=run_proxy_server, daemon=True)
    proxy_thread.start()
    print("[*] Proxy interceptor service started on port 8080.")

    window = MainWindow()
    window.show()
    return application.exec()

def handle_ui_alert(alert):
    print(f"\n🚨 [ANTIVIRUS ALERT - {alert['severity']}]")
    print(f"   Threat Type: {alert['type']}")
    print(f"   Process:     {alert['process']}")
    print(f"   Target IP:   {alert['ip']}:{alert['port']}")
    print(f"   Details:     {alert['details']}\n")

if __name__ == "__main__":
    sys.exit(main())
