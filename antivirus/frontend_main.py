"""Entry point for the Premiere Security desktop frontend."""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from antivirus.view.branding import create_app_icon
from antivirus.view.main_window import MainWindow
from antivirus.view.theme import apply_theme


def main() -> int:
    """Start the desktop application."""
    application = QApplication(sys.argv)
    application.setApplicationName("Premiere Security")
    application.setOrganizationName("IAS")
    application.setApplicationVersion("1.0.0")
    application.setWindowIcon(create_app_icon())
    apply_theme(application)
    window = MainWindow()
    window.show()
    return application.exec()


if __name__ == "__main__":
    raise SystemExit(main())
