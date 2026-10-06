"""Entry point for the Premiere Security desktop frontend."""

from __future__ import annotations

import sys
import sqlite3

from PySide6.QtWidgets import QApplication, QMessageBox

from antivirus.view.branding import create_app_icon
from antivirus.view.main_window import MainWindow
from antivirus.view.theme import apply_theme


def main() -> int:
    """Start the desktop application."""
    application = QApplication(sys.argv)
    application.setApplicationName("Premiere Security")
    application.setOrganizationName("IAS")
    application.setApplicationVersion("1.2.0")
    application.setWindowIcon(create_app_icon())
    apply_theme(application)
    try:
        window = MainWindow()
    except (OSError, sqlite3.Error, ValueError):
        QMessageBox.critical(
            None,
            "Premiere Security could not start",
            "Application data could not be opened. Check folder permissions and available disk space, then try again.",
        )
        return 1
    window.show()
    return application.exec()


if __name__ == "__main__":
    raise SystemExit(main())
