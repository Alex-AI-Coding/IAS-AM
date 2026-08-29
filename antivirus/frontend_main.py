"""Entry point for the desktop frontend.

The GUI is intentionally minimal in Phase 1. Backend services remain
independent and can still be used through the CLI or Python API.
"""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from antivirus.view.main_window import MainWindow


def main() -> int:
    """Start the desktop application."""
    application = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return application.exec()


if __name__ == "__main__":
    raise SystemExit(main())
