"""All tests use disposable application data and offscreen Qt."""

import os
import tempfile
import shutil
import atexit

import pytest

TEST_DATA = tempfile.mkdtemp(prefix="ias-am-tests-")
os.environ["ANTIVIRUS_DATA_DIR"] = TEST_DATA
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
atexit.register(shutil.rmtree, TEST_DATA, ignore_errors=True)


@pytest.fixture(scope="session")
def qapp(tmp_path_factory):
    from PySide6.QtCore import QSettings
    from PySide6.QtWidgets import QApplication
    from antivirus.view.theme import apply_theme

    QSettings.setDefaultFormat(QSettings.Format.IniFormat)
    QSettings.setPath(
        QSettings.Format.IniFormat,
        QSettings.Scope.UserScope,
        str(tmp_path_factory.mktemp("settings")),
    )
    app = QApplication.instance() or QApplication([])
    apply_theme(app)
    return app
