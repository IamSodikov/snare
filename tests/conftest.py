import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import pytest


@pytest.fixture(scope="session")
def qapp():
    from PySide6.QtWidgets import QApplication

    from desktop_sniffer.ui.theme import apply_theme

    app = QApplication.instance() or QApplication([])
    apply_theme(app)
    return app


@pytest.fixture
def window(qapp, tmp_path, monkeypatch):
    from desktop_sniffer.ui.windows import main_window

    monkeypatch.setattr(main_window, "workspaces_dir", lambda: tmp_path / "workspaces")
    monkeypatch.setattr(main_window, "application_data_dir", lambda: tmp_path)
    from desktop_sniffer.core.system_proxy import SystemProxy

    monkeypatch.setattr(SystemProxy, "restore", lambda self: None)
    w = main_window.MainWindow(autostart=False)
    yield w
    w.engine.stop(sync=True)
    w.stats_timer.stop()
    w.captures_page.timer.stop()
    w.hide()
    w.deleteLater()
