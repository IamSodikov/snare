from PySide6.QtCore import QTimer, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMainWindow,
    QMessageBox,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from desktop_sniffer.core.constants import (
    DEFAULT_PROXY_PORT,
    DEFAULT_WORKSPACE,
)
from desktop_sniffer.core.paths import workspaces_dir
from desktop_sniffer.services.engine_process import EngineProcess
from desktop_sniffer.services.workspace_service import WorkspaceService
from desktop_sniffer.ui.helpers.widgets import button
from desktop_sniffer.ui.pages.captures_page import CapturesPage
from desktop_sniffer.ui.pages.logs_page import LogsPage
from desktop_sniffer.ui.pages.rules_page import RulesPage
from desktop_sniffer.ui.pages.traffic_page import TrafficPage


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Desktop Sniffer")
        self.resize(1500, 950)

        self.workspaces = WorkspaceService(workspaces_dir())
        self.engine = EngineProcess(self)

        self.rules_page = None
        self.captures_page = None

        root = QWidget()
        layout = QVBoxLayout(root)
        self.setCentralWidget(root)

        controls = QHBoxLayout()
        layout.addLayout(controls)

        self.workspace_label = QLabel()

        self.proxy_port = QSpinBox()
        self.proxy_port.setRange(1024, 65535)
        self.proxy_port.setValue(DEFAULT_PROXY_PORT)

        controls.addWidget(self.workspace_label)
        controls.addWidget(
            button("Workspace", self.choose_workspace)
        )
        controls.addWidget(
            button("Open folder", self.open_workspace_folder)
        )
        controls.addStretch()
        controls.addWidget(QLabel("Proxy port"))
        controls.addWidget(self.proxy_port)
        controls.addWidget(
            button("Start / Restart", self.restart_engine)
        )
        controls.addWidget(
            button("Stop", self.engine.stop)
        )

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        self.traffic_page = TrafficPage()
        self.logs_page = LogsPage()

        self.tabs.addTab(self.traffic_page, "Traffic")
        self.tabs.addTab(self.logs_page, "Engine Logs")

        self.engine.log_received.connect(
            self.logs_page.append_log
        )
        self.engine.status_changed.connect(
            self.set_status
        )
        self.engine.password_changed.connect(
            self.traffic_page.set_password
        )
        self.engine.ready.connect(
            self.traffic_page.open_url
        )
        self.engine.failed.connect(
            self.show_engine_error
        )

        self.load_workspace(DEFAULT_WORKSPACE)
        QTimer.singleShot(0, self.restart_engine)

    def set_status(self, message: str):
        self.statusBar().showMessage(message)

    def load_workspace(self, name: str):
        store = self.workspaces.open(name)

        self.engine.stop()
        self.traffic_page.clear()

        if self.captures_page:
            self.captures_page.timer.stop()

        for page in (self.rules_page, self.captures_page):
            if page:
                self.tabs.removeTab(
                    self.tabs.indexOf(page)
                )
                page.deleteLater()

        self.store = store
        self.rules_page = RulesPage(store)
        self.captures_page = CapturesPage(store)

        self.captures_page.mock_requested.connect(
            self.open_mock_editor
        )

        self.tabs.insertTab(
            1, self.captures_page, "Captures → Mock"
        )
        self.tabs.insertTab(
            2, self.rules_page, "Mock Rules"
        )

        self.workspace_label.setText(
            f"Workspace: {name}"
        )

    def choose_workspace(self):
        name, accepted = QInputDialog.getItem(
            self,
            "Workspace",
            "Mavjud workspace’ni tanlang yoki yangi nom yozing:",
            self.workspaces.names(),
            0,
            True,
        )

        if not accepted:
            return

        try:
            self.load_workspace(name.strip())
            self.restart_engine()

        except Exception as exc:
            QMessageBox.warning(
                self, "Workspace xatosi", str(exc)
            )

    def open_workspace_folder(self):
        QDesktopServices.openUrl(
            QUrl.fromLocalFile(str(self.store.root))
        )

    def open_mock_editor(self, rule: dict):
        self.tabs.setCurrentWidget(self.rules_page)
        self.rules_page.add_rule(rule)

    def restart_engine(self):
        self.traffic_page.clear()
        self.logs_page.clear()

        self.engine.start(
            workspace=self.store.root,
            proxy_port=self.proxy_port.value(),
        )

    def show_engine_error(self, message: str):
        self.statusBar().showMessage(message)
        self.logs_page.append_log(message)
        self.tabs.setCurrentWidget(self.logs_page)

    def closeEvent(self, event):
        if self.captures_page:
            self.captures_page.timer.stop()

        self.engine.stop()
        event.accept()