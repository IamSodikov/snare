import json
import re
import time

from PySide6.QtCore import QSettings, QTimer, QUrl
from PySide6.QtGui import QDesktopServices, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressDialog,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from desktop_sniffer import __version__
from desktop_sniffer.core.paths import application_data_dir, workspaces_dir
from desktop_sniffer.core.system_proxy import SystemProxy
from desktop_sniffer.core.updater import DownloadThread, Updater, apply_update
from desktop_sniffer.services.engine_process import EngineProcess
from desktop_sniffer.services.workspace_service import WorkspaceService
from desktop_sniffer.ui.dialogs.mobile_setup_dialog import MobileSetupDialog
from desktop_sniffer.ui.helpers.widgets import button
from desktop_sniffer.ui.pages.captures_page import CapturesPage
from desktop_sniffer.ui.pages.logs_page import LogsPage
from desktop_sniffer.ui.pages.rules_page import RulesPage
from desktop_sniffer.ui.theme import ASSETS


class MainWindow(QMainWindow):
    def __init__(self, autostart=False):
        super().__init__()
        self.setWindowTitle(f"Snare {__version__} — HTTP Inspector & Mock")
        self.setWindowIcon(QIcon(str(ASSETS / "icon.ico")))
        self.resize(1200, 800)
        self.settings = QSettings("LocalTools", "Snare")
        if self.settings.value("geometry") is not None:
            self.restoreGeometry(self.settings.value("geometry"))
        self.workspaces = WorkspaceService(workspaces_dir())
        self.engine = EngineProcess(self)
        self.proxy = SystemProxy(application_data_dir() / "proxy-recovery.json")
        self.engine_ready = False
        self._engine_error = False
        self._closing = False
        self.download_thread = None
        self.rules_page = self.captures_page = None
        self.proxy.restore()
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(12, 12, 12, 10)
        layout.setSpacing(10)
        self.setCentralWidget(root)
        controls = QHBoxLayout()
        layout.addLayout(controls)
        brand = QLabel("SNARE")
        brand.setProperty("role", "title")
        controls.addWidget(brand)
        self.workspace_label = QLabel()
        controls.addWidget(self.workspace_label)
        controls.addWidget(button("Workspace", self.choose_workspace))
        controls.addStretch()
        self.engine_toggle = button("Start", self.toggle_engine)
        self.set_engine_state("stopped")
        controls.addWidget(self.engine_toggle)
        controls.addWidget(button("Restart", self.restart_engine))
        self.connection_toggle = QCheckBox("Connection / Storage")
        controls.addWidget(self.connection_toggle)
        self.connection = QGroupBox("Ulanish va saqlash")
        connection_layout = QVBoxLayout(self.connection)
        connection_controls = QHBoxLayout()
        self.proxy_port = QSpinBox()
        self.proxy_port.setRange(1024, 65535)
        self.proxy_port.setValue(int(self.settings.value("port", 8080)))
        self.allow_lan = QCheckBox("Telefon / LAN")
        self.auth = QCheckBox("LAN password")
        self.system_proxy = QCheckBox("Windows System Proxy")
        self.system_proxy.setEnabled(SystemProxy.supported())
        if not SystemProxy.supported():
            self.system_proxy.setToolTip("Bu platformada ilova/brauzer proksisini qo‘lda sozlang")
        connection_controls.addWidget(QLabel("Port"))
        connection_controls.addWidget(self.proxy_port)
        for widget in (self.allow_lan, self.auth, self.system_proxy):
            connection_controls.addWidget(widget)
        connection_controls.addStretch()
        connection_controls.addWidget(button("Mobile Setup", self.show_mobile_setup))
        connection_controls.addWidget(button("Open folder", self.open_workspace_folder))
        connection_layout.addLayout(connection_controls)
        filters = QHBoxLayout()
        self.include_hosts = QLineEdit()
        self.include_hosts.setPlaceholderText("Include hosts regex (vergul bilan, ixtiyoriy)")
        self.exclude_hosts = QLineEdit()
        self.exclude_hosts.setPlaceholderText("Bypass hosts regex (vergul bilan)")
        filters.addWidget(self.include_hosts)
        filters.addWidget(self.exclude_hosts)
        filters.addWidget(button("Apply connection", self.restart_engine))
        connection_layout.addLayout(filters)
        storage = QHBoxLayout()
        self.record = QCheckBox("Record traffic")
        self.redact = QCheckBox("Mask secrets before saving")
        self.storage_limit = QSpinBox()
        self.storage_limit.setRange(1, 10000)
        self.storage_limit.setSuffix(" MiB")
        self.retention_hours = QSpinBox()
        self.retention_hours.setRange(1, 10000)
        self.retention_hours.setSuffix(" h")
        for widget in (
            self.record,
            self.redact,
            QLabel("Limit"),
            self.storage_limit,
            QLabel("Retention"),
            self.retention_hours,
        ):
            storage.addWidget(widget)
        storage.addStretch()
        storage.addWidget(button("Reclaim disk", self.maintain))
        connection_layout.addLayout(storage)
        self.connection.setVisible(False)
        self.connection_toggle.toggled.connect(self.connection.setVisible)
        layout.addWidget(self.connection)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)
        self.logs_page = LogsPage()
        self.tabs.addTab(self.logs_page, "Engine Logs")
        self.engine.log_received.connect(self.logs_page.append_log)
        self.engine.status_changed.connect(self.set_status)
        self.engine.failed.connect(self.show_engine_error)
        self.engine.ready.connect(self._on_engine_ready)
        self.system_proxy.toggled.connect(self.toggle_system_proxy)
        self.allow_lan.toggled.connect(
            lambda: self.restart_engine() if self.engine.is_running() else None
        )
        self.auth.toggled.connect(
            lambda: self.restart_engine() if self.engine.is_running() else None
        )
        self.proxy_port.valueChanged.connect(self.port_changed)
        name = self.settings.value("workspace", "default")
        try:
            self.load_workspace(name)
        except Exception as exc:
            self.logs_page.append_log(f"Workspace recovery: {exc}")
            self.recover_workspace(name)
            self.load_workspace(name)
        for widget in (self.record, self.redact):
            widget.toggled.connect(self.save_storage)
        for widget in (self.storage_limit, self.retention_hours):
            widget.valueChanged.connect(self.save_storage)
        self.stats_timer = QTimer(self)
        self.stats_timer.setInterval(1000)
        self.stats_timer.timeout.connect(self.rules_page_stats)
        self.stats_timer.start()
        self.updater = Updater(self)
        self.updater.update_available.connect(self.prompt_update)
        self.updater.error.connect(self.logs_page.append_log)
        self.updater.check_for_updates()
        if autostart:
            QTimer.singleShot(100, self.restart_engine)

    def recover_workspace(self, name):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", str(name)):
            raise ValueError("Workspace nomi noto‘g‘ri")
        root = self.workspaces.root / name
        from desktop_sniffer.domain.rules.validation import validate_rules
        from desktop_sniffer.infrastructure.persistence.atomic_json import atomic_json

        invalid = root / "rules.json"
        if invalid.exists():
            invalid.rename(root / f"rules.invalid-{time.time_ns()}.json")
        backup = root / "rules.backup.json"
        try:
            doc = json.loads(backup.read_text(encoding="utf-8"))
            validate_rules(doc["rules"])
        except (OSError, ValueError, KeyError):
            doc = {"version": 1, "rules": []}
        atomic_json(root / "rules.json", doc)
        self.logs_page.append_log(
            "Buzilgan rules saqlandi; backup yoki bo‘sh qoidalar bilan tiklandi"
        )

    def load_workspace(self, name):
        store = self.workspaces.open(name)
        self.engine.stop()
        self.engine_ready = False
        self.restore_proxy()
        if self.captures_page:
            self.captures_page.timer.stop()
        for page in (self.rules_page, self.captures_page):
            if page:
                self.tabs.removeTab(self.tabs.indexOf(page))
                page.deleteLater()
        self.store = store
        self.rules_page = RulesPage(store)
        self.captures_page = CapturesPage(store)
        self.captures_page.mock_requested.connect(self.open_mock_editor)
        self.captures_page.rules_changed.connect(self.rules_page.refresh)
        self.tabs.insertTab(0, self.captures_page, "Trafiklar")
        self.tabs.insertTab(1, self.rules_page, "Mock Qoidalar")
        self.tabs.setCurrentIndex(0)
        self.workspace_label.setText(name)
        values = store.settings()
        for widget in (
            self.record,
            self.redact,
            self.storage_limit,
            self.retention_hours,
        ):
            widget.blockSignals(True)
        self.record.setChecked(values["record"])
        self.redact.setChecked(values["redact"])
        self.storage_limit.setValue(values["max_storage_mb"])
        self.retention_hours.setValue(values["retention_hours"])
        for widget in (
            self.record,
            self.redact,
            self.storage_limit,
            self.retention_hours,
        ):
            widget.blockSignals(False)
        self.settings.setValue("workspace", name)
        splitter = self.settings.value("splitter")
        if splitter:
            self.captures_page.splitter.restoreState(splitter)

    def rules_page_stats(self):
        if self.rules_page:
            self.rules_page.update_stats()

    def choose_workspace(self):
        if not self.captures_page.can_leave():
            return
        name, ok = QInputDialog.getItem(
            self,
            "Workspace",
            "Tanlang yoki yangi nom kiriting",
            self.workspaces.names(),
            0,
            True,
        )
        if not ok:
            return
        try:
            self.load_workspace(name.strip())
            self.restart_engine()
        except Exception as exc:
            QMessageBox.warning(self, "Workspace", str(exc))

    def save_storage(self):
        self.store.save_settings(
            {
                "record": self.record.isChecked(),
                "redact": self.redact.isChecked(),
                "max_storage_mb": self.storage_limit.value(),
                "retention_hours": self.retention_hours.value(),
            }
        )

    def maintain(self):
        try:
            self.store.maintain()
            self.statusBar().showMessage(
                "Disk tozalandi; ishlatilmagan fixture’lar o‘chirildi", 5000
            )
        except Exception as exc:
            QMessageBox.warning(self, "Storage", str(exc))

    def open_workspace_folder(self):
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.store.root)))

    def open_mock_editor(self, rule):
        self.tabs.setCurrentWidget(self.rules_page)
        self.rules_page.add_rule(rule)

    def port_changed(self):
        self.settings.setValue("port", self.proxy_port.value())
        if self.engine.is_running():
            self.engine_ready = False
            self.captures_page.proxy_ready = False
            self.restore_proxy()
            self.set_engine_state("changed")

    def restore_proxy(self):
        try:
            self.proxy.restore()
        except Exception as exc:
            self.logs_page.append_log(f"Proxy restore: {exc}")
            self.statusBar().showMessage(f"Proxy restore: {exc}")

    def toggle_system_proxy(self, checked):
        if not checked:
            self.restore_proxy()
            return
        if self.engine_ready:
            try:
                self.proxy.enable(self.proxy_port.value())
            except Exception as exc:
                self.system_proxy.blockSignals(True)
                self.system_proxy.setChecked(False)
                self.system_proxy.blockSignals(False)
                QMessageBox.warning(self, "System Proxy", str(exc))
        else:
            self.statusBar().showMessage("System Proxy engine tayyor bo‘lgach yoqiladi")

    def _on_engine_ready(self, *args):
        self.engine_ready = True
        page = self.captures_page
        page.proxy_ready = True
        page.proxy_port = self.proxy_port.value()
        page.proxy_auth = self.auth.isChecked()
        page.proxy_password = self.engine._password
        page.ca_path = self.store.root.parent.parent / "mitmproxy" / "mitmproxy-ca-cert.pem"
        if self.system_proxy.isChecked():
            self.toggle_system_proxy(True)

    def set_engine_state(self, state):
        labels = {
            "stopped": "Start · Stopped",
            "starting": "Stop · Starting…",
            "running": "Stop · Running",
            "stopping": "Stopping…",
            "error": "Start · Error",
            "changed": "Stop · Apply connection",
        }
        self.engine_toggle.setText(labels[state])
        self.engine_toggle.setProperty("engineState", state)
        self.engine_toggle.setEnabled(state != "stopping")
        self.engine_toggle.setAccessibleName(labels[state])
        self.engine_toggle.setToolTip(
            "Proxy ishlayapti — to‘xtatish uchun bosing" if state == "running" else labels[state]
        )
        style = self.engine_toggle.style()
        style.unpolish(self.engine_toggle)
        style.polish(self.engine_toggle)
        self.engine_toggle.update()

    def set_status(self, message):
        if self.captures_page is None:
            return
        self.statusBar().showMessage(message)
        if message.startswith("Proxy:"):
            self.set_engine_state("running")
        elif message.startswith("Engine ishga"):
            self._engine_error = False
            self.engine_ready = False
            self.captures_page.proxy_ready = False
            self.set_engine_state("starting")
        else:
            self.engine_ready = False
            self.captures_page.proxy_ready = False
            state = (
                "stopping"
                if message.startswith("Engine to‘xtatilmoqda")
                else "error"
                if message.startswith("Engine to‘xtadi:")
                else "stopped"
            )
            if state == "error":
                self._engine_error = True
            elif state == "stopped" and self._engine_error:
                state = "error"
            self.set_engine_state(state)
            self.restore_proxy()

    def restart_engine(self):
        if self._closing:
            return
        options = {"auth": self.auth.isChecked()}
        try:
            for field, widget in (
                ("allow_hosts", self.include_hosts),
                ("ignore_hosts", self.exclude_hosts),
            ):
                values = [v.strip() for v in widget.text().split(",") if v.strip()]
                for value in values:
                    re.compile(value)
                options[field] = values
        except re.error as exc:
            QMessageBox.warning(self, "Host regex", str(exc))
            return
        self.restore_proxy()
        self.engine_ready = False
        self.captures_page.proxy_ready = False
        self.engine.start(
            self.store.root,
            self.proxy_port.value(),
            "0.0.0.0" if self.allow_lan.isChecked() else "127.0.0.1",
            options,
        )

    def toggle_engine(self):
        self._engine_error = False
        if self.engine._process.state() != self.engine._process.ProcessState.NotRunning:
            self.restore_proxy()
            self.engine_ready = False
            self.captures_page.proxy_ready = False
            self.engine.stop()
        else:
            self.restart_engine()

    def show_engine_error(self, message):
        self._engine_error = True
        self.restore_proxy()
        self.engine_ready = False
        self.captures_page.proxy_ready = False
        self.set_engine_state("error")
        self.logs_page.append_log(message)
        self.statusBar().showMessage(message)
        self.tabs.setCurrentWidget(self.logs_page)

    def show_mobile_setup(self):
        MobileSetupDialog(
            self.proxy_port.value(),
            self,
            lan=self.allow_lan.isChecked(),
            ready=self.engine_ready,
            password=self.engine._password if self.auth.isChecked() else "",
            ca_dir=self.store.root.parent.parent / "mitmproxy",
        ).exec()

    def prompt_update(self, version, url, notes, digest):
        if (
            QMessageBox.question(
                self,
                "Yangilanish",
                f"{version} mavjud. Tekshirilgan portable nusxani yuklab olasizmi? Joriy o‘rnatilgan ilova saqlanadi.\n\n{notes[:4000]}",
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        self.progress_dialog = QProgressDialog(
            "Yangilanish yuklanmoqda…", "Bekor qilish", 0, 100, self
        )
        self.download_thread = DownloadThread(url, digest, self)
        self.download_thread.progress.connect(self.progress_dialog.setValue)
        self.download_thread.completed.connect(lambda path: apply_update(path))
        self.download_thread.error.connect(self.logs_page.append_log)
        self.download_thread.finished.connect(self.progress_dialog.close)
        self.progress_dialog.canceled.connect(self.download_thread.requestInterruption)
        self.download_thread.start()
        self.progress_dialog.show()

    def closeEvent(self, event):
        event.ignore()
        if self._closing:
            return
        if not self.captures_page.can_leave():
            return
        self._closing = True
        self.restore_proxy()
        self.captures_page.timer.stop()
        self.stats_timer.stop()
        self.setEnabled(False)
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.setValue("splitter", self.captures_page.splitter.saveState())
        if self.download_thread and self.download_thread.isRunning():
            self.download_thread.requestInterruption()
        self.engine.stop()
        self._close_timer = QTimer(self)
        self._close_timer.setInterval(100)

        def complete():
            if (
                self.engine._process.state() == self.engine._process.ProcessState.NotRunning
                and not (self.download_thread and self.download_thread.isRunning())
            ):
                self._close_timer.stop()
                QApplication.quit()

        self._close_timer.timeout.connect(complete)
        self._close_timer.start()
