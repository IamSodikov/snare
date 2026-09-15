from pathlib import Path

from PySide6.QtCore import QSettings, Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMainWindow,
    QMessageBox,
    QProgressDialog,
    QPushButton,
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
from desktop_sniffer.core.system_proxy import set_windows_proxy
from desktop_sniffer.core.updater import Updater, DownloadThread, apply_update
from desktop_sniffer.services.engine_process import EngineProcess
from desktop_sniffer.services.workspace_service import WorkspaceService
from desktop_sniffer.ui.dialogs.mobile_setup_dialog import MobileSetupDialog
from desktop_sniffer.ui.helpers.widgets import button
from desktop_sniffer.ui.pages.captures_page import CapturesPage
from desktop_sniffer.ui.pages.logs_page import LogsPage
from desktop_sniffer.ui.pages.rules_page import RulesPage


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Snare - HTTP Sniffer & Mock")
        
        icon_path = str(Path(__file__).resolve().parents[3] / "assets" / "icon.ico")
        self.setWindowIcon(QIcon(icon_path))
        QApplication.setWindowIcon(QIcon(icon_path))
        
        self.resize(1500, 950)

        self.workspaces = WorkspaceService(workspaces_dir())
        self.engine = EngineProcess(self)

        self.rules_page = None
        self.captures_page = None

        root = QWidget()
        root.setStyleSheet("""
            QWidget { font-size: 13px; font-family: "Segoe UI", Arial, sans-serif; }
            QTabWidget::pane { border: 1px solid #cbd5e1; border-radius: 6px; background-color: white; }
            QTabBar::tab { padding: 9px 16px; margin-right: 2px; background-color: #f1f5f9; border: 1px solid #e2e8f0; border-bottom: none; border-top-left-radius: 6px; border-top-right-radius: 6px; color: #475569; }
            QTabBar::tab:selected { background: white; font-weight: bold; border: 1px solid #cbd5e1; border-bottom: 2px solid white; color: #0284c7; }
            QTabBar::tab:hover { background-color: #e0f2fe; color: #0369a1; }
            
            QPushButton { background-color: #f8fafc; border: 1px solid #cbd5e1; padding: 7px 14px; border-radius: 5px; color: #334155; }
            QPushButton:hover { background-color: #e2e8f0; border: 1px solid #94a3b8; color: #0f172a; }
            QPushButton:pressed { background-color: #cbd5e1; }
            
            QHeaderView::section { padding: 7px; font-weight: 600; background-color: #f1f5f9; border: none; border-bottom: 1px solid #cbd5e1; border-right: 1px solid #e2e8f0; color: #334155; }
            QTableWidget { border: 1px solid #cbd5e1; border-radius: 6px; alternate-background-color: #f8fafc; selection-background-color: #bae6fd; selection-color: #0c4a6e; gridline-color: #f1f5f9; }
            QLineEdit, QSpinBox, QPlainTextEdit { border: 1px solid #cbd5e1; border-radius: 4px; padding: 5px; background-color: #f8fafc; }
            QLineEdit:focus, QSpinBox:focus, QPlainTextEdit:focus { border: 1px solid #0ea5e9; background-color: white; }
        """)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)
        self.setCentralWidget(root)

        controls = QHBoxLayout()
        layout.addLayout(controls)

        self.workspace_label = QLabel()
        self.workspace_label.setStyleSheet("font-weight: 600;")

        self.proxy_port = QSpinBox()
        self.proxy_port.setRange(1024, 65535)
        self.proxy_port.setValue(DEFAULT_PROXY_PORT)

        def create_cb_with_info(text, info_text, info_title, callback=None):
            w = QWidget()
            l = QHBoxLayout(w)
            l.setContentsMargins(0, 0, 0, 0)
            l.setSpacing(4)
            cb = QCheckBox(text)
            btn_info = QPushButton("ℹ️")
            btn_info.setCursor(Qt.CursorShape.PointingHandCursor)
            btn_info.setStyleSheet("border: none; background: transparent; color: #0ea5e9; font-weight: bold; font-size: 14px; padding: 0;")
            btn_info.setToolTip(info_text)
            btn_info.clicked.connect(lambda: QMessageBox.information(self, info_title, info_text))
            l.addWidget(cb)
            l.addWidget(btn_info)
            if callback:
                cb.toggled.connect(callback)
            return w, cb

        lan_info = (
            "Bu funksiya nima qiladi?\n"
            "YONIQ: Proksi serveringiz butun mahalliy tarmoqqa ochiladi (0.0.0.0).\n"
            "Siz bilan bitta Wi-Fi tarmog'ida bo'lgan boshqa qurilmalar (masalan telefoningiz)\n"
            "ushbu kompyuter IP manzili va proksi portiga ulanib trafiklarini o'tkazishi mumkin bo'ladi.\n"
            "O'CHIQ: Faqat ushbu kompyuterning o'zidan qilinadigan so'rovlar qabul qilinadi (127.0.0.1)."
        )
        self.lan_widget, self.allow_lan = create_cb_with_info("Telefon / LAN", lan_info, "Telefon / LAN qurilmalari", self.toggle_allow_lan)

        sys_info = (
            "Bu funksiya nima qiladi?\n"
            "YONIQ: Windows tizim proxy sozlamalari avtomatik tarzda ilovaga yo'naltiriladi.\n"
            "Ya'ni, barcha brauzerlar va dasturlar trafigi ushbu sniffer orqali o'ta boshlaydi.\n"
            "O'CHIQ: Windows proxy sozlamalari o'z holiga qaytariladi."
        )
        self.sys_widget, self.system_proxy = create_cb_with_info("System Proxy", sys_info, "System Proxy", self.toggle_system_proxy)

        self.status_indicator = QLabel("⚪ Kutilmoqda")
        self.status_indicator.setStyleSheet("font-weight: bold; color: #64748b; background: #f1f5f9; padding: 4px 8px; border-radius: 4px; border: 1px solid #cbd5e1;")

        controls.addWidget(self.workspace_label)
        controls.addWidget(button("Workspace", self.choose_workspace))
        controls.addWidget(button("Open folder", self.open_workspace_folder))
        controls.addStretch()
        controls.addWidget(self.status_indicator)
        controls.addWidget(QLabel(" Port:"))
        controls.addWidget(self.proxy_port)
        controls.addWidget(self.lan_widget)
        controls.addWidget(self.sys_widget)
        controls.addWidget(button("Mobile Setup", self.show_mobile_setup))
        controls.addWidget(button("Restart", self.restart_engine))
        self.engine_toggle = button("On / Off", self.toggle_engine)
        controls.addWidget(self.engine_toggle)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        self.logs_page = LogsPage()
        self.tabs.addTab(self.logs_page, "Engine Logs")

        self.engine.log_received.connect(self.logs_page.append_log)
        self.engine.status_changed.connect(self.set_status)
        self.engine.failed.connect(self.show_engine_error)
        self.engine.ready.connect(self._on_engine_ready)

        self.load_workspace(DEFAULT_WORKSPACE)
        QTimer.singleShot(100, self.restart_engine)
        
        self.updater = Updater()
        self.updater.update_available.connect(self.prompt_update)
        self.updater.check_for_updates()

    def prompt_update(self, version, url, release_notes):
        if not release_notes or not release_notes.strip():
            release_notes = "• Ilova yanada optimallashtirildi va yangi qulayliklar qo'shildi.\n• Xatoliklar tuzatildi va barqarorlik oshirildi."
            
        reply = QMessageBox.question(
            self,
            "Yangi versiya mavjud!",
            f"Dasturning yangi {version} versiyasi chiqdi.\n\n"
            f"Yangiliklar:\n{release_notes}\n\n"
            "Hozir yuklab olib o'rnatishni xohlaysizmi?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.start_download(url)

    def start_download(self, url):
        self.progress_dialog = QProgressDialog("Yangilanish yuklanmoqda...", "Bekor qilish", 0, 100, self)
        self.progress_dialog.setWindowTitle("Yuklanmoqda")
        self.progress_dialog.setWindowModality(Qt.WindowModality.WindowModal)
        self.progress_dialog.setAutoClose(True)
        self.progress_dialog.setAutoReset(True)
        
        self.download_thread = DownloadThread(url)
        self.download_thread.progress.connect(self.progress_dialog.setValue)
        self.download_thread.finished.connect(self.on_download_finished)
        self.download_thread.error.connect(lambda e: QMessageBox.warning(self, "Xatolik", f"Yuklashda xatolik: {e}"))
        self.progress_dialog.canceled.connect(self.download_thread.terminate)
        
        self.download_thread.start()
        self.progress_dialog.show()

    def on_download_finished(self, filename):
        self.progress_dialog.close()
        reply = QMessageBox.question(
            self,
            "Yuklab olindi",
            "Yangi versiya muvaffaqiyatli yuklab olindi!\nO'rnatish uchun dastur qayta ishga tushiriladi. Davom etamizmi?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            apply_update(filename)

    def _on_engine_ready(self, *_):
        pass

    def set_status(self, message: str):
        self.statusBar().showMessage(message)

        if message.startswith("Engine to'xt") or message.startswith("Engine to‘xt"):
            self.engine_toggle.setText("Yoqish")
            self.status_indicator.setText("🔴 O'chiq")
            self.status_indicator.setStyleSheet("font-weight: bold; color: #dc2626; background: #fee2e2; padding: 4px 8px; border-radius: 4px; border: 1px solid #fca5a5;")
        elif message.startswith("Proxy:"):
            self.status_indicator.setText(f"🟢 Yoniq ({message.split('Proxy: ')[1]})")
            self.status_indicator.setStyleSheet("font-weight: bold; color: #16a34a; background: #dcfce7; padding: 4px 8px; border-radius: 4px; border: 1px solid #86efac;")
        elif message.startswith("Engine ishga"):
            self.status_indicator.setText("🟡 Yuklanmoqda")
            self.status_indicator.setStyleSheet("font-weight: bold; color: #d97706; background: #fef3c7; padding: 4px 8px; border-radius: 4px; border: 1px solid #fcd34d;")

    def load_workspace(self, name: str):
        store = self.workspaces.open(name)
        self.engine.stop()

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
        self.workspace_label.setText(f"Workspace: {name}")

    def choose_workspace(self):
        name, accepted = QInputDialog.getItem(
            self, "Workspace", "Mavjud workspace'ni tanlang yoki yangi nom kiriting:",
            self.workspaces.names(), 0, True,
        )
        if not accepted: return
        try:
            self.load_workspace(name.strip())
            self.restart_engine()
        except Exception as exc:
            QMessageBox.warning(self, "Workspace xatosi", str(exc))

    def open_workspace_folder(self):
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.store.root)))

    def open_mock_editor(self, rule: dict):
        self.tabs.setCurrentWidget(self.rules_page)
        self.rules_page.add_rule(rule)

    def show_info_dialog(self, title, msg, settings_key):
        settings = QSettings("LocalTools", "DesktopSniffer")
        if settings.value(settings_key, False, type=bool): return
            
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Information)
        box.setWindowTitle(title)
        box.setText(msg)
        
        cb = QCheckBox("Boshqa ko'rsatilmasin")
        box.setCheckBox(cb)
        box.exec()
        
        if cb.isChecked():
            settings.setValue(settings_key, True)

    def toggle_allow_lan(self, checked):
        self._last_toggle = "lan"
        self._last_lan_state = checked
        if checked:
            msg = ("LAN eshitish yondi!\n\n"
                   "Endi tarmog'ingizdagi boshqa qurilmalar (masalan telefoningiz) shu kompyuter IP manzili va proxy portiga ulanib trafikni ko'rishi mumkin.\n\n"
                   "O'zgarishlar kuchga kirishi uchun tizim orqa fonda qayta ishga tushiriladi (bu jarayon interfeysni qotirmaydi).")
            self.show_info_dialog("Telefon / LAN qurilmalari", msg, "skip_lan_warning")
        self.restart_engine()

    def toggle_system_proxy(self, checked):
        self._last_toggle = "sys"
        self._last_sys_state = checked
        if checked:
            msg = ("System Proxy yondi!\n\n"
                   "Endi ushbu kompyuterdagi barcha brauzerlar va ilovalarning trafigi to'g'ridan to'g'ri emas, balki shu ilova orqali o'tadi.")
            self.show_info_dialog("System Proxy", msg, "skip_sysproxy_warning")
            set_windows_proxy(True, port=self.proxy_port.value())
        else:
            set_windows_proxy(False)

    def show_mobile_setup(self):
        MobileSetupDialog(self.proxy_port.value(), self).exec()

    def restart_engine(self):
        self.logs_page.clear()
        self.engine.start(
            workspace=self.store.root,
            proxy_port=self.proxy_port.value(),
            listen_host="0.0.0.0" if self.allow_lan.isChecked() else "127.0.0.1",
        )
        self.engine_toggle.setText("O'chirish")

    def toggle_engine(self):
        if self.engine.is_running():
            self.engine.stop()
            self.engine_toggle.setText("Yoqish")
        else:
            self.restart_engine()

    def show_engine_error(self, message: str):
        self.engine_toggle.setText("Yoqish")
        self.status_indicator.setText("🔴 Xatolik")
        self.status_indicator.setStyleSheet("font-weight: bold; color: #dc2626; background: #fee2e2; padding: 4px 8px; border-radius: 4px; border: 1px solid #fca5a5;")
        self.statusBar().showMessage(message)
        self.logs_page.append_log(message)

        if getattr(self, "_last_toggle", None) == "lan":
            self.allow_lan.blockSignals(True)
            self.allow_lan.setChecked(not self._last_lan_state)
            self.allow_lan.blockSignals(False)
            self._last_toggle = None

        if self.system_proxy.isChecked():
            self.system_proxy.blockSignals(True)
            self.system_proxy.setChecked(False)
            set_windows_proxy(False)
            self.system_proxy.blockSignals(False)

        QMessageBox.critical(self, "Tizim xatosi", f"Dastur ishlashdan to'xtadi!\n\nXato: {message}\n\nLogs oynasida batafsil ma'lumot ko'rishingiz mumkin.")
        self.tabs.setCurrentWidget(self.logs_page)

    def closeEvent(self, event):
        if getattr(self, '_is_closing', False):
            event.accept()
            return

        event.ignore()
        self._is_closing = True

        if self.captures_page:
            self.captures_page.timer.stop()

        if self.system_proxy.isChecked():
            set_windows_proxy(False)

        self.setEnabled(False) 

        def do_close():
            QApplication.quit()

        if self.engine.is_running():
            self.engine._process.finished.connect(do_close)
            self.engine.stop() 
        else:
            QTimer.singleShot(100, do_close)
