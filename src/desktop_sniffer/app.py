import sys

from PySide6.QtCore import QTimer, QUrl, Qt, QPropertyAnimation, QEasingCurve, QSettings
from PySide6.QtGui import QDesktopServices, QPainter, QColor, QFont
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMainWindow,
    QMessageBox,
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
from desktop_sniffer.services.engine_process import EngineProcess
from desktop_sniffer.services.workspace_service import WorkspaceService
from desktop_sniffer.ui.helpers.widgets import button
from desktop_sniffer.ui.pages.captures_page import CapturesPage
from desktop_sniffer.ui.pages.logs_page import LogsPage
from desktop_sniffer.ui.pages.rules_page import RulesPage
from desktop_sniffer.core.system_proxy import set_windows_proxy
from desktop_sniffer.ui.dialogs.mobile_setup_dialog import MobileSetupDialog


class SplashOverlay(QWidget):
    """Ilova ochilganda ko'rsatiladigan splash/loader oynasi."""

    def __init__(self, parent=None, message="Engine ishga tushirilmoqda"):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, False)
        self.setStyleSheet("background-color: white;")
        self._dots = 0
        self.message = message
        self._timer = QTimer(self)
        self._timer.setInterval(400)
        self._timer.timeout.connect(self._tick)

    def start(self):
        self.show()
        self.raise_()
        self._timer.start()

    def _tick(self):
        self._dots = (self._dots + 1) % 4
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Background
        p.fillRect(self.rect(), QColor("white"))

        # Title
        title_font = QFont("Segoe UI", 22, QFont.Weight.Bold)
        p.setFont(title_font)
        p.setPen(QColor("#0284c7"))
        p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "Desktop Sniffer")

        # Subtitle with dots animation
        sub_font = QFont("Segoe UI", 11)
        p.setFont(sub_font)
        p.setPen(QColor("#64748b"))
        dots = "." * self._dots
        sub_rect = self.rect().adjusted(0, 60, 0, 60)
        p.drawText(sub_rect, Qt.AlignmentFlag.AlignCenter, f"{self.message}{dots}")

        # Loading bar
        bar_w = 200
        bar_h = 4
        cx = self.width() // 2
        cy = self.height() // 2 + 50
        p.setBrush(QColor("#e2e8f0"))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawRoundedRect(cx - bar_w // 2, cy, bar_w, bar_h, 2, 2)

        # Animated segment
        seg_w = 60
        offset = (self._dots * bar_w // 4) % (bar_w - seg_w)
        p.setBrush(QColor("#0284c7"))
        p.drawRoundedRect(cx - bar_w // 2 + offset, cy, seg_w, bar_h, 2, 2)
        p.end()

    def fade_out(self, callback):
        self._timer.stop()
        effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(effect)
        self._anim = QPropertyAnimation(effect, b"opacity")
        self._anim.setDuration(400)
        self._anim.setStartValue(1.0)
        self._anim.setEndValue(0.0)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim.finished.connect(callback)
        self._anim.finished.connect(self.deleteLater)
        self._anim.start()


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

        # Helper to create checkbox with info button
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

        # Telefon / LAN
        lan_info = (
            "Bu funksiya nima qiladi?\n"
            "YONIQ: Proksi serveringiz butun mahalliy tarmoqqa ochiladi (0.0.0.0).\n"
            "Siz bilan bitta Wi-Fi tarmog'ida bo'lgan boshqa qurilmalar (masalan telefoningiz)\n"
            "ushbu kompyuter IP manzili va proksi portiga ulanib trafiklarini o'tkazishi mumkin bo'ladi.\n"
            "O'CHIQ: Faqat ushbu kompyuterning o'zidan qilinadigan so'rovlar qabul qilinadi (127.0.0.1)."
        )
        self.lan_widget, self.allow_lan = create_cb_with_info("Telefon / LAN", lan_info, "Telefon / LAN qurilmalari", self.toggle_allow_lan)

        # System Proxy
        sys_info = (
            "Bu funksiya nima qiladi?\n"
            "YONIQ: Windows tizim proxy sozlamalari avtomatik tarzda ilovaga yo'naltiriladi.\n"
            "Ya'ni, barcha brauzerlar va dasturlar trafigi ushbu sniffer orqali o'ta boshlaydi.\n"
            "O'CHIQ: Windows proxy sozlamalari o'z holiga qaytariladi."
        )
        self.sys_widget, self.system_proxy = create_cb_with_info("System Proxy", sys_info, "System Proxy", self.toggle_system_proxy)

        # Engine Status Indicator
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

        self.engine.log_received.connect(
            self.logs_page.append_log
        )
        self.engine.status_changed.connect(
            self.set_status
        )
        self.engine.failed.connect(
            self.show_engine_error
        )
        self.engine.ready.connect(self._on_engine_ready)

        self.load_workspace(DEFAULT_WORKSPACE)

        # Splash overlay
        self._splash = SplashOverlay(root)
        self._splash.resize(1500, 950)
        self._splash.start()

        QTimer.singleShot(100, self.restart_engine)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, '_splash') and self._splash and self._splash.isVisible():
            self._splash.setGeometry(self.centralWidget().rect())

    def _on_engine_ready(self, *_):
        if hasattr(self, '_splash') and self._splash and self._splash.isVisible():
            self._splash.fade_out(lambda: None)
            self._splash = None
        # Always select Trafiklar tab on successful start
        self.tabs.setCurrentIndex(0)

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
        self.captures_page.rules_changed.connect(
            self.rules_page.refresh
        )

        self.tabs.insertTab(
            0, self.captures_page, "Trafiklar"
        )
        self.tabs.insertTab(
            1, self.rules_page, "Mock Qoidalar"
        )
        self.tabs.setCurrentIndex(0)

        self.workspace_label.setText(
            f"Workspace: {name}"
        )

    def choose_workspace(self):
        name, accepted = QInputDialog.getItem(
            self,
            "Workspace",
            "Mavjud workspace'ni tanlang yoki yangi nom kiriting:",
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

    def show_info_dialog(self, title, msg, settings_key):
        settings = QSettings("LocalTools", "DesktopSniffer")
        if settings.value(settings_key, False, type=bool):
            return
            
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

        # Agar checkbox bosilgandan keyin xatolik chiqsa, holatini orqaga qaytarish
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

        # Splash yashirilsin agar error bo'lsa
        if hasattr(self, '_splash') and self._splash and self._splash.isVisible():
            self._splash.fade_out(lambda: None)
            self._splash = None
            
        QMessageBox.critical(self, "Tizim xatosi", f"Dastur ishlashdan to'xtadi!\\n\\nXato: {message}\\n\\nLogs oynasida batafsil ma'lumot ko'rishingiz mumkin.")
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

        # Oyna yopilayotganini bildiruvchi animatsiya
        if hasattr(self, '_splash') and self._splash:
            self._splash.deleteLater()
            
        self._splash = SplashOverlay(self.centralWidget(), message="Ilova xavfsiz yopilmoqda")
        self._splash.resize(self.centralWidget().size())
        self._splash.start()

        def do_close():
            QApplication.quit()

        if self.engine.is_running():
            # Asinxron yopilishni kutamiz
            self.engine._process.finished.connect(do_close)
            self.engine.stop()  # sync=False, shuning uchun UI qotmaydi
        else:
            QTimer.singleShot(800, do_close) # Hech bo'lmasa animatsiyani ko'rsatish uchun ozroq kutish


def main() -> int:
    """Create and run the desktop application."""
    application = QApplication.instance() or QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return application.exec()
