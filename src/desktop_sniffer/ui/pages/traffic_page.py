from PySide6.QtCore import QUrl
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from desktop_sniffer.ui.helpers.widgets import button


class TrafficPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QVBoxLayout(self)

        auth = QHBoxLayout()
        auth.addWidget(QLabel("mitmweb password"))

        self.password = QLineEdit()
        self.password.setReadOnly(True)
        self.password.setEchoMode(
            QLineEdit.EchoMode.Password
        )

        auth.addWidget(self.password)
        auth.addWidget(button("Copy", self.copy_password))
        auth.addWidget(button("Reload", self.reload))

        layout.addLayout(auth)

        self.web = QWebEngineView()
        layout.addWidget(self.web)

        self.current_url = None

    def set_password(self, password: str):
        self.password.setText(password)

    def copy_password(self):
        QApplication.clipboard().setText(
            self.password.text()
        )

    def open_url(self, url: str):
        self.current_url = url
        self.web.setUrl(QUrl(url))

    def reload(self):
        if self.current_url:
            self.web.setUrl(QUrl(self.current_url))

    def clear(self):
        self.current_url = None
        self.web.setUrl(QUrl("about:blank"))