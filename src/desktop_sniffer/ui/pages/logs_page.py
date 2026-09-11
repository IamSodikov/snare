from PySide6.QtWidgets import QPlainTextEdit


class LogsPage(QPlainTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setReadOnly(True)
        self.setMaximumBlockCount(3000)

    def append_log(self, text: str):
        self.appendPlainText(text)