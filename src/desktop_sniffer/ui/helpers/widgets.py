from PySide6.QtWidgets import QPushButton, QTableWidgetItem


def button(text, callback):
    widget = QPushButton(text)

    # clicked(bool) argumentini callback'ka uzatmaymiz.
    widget.clicked.connect(lambda checked=False: callback())

    return widget


def text_item(value):
    return QTableWidgetItem(str(value))