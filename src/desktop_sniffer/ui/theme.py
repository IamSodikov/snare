"""One widget style, font and palette on every supported operating system."""

from pathlib import Path

from PySide6.QtGui import QColor, QFont, QFontDatabase, QPalette
from PySide6.QtWidgets import QStyleFactory

ASSETS = Path(__file__).resolve().parents[1] / "assets"
STYLE = """
QWidget { color: #24344b; }
QMainWindow, QDialog { background: #f3f6fa; }
QLabel[role="title"] { font-size: 18px; font-weight: 700; color: #102c48; }
QLabel[role="muted"] { color: #63768d; }
QPushButton, QToolButton { background: #ffffff; border: 1px solid #cbd7e4;
  border-radius: 6px; padding: 7px 12px; min-height: 18px; }
QPushButton:hover, QToolButton:hover { background: #eaf3fd; border-color: #7aabd8; }
QPushButton:pressed, QToolButton:pressed { background: #d8eafb; }
QPushButton:focus, QToolButton:focus { border: 2px solid #1475c9; }
QPushButton:disabled, QToolButton:disabled { color: #8997a9; background: #edf1f5; }
QPushButton[role="primary"] { background: #176fb2; color: white; border-color: #176fb2; font-weight: 600; }
QPushButton[role="primary"]:hover { background: #125d97; }
QPushButton[engineState] { color: white; font-weight: 600; }
QPushButton[engineState="stopped"] { background: #52687f; border-color: #52687f; }
QPushButton[engineState="running"] { background: #15803d; border-color: #15803d; }
QPushButton[engineState="running"]:hover { background: #166534; }
QPushButton[engineState="starting"], QPushButton[engineState="stopping"],
QPushButton[engineState="changed"] { background: #a65c00; border-color: #a65c00; }
QPushButton[engineState="error"] { background: #b91c1c; border-color: #b91c1c; }
QPushButton[role="danger"] { color: #ad3030; background: #fff2f2; }
QLineEdit, QSpinBox, QComboBox, QPlainTextEdit { background: white; border: 1px solid #cbd7e4;
  border-radius: 5px; padding: 6px; selection-background-color: #cce5ff; selection-color: #163858; }
QLineEdit:focus, QSpinBox:focus, QComboBox:focus, QPlainTextEdit:focus { border-color: #1475c9; }
QComboBox { min-height: 20px; padding-right: 22px; }
QGroupBox { background: white; border: 1px solid #d7e1ec; border-radius: 8px; margin-top: 14px; padding: 12px; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 4px; font-weight: 600; }
QTabWidget::pane { border: 1px solid #d7e1ec; background: white; border-radius: 7px; }
QTabBar::tab { background: #edf2f8; color: #63768d; padding: 9px 15px; margin-right: 3px; }
QTabBar::tab:selected { background: white; color: #176fb2; font-weight: 600; }
QTableWidget, QTreeWidget { border: 1px solid #d7e1ec; background: white;
 alternate-background-color: #f5f8fc; selection-background-color: #d9ecff; selection-color: #173d60; gridline-color: #edf2f7; }
QHeaderView::section { background: #eef4fa; border: none; border-bottom: 1px solid #d7e1ec;
 padding: 8px; color: #52687f; font-weight: 600; }
QCheckBox { spacing: 7px; }
QCheckBox::indicator { width: 16px; height: 16px; }
QSplitter::handle { background: #edf2f7; }
QScrollBar:vertical { background: #eef2f7; width: 12px; margin: 0; }
QScrollBar::handle:vertical { background: #bdcbd9; min-height: 24px; border-radius: 5px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QStatusBar { background: #edf2f7; color: #63768d; }
"""


def apply_theme(application):
    application.setStyle(QStyleFactory.create("Fusion"))
    for name in ("NotoSans.ttf", "NotoSans-Bold.ttf"):
        QFontDatabase.addApplicationFont(str(ASSETS / name))
    font = QFont("Noto Sans", 10)
    application.setFont(font)
    palette = QPalette()
    for role, color in (
        (QPalette.ColorRole.Window, "#f3f6fa"),
        (QPalette.ColorRole.WindowText, "#24344b"),
        (QPalette.ColorRole.Base, "#ffffff"),
        (QPalette.ColorRole.Text, "#24344b"),
        (QPalette.ColorRole.Button, "#ffffff"),
        (QPalette.ColorRole.ButtonText, "#24344b"),
        (QPalette.ColorRole.Highlight, "#cce5ff"),
        (QPalette.ColorRole.HighlightedText, "#173d60"),
    ):
        palette.setColor(role, QColor(color))
    application.setPalette(palette)
    application.setStyleSheet(STYLE)
