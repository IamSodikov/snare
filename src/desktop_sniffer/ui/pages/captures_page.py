import base64
import difflib
import json
import ssl
import threading
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

from PySide6.QtCore import QEvent, QRegularExpression, Qt, QTimer, Signal, QSettings
from PySide6.QtGui import (
    QColor,
    QCursor,
    QFont,
    QGuiApplication,
    QKeySequence,
    QShortcut,
    QSyntaxHighlighter,
    QTextCharFormat,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QTreeWidget,
    QTreeWidgetItem,
    QDialog,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from desktop_sniffer.domain.rules.defaults import default_rule
from desktop_sniffer.domain.rules.patching import deep_diff
from desktop_sniffer.services.traffic_tools import curl_command, export_har, import_har
from desktop_sniffer.ui.helpers.widgets import button, text_item


class HeaderHighlighter(QSyntaxHighlighter):
    def highlightBlock(self, text):
        fmt = QTextCharFormat()
        fmt.setFontWeight(QFont.Weight.Bold)
        fmt.setForeground(QColor("#0284c7"))

        match = QRegularExpression("^[^:]+:").match(text)
        if match.hasMatch():
            self.setFormat(match.capturedStart(), match.capturedLength(), fmt)


class JsonHighlighter(QSyntaxHighlighter):
    def highlightBlock(self, text):
        fmt = QTextCharFormat()
        fmt.setForeground(QColor("#c026d3"))

        re = QRegularExpression(r'"[^"]*"\s*:')
        it = re.globalMatch(text)
        while it.hasNext():
            match = it.next()
            self.setFormat(match.capturedStart(), match.capturedLength() - 1, fmt)

        str_fmt = QTextCharFormat()
        str_fmt.setForeground(QColor("#16a34a"))
        re_str = QRegularExpression(r':\s*("[^"]*")')
        it_str = re_str.globalMatch(text)
        while it_str.hasNext():
            match = it_str.next()
            self.setFormat(match.capturedStart(1), match.capturedLength(1), str_fmt)


class EditorDialog(QDialog):
    def __init__(self, title, text, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(800, 600)
        from PySide6.QtWidgets import QHBoxLayout, QVBoxLayout

        layout = QVBoxLayout(self)
        self.editor = QPlainTextEdit()

        font = QFont("Consolas", 11)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.editor.setFont(font)

        if "Headers" in title:
            self.highlighter = HeaderHighlighter(self.editor.document())
        else:
            self.highlighter = JsonHighlighter(self.editor.document())

        self.editor.setPlainText(text)
        self.editor.setTabStopDistance(self.editor.fontMetrics().horizontalAdvance(" ") * 2)
        layout.addWidget(self.editor)
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        save_btn = QPushButton("Saqlash")
        save_btn.clicked.connect(self.accept)
        btn_layout.addWidget(save_btn)
        cancel_btn = QPushButton("Bekor qilish")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)

    def text(self):
        return self.editor.toPlainText()


class HeadersTableWidget(QTableWidget):
    textChanged = Signal()

    def __init__(self, title="", parent=None):
        super().__init__(0, 2, parent)
        self.title = title
        self.setHorizontalHeaderLabels(["Key", "Value"])
        from PySide6.QtWidgets import QHeaderView

        self.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.verticalHeader().setVisible(False)
        self.setAlternatingRowColors(True)
        self.itemChanged.connect(lambda _: self.textChanged.emit())

    def toPlainText(self):
        lines = []
        for row in range(self.rowCount()):
            k_item = self.item(row, 0)
            v_item = self.item(row, 1)
            k = k_item.text().strip() if k_item else ""
            v = v_item.text().strip() if v_item else ""
            if k:
                lines.append(f"{k}: {v}")
        return "\n".join(lines)

    def setPlainText(self, text):
        self.blockSignals(True)
        self.setRowCount(0)
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            k, v = line, ""
            if ":" in line:
                k, v = line.split(":", 1)
            row = self.rowCount()
            self.insertRow(row)
            self.setItem(row, 0, QTableWidgetItem(k.strip()))
            self.setItem(row, 1, QTableWidgetItem(v.strip()))
        self.blockSignals(False)
        self.textChanged.emit()

    def open_editor(self):
        dialog = EditorDialog(self.title, self.toPlainText(), self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.setPlainText(dialog.text())


class BodyTextEdit(QPlainTextEdit):
    edit_requested = Signal()
    dialog_edit_requested = Signal()
    discard_requested = Signal()

    def __init__(self, title="", parent=None):
        super().__init__(parent)
        self.title = title
        self.setReadOnly(True)

        font = QFont("Consolas", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.setFont(font)
        self.highlighter = JsonHighlighter(self.document())
        self._setting_text = False
        self.full_text = ""
        self.textChanged.connect(self._sync_text)
        self.setToolTip("Body ichiga bosib tahrirlang; Ctrl+C yoki o‘ng tugma bilan nusxalang")

    def _sync_text(self):
        if not self._setting_text:
            self.full_text = super().toPlainText()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.edit_requested.emit()
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and len(self.full_text) > 65536:
            self.dialog_edit_requested.emit()
            return
        super().mouseDoubleClickEvent(event)

    def contextMenuEvent(self, event):
        menu = self.createStandardContextMenu()
        menu.addSeparator()
        menu.addAction(
            "Copy full body", lambda: QGuiApplication.clipboard().setText(self.toPlainText())
        )
        menu.addAction("Edit body…", self.dialog_edit_requested.emit)
        menu.addAction("Discard changes", self.discard_requested.emit)
        menu.exec(event.globalPos())

    def setPlainText(self, text):
        self.full_text = text
        preview = text[:65536]
        if len(text) > 65536:
            preview += "\n\n[Preview: 64 KiB. Tahrirlash/Nusxa olish to‘liq body’dan foydalanadi.]"
        self._setting_text = True
        try:
            super().setPlainText(preview)
        finally:
            self._setting_text = False

    def toPlainText(self):
        return getattr(self, "full_text", "")

    def clear(self):
        self.setPlainText("")

    def open_editor(self):
        dialog = EditorDialog(self.title, self.toPlainText(), self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.setPlainText(dialog.text())
            # We don't trigger signal here, let the caller handle it. Actually QPlainTextEdit doesn't emit textChanged when setPlainText is called in some contexts, but we should make sure changes are tracked.
            # Actually, `self.setPlainText` triggers `textChanged` naturally.


class JsonTreeDialog(QDialog):
    """Expand JSON branches on demand; cap each visible branch at 500 items."""

    def __init__(self, text, parent=None):
        super().__init__(parent)
        self.setWindowTitle("JSON tree — lazy preview")
        self.resize(750, 550)
        value = json.loads(text)
        self.values = {}
        layout = QVBoxLayout(self)
        tree = QTreeWidget()
        tree.setHeaderLabels(["Key", "Value"])
        tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(tree)

        def add(parent_item, key, item_value):
            label = (
                f"{len(item_value)} items"
                if isinstance(item_value, (dict, list))
                else json.dumps(item_value, ensure_ascii=False)
            )
            node = QTreeWidgetItem([str(key), label[:1000]])
            if isinstance(parent_item, QTreeWidget):
                parent_item.addTopLevelItem(node)
            else:
                parent_item.addChild(node)
            if isinstance(item_value, (dict, list)) and item_value:
                identity = str(id(node))
                self.values[identity] = item_value
                node.setData(0, Qt.ItemDataRole.UserRole, identity)
                node.addChild(QTreeWidgetItem(["Expand…", ""]))
            return node

        def expand(node):
            identity = node.data(0, Qt.ItemDataRole.UserRole)
            if identity not in self.values:
                return
            item_value = self.values.pop(identity)
            node.takeChildren()
            pairs = item_value.items() if isinstance(item_value, dict) else enumerate(item_value)
            for index, (key, child) in enumerate(pairs):
                if index >= 500:
                    node.addChild(
                        QTreeWidgetItem(["Preview limited to 500 items", "Copy body for full JSON"])
                    )
                    break
                add(node, key, child)

        tree.itemExpanded.connect(expand)
        root = add(tree, "$", value)
        root.setExpanded(True)


class CapturesPage(QWidget):
    mock_requested = Signal(dict)
    rules_changed = Signal()
    replay_finished = Signal(str)

    def __init__(self, store):
        super().__init__()
        self.store = store
        self.selected_id = None
        self.current_document = None
        self.req_snapshot = self.res_snapshot = None
        self._loading = False
        self._editing = False
        self._dirty = False
        self._last_revision = None
        self._shown_revision = None
        self.proxy_port = 8080
        self.proxy_password = ""
        self.proxy_auth = False
        self.proxy_ready = False
        self.ca_path = None
        self.preferences = QSettings("LocalTools", "Snare")
        self.pinned = set(self.preferences.value("pins/" + self.store.root.name, [], type=list))
        for prefix in ("req", "res"):
            setattr(self, prefix + "_initial_headers", "")
            setattr(self, prefix + "_initial_body", "")
        self.req_initial_method = self.req_initial_url = ""
        self.res_initial_status = 0
        layout = QVBoxLayout(self)
        controls = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Host, URL, RPC yoki mock bo‘yicha qidirish (Ctrl+F)")
        self.search_input.textChanged.connect(lambda: self.refresh(force=True))
        self.method_filter = QComboBox()
        self.method_filter.addItems(
            ["All methods", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
        )
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All status", "2xx", "3xx", "4xx", "5xx", "Errors", "Pending"])
        self.mock_filter = QCheckBox("Mock")
        self.pin_filter = QCheckBox("Pinned")
        for widget in (self.method_filter, self.status_filter):
            widget.currentTextChanged.connect(lambda: self.refresh(force=True))
        for widget in (self.mock_filter, self.pin_filter):
            widget.toggled.connect(lambda: self.refresh(force=True))
        self.pause = QCheckBox("Pause view")
        self.pause.setToolTip("Faqat ro‘yxat yangilanishini to‘xtatadi; so‘rovlar davom etadi")
        self.pause.toggled.connect(self.pause_changed)
        for widget in (
            self.search_input,
            self.method_filter,
            self.status_filter,
            self.mock_filter,
            self.pin_filter,
            self.pause,
        ):
            controls.addWidget(widget)
        layout.addLayout(controls)
        actions = QHBoxLayout()
        for title, callback in [
            ("Copy cURL", self.copy_curl),
            ("HAR Import", self.har_import),
            ("HAR Export", self.har_export),
            ("Clear", self.clear),
        ]:
            actions.addWidget(button(title, callback))
        actions.addStretch()
        self.info = QLabel("Trafikni tanlang. HTTPS uchun CA sertifikatiga ishonch kerak.")
        self.info.setProperty("role", "muted")
        actions.addWidget(self.info)
        layout.addLayout(actions)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.splitter = splitter
        layout.addWidget(splitter, 1)
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["Time", "Method", "URL", "Status", "ms", "Size", "Mock"]
        )
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().hide()
        for index in range(7):
            self.table.horizontalHeader().setSectionResizeMode(
                index, QHeaderView.ResizeMode.ResizeToContents
            )
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.itemSelectionChanged.connect(self.show_selected)
        self.table.setMouseTracking(True)
        self.table.viewport().installEventFilter(self)
        self.table.verticalScrollBar().valueChanged.connect(lambda: self.row_actions.hide())
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.traffic_menu)
        self.hover_id = None
        self.row_actions = QWidget(self.table.viewport())
        row_controls = QHBoxLayout(self.row_actions)
        row_controls.setContentsMargins(2, 1, 2, 1)
        row_controls.setSpacing(3)
        self.row_replay = button("Replay", lambda: self.replay(self.row_replay.property("target")))
        self.row_pin = button("Pin", lambda: self.pin(self.row_pin.property("target")))
        for control in (self.row_replay, self.row_pin):
            control.pressed.connect(lambda c=control: c.setProperty("target", self.hover_id))
        self.row_play = button("Play", self.resume_view)
        self.row_play.setToolTip("Trafik ro‘yxati yangilanishini davom ettirish")
        for control in (self.row_replay, self.row_pin, self.row_play):
            control.setStyleSheet("padding: 2px 6px; min-height: 16px;")
            row_controls.addWidget(control)
        self.row_actions.hide()
        splitter.addWidget(self.table)
        self.details = QTabWidget()
        splitter.addWidget(self.details)
        splitter.setSizes([640, 560])
        for prefix, title in (("req", "Request"), ("res", "Response")):
            panel = QWidget()
            form = QVBoxLayout(panel)
            toolbar = QHBoxLayout()
            view = QComboBox()
            view.addItems(["Modified", "Original", "Diff"])
            setattr(self, prefix + "_view", view)
            toolbar.addWidget(view)
            form.addLayout(toolbar)
            fields = QFormLayout()
            if prefix == "req":
                self.req_method = QLineEdit()
                self.req_url = QLineEdit()
                fields.addRow("Method", self.req_method)
                fields.addRow("URL", self.req_url)
            else:
                self.res_status = QSpinBox()
                self.res_status.setRange(0, 599)
                fields.addRow("Status", self.res_status)
                self.res_info = QLabel()
                self.res_info.setWordWrap(True)
                form.addWidget(self.res_info)
            form.addLayout(fields)
            headers = HeadersTableWidget(title + " Headers")
            headers.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            setattr(self, prefix + "_headers", headers)
            headers.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            headers.customContextMenuRequested.connect(
                lambda pos, p=prefix: self.headers_menu(p, pos)
            )
            form.addWidget(QLabel("Headers"))
            form.addWidget(headers, 1)
            body = BodyTextEdit(title + " Body")
            setattr(self, prefix + "_body", body)
            body_row = QHBoxLayout()
            body_row.addWidget(QLabel("Body"))
            body_row.addStretch()
            body_row.addWidget(button("JSON tree", lambda p=prefix: self.json_tree(p)))
            body_row.addWidget(button("Raw / Hex", lambda p=prefix: self.raw_body(p)))
            body.edit_requested.connect(lambda p=prefix: self.inline_body(p))
            body.dialog_edit_requested.connect(lambda p=prefix: self.edit_body(p))
            body.discard_requested.connect(self.discard)
            form.addLayout(body_row)
            form.addWidget(body, 2)
            save = button(
                "Apply → Mock qoida",
                self.save_req_mock if prefix == "req" else self.save_res_mock,
            )
            save.setProperty("role", "primary")
            save.hide()
            setattr(self, prefix + "_save_btn", save)
            form.addWidget(save)
            if prefix == "res":
                self.res_fixture_btn = button(
                    "Local fixture yaratish", lambda: self.save_mock("final")
                )
                form.addWidget(self.res_fixture_btn)
            view.currentIndexChanged.connect(lambda: self.reload_selected())
            self.details.addTab(panel, title)
        self.stream = QPlainTextEdit()
        self.stream.setReadOnly(True)
        self.details.addTab(self.stream, "WebSocket / SSE")
        self.req_method.setReadOnly(True)
        self.req_url.setReadOnly(True)
        self.res_status.setEnabled(False)
        for widget in (self.req_method, self.req_url, self.req_headers, self.req_body):
            widget.textChanged.connect(self.check_req_changes)
        self.res_status.valueChanged.connect(self.check_res_changes)
        self.res_headers.textChanged.connect(self.check_res_changes)
        self.res_body.textChanged.connect(self.check_res_changes)
        self.replay_finished.connect(self.info.setText)
        QShortcut(QKeySequence("Ctrl+F"), self, activated=self.search_input.setFocus)
        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.refresh)
        self.timer.start()
        self.refresh(force=True)

    def pause_changed(self, checked):
        self.row_actions.hide()
        if not checked:
            self.refresh(force=True)

    def resume_view(self):
        self.pause.setChecked(False)

    def eventFilter(self, watched, event):
        if watched is self.table.viewport():
            if event.type() == QEvent.Type.MouseMove:
                self.show_row_actions(self.table.rowAt(int(event.position().y())))
            elif event.type() == QEvent.Type.Leave:
                if (
                    not self.table.viewport()
                    .rect()
                    .contains(self.table.viewport().mapFromGlobal(QCursor.pos()))
                ):
                    self.row_actions.hide()
        return super().eventFilter(watched, event)

    def show_row_actions(self, row):
        if row < 0 or not self.table.item(row, 0):
            self.row_actions.hide()
            return
        self.hover_id = self.table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        self.row_pin.setText("Unpin" if self.hover_id in self.pinned else "Pin")
        self.row_play.setVisible(self.pause.isChecked())
        self.row_replay.setEnabled(self.proxy_ready)
        self.row_actions.adjustSize()
        rect = self.table.visualItemRect(self.table.item(row, 2))
        x = max(0, self.table.viewport().width() - self.row_actions.width() - 2)
        self.row_actions.move(x, rect.top())
        self.row_actions.show()
        self.row_actions.raise_()

    def traffic_menu(self, pos):
        row = self.table.rowAt(pos.y())
        if row < 0:
            row = self.table.currentRow()
        if row < 0:
            return
        fid = self.table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        menu = QMenu(self.table)
        action = menu.addAction("Replay", lambda: self.replay(fid))
        action.setEnabled(self.proxy_ready)
        menu.addAction("Unpin" if fid in self.pinned else "Pin", lambda: self.pin(fid))
        if self.pause.isChecked():
            menu.addAction("Play — resume view", self.resume_view)
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def headers_menu(self, prefix, pos):
        table = getattr(self, prefix + "_headers")
        menu = QMenu(table)
        menu.addAction(
            "Copy selected",
            lambda: QGuiApplication.clipboard().setText(
                "\n".join(item.text() for item in table.selectedItems())
            ),
        )
        menu.addAction(
            "Copy all headers", lambda: QGuiApplication.clipboard().setText(table.toPlainText())
        )
        menu.addAction("Edit headers…", lambda: self.edit_headers(prefix))
        menu.addAction("Discard changes", self.discard)
        menu.exec(table.viewport().mapToGlobal(pos))

    def edit_headers(self, prefix):
        if self.current_document:
            self.begin_edit(prefix)
            getattr(self, prefix + "_headers").open_editor()

    def refresh(self, force=False):
        if self.pause.isChecked() and not force:
            return
        try:
            rows = self.store.capture_rows(
                self.search_input.text().strip(),
                self.method_filter.currentText() if self.method_filter.currentIndex() else "",
                self.status_filter.currentText() if self.status_filter.currentIndex() else "",
                self.mock_filter.isChecked(),
            )
            if self.pin_filter.isChecked():
                rows = [r for r in rows if r[0] in self.pinned]
            revision = tuple(rows)
            if not force and revision == self._last_revision:
                return
            self._last_revision = revision
            self.row_actions.hide()
            self.table.blockSignals(True)
            self.table.setRowCount(len(rows))
            selected = None
            for row, data in enumerate(rows):
                (
                    fid,
                    created,
                    method,
                    url,
                    status,
                    mock,
                    duration,
                    size,
                    pending,
                    error,
                ) = data
                texts = [
                    datetime.fromtimestamp(created).strftime("%H:%M:%S"),
                    method,
                    ("* " if fid in self.pinned else "") + url,
                    "Pending"
                    if pending
                    else (str(status) if status else "Error" if error else "—"),
                    str(round(duration or 0)),
                    f"{(size or 0) / 1024:.1f}K",
                    mock or "",
                ]
                for column, text in enumerate(texts):
                    item = self.table.item(row, column)
                    if item is None:
                        item = text_item(text)
                        self.table.setItem(row, column, item)
                    else:
                        item.setText(text)
                    item.setToolTip(str(url if column == 2 else error or text))
                    item.setData(Qt.ItemDataRole.UserRole, fid)
                if fid == self.selected_id:
                    selected = row
            self.table.clearSelection()
            if selected is not None:
                self.table.selectRow(selected)
            self.table.blockSignals(False)
            if selected is not None and not self._dirty:
                self.show_selected()
            cursor = self.table.viewport().mapFromGlobal(QCursor.pos())
            if self.table.viewport().rect().contains(cursor):
                self.show_row_actions(self.table.rowAt(cursor.y()))
            stats = self.store.statistics()
            self.info.setText(
                f"{len(rows)} / {stats['count']} capture · {stats['bytes'] / 1024 / 1024:.1f} MiB"
                + (" · Draft saqlanmagan" if self._dirty else "")
            )
        except Exception as exc:
            self.table.blockSignals(False)
            self.info.setText(f"Storage: {exc}")

    def can_leave(self):
        if not self._dirty:
            return True
        answer = QMessageBox.question(
            self,
            "Saqlanmagan tahrir",
            "Draft saqlanmagan. Uni bekor qilib davom etilsinmi?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        return answer == QMessageBox.StandardButton.Yes

    def show_selected(self):
        row = self.table.currentRow()
        if row < 0 or not self.table.selectedItems():
            return
        fid = self.table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        if fid != self.selected_id and not self.can_leave():
            self.table.blockSignals(True)
            for i in range(self.table.rowCount()):
                if self.table.item(i, 0).data(Qt.ItemDataRole.UserRole) == self.selected_id:
                    self.table.selectRow(i)
                    break
            self.table.blockSignals(False)
            return
        if fid != self.selected_id:
            self.finish_edit()
        self.selected_id = fid
        if self._dirty:
            return
        doc = self.store.capture(fid)
        if not doc:
            return
        revision = json.dumps(doc, sort_keys=True)
        if revision == self._shown_revision:
            return
        self.current_document = doc
        self._shown_revision = revision
        self.render_document()

    def reload_selected(self):
        if self._loading:
            return
        if not self.can_leave():
            return
        self.finish_edit()
        self._shown_revision = None
        self.render_document()

    def render_document(self):
        doc = self.current_document
        if not doc:
            return
        self._loading = True
        try:
            for prefix, original, modified in (
                (
                    "req",
                    doc.get("request_original") or doc.get("request"),
                    doc.get("request"),
                ),
                ("res", doc.get("original"), doc.get("final")),
            ):
                view = getattr(self, prefix + "_view").currentText()
                snap = original if view == "Original" else modified
                setattr(self, prefix + "_snapshot", snap)
                text = self.decode_body(snap)
                if view == "Diff":
                    text = (
                        "\n".join(
                            difflib.unified_diff(
                                self.decode_body(original).splitlines()[:3000],
                                self.decode_body(modified).splitlines()[:3000],
                                fromfile="Original",
                                tofile="Modified",
                                lineterm="",
                            )
                        )
                        or "Body o‘zgarmagan"
                    )
                headers = "\n".join(f"{k}: {v}" for k, v in (snap or {}).get("headers", []))
                setattr(self, prefix + "_initial_headers", headers)
                setattr(self, prefix + "_initial_body", text)
                getattr(self, prefix + "_headers").setPlainText(headers)
                getattr(self, prefix + "_body").setReadOnly(True)
                getattr(self, prefix + "_body").setPlainText(text)
                editable = view != "Diff" and bool(snap)
                getattr(self, prefix + "_headers").setEditTriggers(
                    QAbstractItemView.EditTrigger.DoubleClicked
                    | QAbstractItemView.EditTrigger.SelectedClicked
                    | QAbstractItemView.EditTrigger.EditKeyPressed
                    if editable
                    else QAbstractItemView.EditTrigger.NoEditTriggers
                )
                if prefix == "req":
                    self.req_method.setReadOnly(not editable)
                    self.req_url.setReadOnly(not editable)
                else:
                    self.res_status.setEnabled(editable)
                if prefix == "req":
                    self.req_initial_method = (snap or {}).get("method", doc["method"])
                    self.req_initial_url = (snap or {}).get("url", doc["url"])
                    self.req_method.setText(self.req_initial_method)
                    self.req_url.setText(self.req_initial_url)
                else:
                    self.res_initial_status = (snap or {}).get("status", 0)
                    self.res_status.setValue(self.res_initial_status)
                    self.res_info.setText(
                        f"{(snap or {}).get('body_size', 0)} bytes"
                        + (
                            " · TRUNCATED: to‘liq body saqlanmagan"
                            if (snap or {}).get("truncated")
                            else ""
                        )
                        + (f" · {doc['error']}" if doc.get("error") else "")
                    )
            self.stream.setPlainText(
                "\n\n".join(
                    f"{m['direction']} · {m['size']} bytes\n{m['text']}"
                    for m in doc.get("messages", [])
                )
                or "WebSocket yoki SSE xabarlari yo‘q"
            )
            self.req_save_btn.hide()
            self.res_save_btn.hide()
        finally:
            self._loading = False

    def decode_body(self, snapshot):
        if not snapshot:
            return ""
        raw = base64.b64decode(snapshot.get("body_b64", ""))
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return f"<binary {len(raw)} bytes>\n" + raw[:2048].hex(" ")
        if len(raw) <= 65536:
            try:
                return json.dumps(json.loads(text), ensure_ascii=False, indent=2)
            except ValueError:
                pass
        return text

    def json_tree(self, prefix):
        try:
            JsonTreeDialog(getattr(self, prefix + "_body").toPlainText(), self).exec()
        except ValueError as exc:
            QMessageBox.warning(self, "JSON tree", str(exc))

    def raw_body(self, prefix):
        snap = getattr(self, prefix + "_snapshot")
        if not snap:
            return
        raw = base64.b64decode(snap.get("body_b64", ""))
        dialog = EditorDialog(
            "Raw / Hex",
            raw[:65536].decode("utf-8", errors="replace")
            + "\n\nHEX (first 1024 bytes):\n"
            + raw[:1024].hex(" "),
            self,
        )
        dialog.editor.setReadOnly(True)
        dialog.exec()

    def begin_edit(self, prefix):
        if not self.current_document:
            return
        view = getattr(self, prefix + "_view")
        if view.currentText() == "Diff":
            view.setCurrentIndex(0)
        self._editing = True
        if prefix == "req":
            self.req_method.setReadOnly(False)
            self.req_url.setReadOnly(False)
        else:
            self.res_status.setEnabled(True)
        getattr(self, prefix + "_headers").setEditTriggers(
            QAbstractItemView.EditTrigger.DoubleClicked
            | QAbstractItemView.EditTrigger.SelectedClicked
            | QAbstractItemView.EditTrigger.EditKeyPressed
        )
        self.info.setText("Draft · Apply → Mock; bekor qilish uchun o‘ng tugma → Discard changes")

    def inline_body(self, prefix):
        body = getattr(self, prefix + "_body")
        if not self.current_document or getattr(self, prefix + "_view").currentText() == "Diff":
            return
        # Large previews remain bounded; double-click opens the full editor.
        if len(body.toPlainText()) > 65536 or not body.isReadOnly():
            return
        snap = getattr(self, prefix + "_snapshot")
        if not snap or snap.get("truncated") or body.toPlainText().startswith("<binary"):
            return
        self.begin_edit(prefix)
        body.setReadOnly(False)

    def edit_body(self, prefix):
        self.begin_edit(prefix)
        snap = getattr(self, prefix + "_snapshot")
        if not self.guard_body(snap, True):
            return
        if any("<binary" in getattr(self, prefix + "_body").toPlainText() for _ in [0]):
            QMessageBox.warning(self, "Binary", "Binary body uchun Fixture qoidasidan foydalaning")
            return
        getattr(self, prefix + "_body").open_editor()

    def finish_edit(self):
        self._editing = False
        self._dirty = False
        self.req_method.setReadOnly(True)
        self.req_url.setReadOnly(True)
        self.res_status.setEnabled(False)
        for p in ("req", "res"):
            getattr(self, p + "_headers").setEditTriggers(
                QAbstractItemView.EditTrigger.NoEditTriggers
            )
            getattr(self, p + "_body").setReadOnly(True)
            getattr(self, p + "_save_btn").hide()

    def discard(self):
        self.finish_edit()
        self._shown_revision = None
        self.render_document()

    def check_req_changes(self):
        if self._loading or not self.req_snapshot:
            return
        self._editing = True
        changed = (
            self.req_method.text() != self.req_initial_method
            or self.req_url.text() != self.req_initial_url
            or self.req_headers.toPlainText() != self.req_initial_headers
            or self.req_body.toPlainText() != self.req_initial_body
        )
        self.req_save_btn.setVisible(changed)
        self._dirty = changed or not self.res_save_btn.isHidden()

    def check_res_changes(self):
        if self._loading or not self.res_snapshot:
            return
        self._editing = True
        changed = (
            self.res_status.value() != self.res_initial_status
            or self.res_headers.toPlainText() != self.res_initial_headers
            or self.res_body.toPlainText() != self.res_initial_body
        )
        self.res_save_btn.setVisible(changed)
        self._dirty = changed or not self.req_save_btn.isHidden()

    def guard_body(self, snapshot, changed):
        if not snapshot:
            return False
        if changed and snapshot.get("truncated"):
            QMessageBox.warning(
                self,
                "Kesilgan body",
                "To‘liq body saqlanmagan. Header-only patch mumkin; body replacement bloklangan.",
            )
            return False
        return True

    def copy_curl(self):
        if not self.current_document:
            return
        try:
            QGuiApplication.clipboard().setText(curl_command(self.current_document))
            self.info.setText("cURL nusxalandi — POSIX shell sintaksisi")
        except ValueError as exc:
            QMessageBox.warning(self, "cURL", str(exc))

    def replay(self, fid=None):
        document = self.store.capture(fid) if fid else self.current_document
        if not document or not self.proxy_ready:
            QMessageBox.warning(self, "Replay", "Engine tayyor bo‘lishi va trafik tanlanishi kerak")
            return
        doc = json.loads(json.dumps(document))
        snapshot = doc.get("request_original") or doc.get("request") or {}
        if snapshot.get("truncated") or doc.get("redacted"):
            QMessageBox.warning(self, "Replay", "Kesilgan yoki redacted request qayta yuborilmaydi")
            return
        if snapshot.get("method", doc["method"]) not in ("GET", "HEAD", "OPTIONS"):
            if (
                QMessageBox.question(
                    self,
                    "Replay",
                    "Bu request serverda ma’lumotni o‘zgartirishi mumkin. Qayta yuborilsinmi?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                != QMessageBox.StandardButton.Yes
            ):
                return
        url = snapshot.get("url", doc["url"])
        port = self.proxy_port
        ca = self.ca_path
        auth = self.proxy_auth
        password = self.proxy_password

        def send():
            try:
                context = (
                    ssl.create_default_context(cafile=str(ca))
                    if ca and ca.exists()
                    else ssl.create_default_context()
                )
                proxy = f"http://127.0.0.1:{port}"
                opener = build_opener(
                    ProxyHandler({"http": proxy, "https": proxy}),
                    HTTPSHandler(context=context),
                )
                # Explicit proxy on Request prevents environment NO_PROXY bypass.
                request = Request(
                    url,
                    data=base64.b64decode(snapshot.get("body_b64", "")) or None,
                    method=snapshot.get("method", doc["method"]),
                )
                for k, v in snapshot.get("headers", []):
                    if k.lower() not in ("host", "content-length", "transfer-encoding"):
                        request.add_header(k, v)
                if auth:
                    request.add_header(
                        "Proxy-Authorization",
                        "Basic " + base64.b64encode(f"snare:{password}".encode()).decode(),
                    )
                request.set_proxy(f"127.0.0.1:{port}", urlsplit(url).scheme)
                with opener.open(request, timeout=30) as response:
                    response.read(2 * 1024 * 1024)
                self.replay_finished.emit("Replay tugadi; yangi trafik tarixda")
            except Exception as exc:
                self.replay_finished.emit(f"Replay: {exc}")

        threading.Thread(target=send, daemon=True).start()

    def pin(self, fid=None):
        fid = fid or self.selected_id
        if fid:
            if fid in self.pinned:
                self.pinned.remove(fid)
            else:
                self.pinned.add(fid)
            self.preferences.setValue("pins/" + self.store.root.name, sorted(self.pinned))
            self.refresh(force=True)

    def har_export(self):
        filename, _ = QFileDialog.getSaveFileName(
            self, "Sanitized HAR export", "traffic.har", "HAR (*.har)"
        )
        if not filename:
            return
        QMessageBox.information(
            self,
            "HAR eksport",
            "Header va JSON’dagi odatiy secret maydonlar yashiriladi. Boshqa matn/binary ichidagi maxfiy ma’lumotni ulashishdan oldin tekshiring.",
        )
        try:
            export_har(self.store, Path(filename), sanitize=True)
        except Exception as exc:
            QMessageBox.warning(self, "HAR", str(exc))

    def har_import(self):
        filename, _ = QFileDialog.getOpenFileName(self, "HAR import", "", "HAR (*.har)")
        if not filename:
            return
        try:
            import_har(self.store, Path(filename))
            self.refresh(force=True)
        except Exception as exc:
            QMessageBox.warning(self, "HAR", str(exc))

    def clear_panels(self):
        self.finish_edit()
        self.selected_id = None
        self.current_document = None
        self.req_snapshot = self.res_snapshot = None
        self._shown_revision = None
        self._loading = True
        self.req_method.clear()
        self.req_url.clear()
        self.req_headers.setPlainText("")
        self.req_body.clear()
        self.res_headers.setPlainText("")
        self.res_body.clear()
        self.res_info.clear()
        self.stream.clear()
        self._loading = False

    def clear(self):
        if not self.can_leave():
            return
        if (
            QMessageBox.question(
                self, "Trafiklarni tozalash", "Barcha capture tarixi o‘chirilsinmi?"
            )
            == QMessageBox.StandardButton.Yes
        ):
            try:
                self.store.clear_captures()
                self.clear_panels()
                self.refresh(force=True)
            except Exception as exc:
                QMessageBox.warning(self, "Storage", str(exc))

    @staticmethod
    def header_changes(original: list, edited: list) -> tuple[list, list]:
        def grouped(pairs):
            result = {}
            for name, value in pairs:
                result.setdefault(name.lower(), []).append([name, value])
            return result

        before = grouped(original)
        after = grouped(edited)
        replacements = []
        for name, values in after.items():
            if values != before.get(name):
                replacements.extend(values)
        removed = [values[0][0] for name, values in before.items() if name not in after]
        return replacements, removed

    def build_conditions(self, parsed, req_snapshot):
        conds = [
            {"source": "query", "key": k, "op": "equals", "value": v}
            for k, v in parse_qsl(parsed.query, keep_blank_values=True)
        ]

        # Parse request body to extract RPC methods
        if req_snapshot and req_snapshot.get("body_b64"):
            try:
                raw = base64.b64decode(req_snapshot["body_b64"]).decode("utf-8")
                body = json.loads(raw)
                if isinstance(body, dict):
                    for key in ["method", "action", "operationName"]:
                        if key in body and isinstance(body[key], str):
                            conds.append(
                                {
                                    "source": "json",
                                    "key": key,
                                    "op": "equals",
                                    "value": body[key],
                                }
                            )
            except Exception:
                pass
        return conds

    def generate_rule_name(self, method, path, conditions, prefix=""):
        rpc = ""
        for c in conditions:
            if c.get("source") == "json" and c.get("key") in (
                "method",
                "action",
                "operationName",
            ):
                rpc = f" [{c['value']}]"
                break
        short_path = path or "/"
        if len(short_path) > 40:
            short_path = "..." + short_path[-37:]
        base = f"{method} {short_path}{rpc}"
        return f"{prefix} {base}".strip()

    def parse_headers_text(self, text):
        headers = []
        for line in text.split("\n"):
            line = line.strip()
            if not line:
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                headers.append([k.strip(), v.strip()])
            else:
                headers.append([line, ""])
        return headers

    def save_req_mock(self):
        if not self.guard_body(
            self.req_snapshot, self.req_body.toPlainText() != self.req_initial_body
        ):
            return
        headers = self.parse_headers_text(self.req_headers.toPlainText())

        doc = self.current_document
        target = doc.get("request_original") or doc.get("request") or {}
        parsed = urlsplit(target.get("url", doc["url"]))
        replacements, removed = self.header_changes(self.req_snapshot["headers"], headers)

        body_changed = self.req_body.toPlainText() != self.req_initial_body
        method_changed = self.req_method.text() != self.req_initial_method
        url_changed = self.req_url.text() != self.req_initial_url

        body_patch = None
        if body_changed:
            try:
                orig_json = json.loads(self.req_initial_body)
                edited_json = json.loads(self.req_body.toPlainText())
                body_patch = deep_diff(orig_json, edited_json)
            except Exception:
                pass

        conditions = self.build_conditions(parsed, self.req_snapshot)
        rule = default_rule()
        rule.update(
            {
                "name": self.generate_rule_name(
                    doc["method"], parsed.path, conditions, "ReqPatch:"
                ),
                "method": target.get("method", doc["method"]),
                "host": parsed.hostname or "",
                "path": parsed.path or "/",
                "action": "request_patch",
                "status": 0,
                "headers": replacements,
                "remove_headers": removed,
                "body": self.req_body.toPlainText() if body_changed else "",
                "body_patch": body_patch,
                "body_base": self.req_initial_body if body_patch is not None else "",
                "preserve_body": not body_changed,
                "rewrite_method": self.req_method.text() if method_changed else "",
                "rewrite_url": self.req_url.text() if url_changed else "",
                "conditions": conditions,
            }
        )

        try:
            self.store.save_rules(self.store.load_rules() + [rule])
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "Saqlash xatosi", str(exc))
            return
        self.rules_changed.emit()
        self.req_save_btn.setVisible(False)
        self.req_initial_method = self.req_method.text()
        self.req_initial_url = self.req_url.text()
        self.req_initial_headers = self.req_headers.toPlainText()
        self.req_initial_body = self.req_body.toPlainText()
        self.req_snapshot = {
            **self.req_snapshot,
            "headers": headers,
            "body_b64": base64.b64encode(self.req_body.toPlainText().encode()).decode(),
        }
        self.finish_edit()
        self._shown_revision = None
        self.render_document()
        QMessageBox.information(
            self,
            "Muvaffaqiyatli",
            "So'rovni o'zgartirish (Request Patch) qoidasi saqlandi!",
        )

    def save_res_mock(self):
        if not self.guard_body(
            self.res_snapshot, self.res_body.toPlainText() != self.res_initial_body
        ):
            return
        headers = self.parse_headers_text(self.res_headers.toPlainText())

        doc = self.current_document
        target = doc.get("request_original") or doc.get("request") or {}
        parsed = urlsplit(target.get("url", doc["url"]))
        replacements, removed = self.header_changes(self.res_snapshot["headers"], headers)

        body_changed = self.res_body.toPlainText() != self.res_initial_body
        status_changed = self.res_status.value() != self.res_initial_status

        body_patch = None
        if body_changed:
            try:
                orig_json = json.loads(self.res_initial_body)
                edited_json = json.loads(self.res_body.toPlainText())
                body_patch = deep_diff(orig_json, edited_json)
            except Exception:
                pass

        conditions = self.build_conditions(parsed, self.req_snapshot)
        rule = default_rule()
        rule.update(
            {
                "name": self.generate_rule_name(doc["method"], parsed.path, conditions),
                "method": target.get("method", doc["method"]),
                "host": parsed.hostname or "",
                "path": parsed.path or "/",
                "action": "patch",
                "status": self.res_status.value() if status_changed else 0,
                "headers": replacements,
                "remove_headers": removed,
                "body": self.res_body.toPlainText() if body_changed else "",
                "body_patch": body_patch,
                "body_base": self.res_initial_body if body_patch is not None else "",
                "preserve_body": not body_changed,
                "conditions": conditions,
            }
        )

        try:
            self.store.save_rules(self.store.load_rules() + [rule])
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "Saqlash xatosi", str(exc))
            return
        self.rules_changed.emit()
        self.res_save_btn.setVisible(False)
        self.res_initial_status = self.res_status.value()
        self.res_initial_headers = self.res_headers.toPlainText()
        self.res_initial_body = self.res_body.toPlainText()
        self.res_snapshot = {
            **self.res_snapshot,
            "headers": headers,
            "body_b64": base64.b64encode(self.res_body.toPlainText().encode()).decode(),
        }
        self.finish_edit()
        self._shown_revision = None
        self.render_document()
        QMessageBox.information(self, "Muvaffaqiyatli", "Javob mock qoidasi saqlandi!")

    def save_mock(self, source: str):
        if not self.selected_id:
            return
        try:
            document = self.store.capture(self.selected_id)
            snapshot = document.get(source)
            if not snapshot:
                raise ValueError("Javob (Response) ma'lumoti topilmadi")
            if snapshot.get("truncated"):
                raise ValueError("Tana (Body) qismi to'liq saqlanmagan (kesilgan)!")

            fixture_id = self.store.put_fixture(base64.b64decode(snapshot["body_b64"]))
            parsed = urlsplit(document["url"])
            conditions = self.build_conditions(parsed, self.req_snapshot)
            rule = default_rule()
            rule.update(
                {
                    "name": self.generate_rule_name(
                        document["method"], parsed.path, conditions, "Local:"
                    ),
                    "method": document["method"],
                    "host": parsed.hostname or "",
                    "path": parsed.path or "/",
                    "status": snapshot["status"],
                    "headers": snapshot["headers"],
                    "fixture": fixture_id,
                    "conditions": conditions,
                }
            )
            self.mock_requested.emit(rule)
        except Exception as exc:
            QMessageBox.warning(self, "Xatolik", str(exc))
