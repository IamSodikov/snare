import base64
import json
from urllib.parse import parse_qsl, urlsplit

from PySide6.QtCore import QRegularExpression, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QGuiApplication, QSyntaxHighlighter, QTextCharFormat
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
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
        self.editor.setTabStopDistance(self.editor.fontMetrics().horizontalAdvance(' ') * 2)
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
            if k: lines.append(f"{k}: {v}")
        return "\n".join(lines)
        
    def setPlainText(self, text):
        self.blockSignals(True)
        self.setRowCount(0)
        for line in text.splitlines():
            line = line.strip()
            if not line: continue
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
    def __init__(self, title="", parent=None):
        super().__init__(parent)
        self.title = title
        self.setReadOnly(True)
        
        font = QFont("Consolas", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.setFont(font)
        self.highlighter = JsonHighlighter(self.document())
        
    def open_editor(self):
        dialog = EditorDialog(self.title, self.toPlainText(), self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.setPlainText(dialog.text())
            # We don't trigger signal here, let the caller handle it. Actually QPlainTextEdit doesn't emit textChanged when setPlainText is called in some contexts, but we should make sure changes are tracked.
            # Actually, `self.setPlainText` triggers `textChanged` naturally.


class CapturesPage(QWidget):
    mock_requested = Signal(dict)
    rules_changed = Signal()

    def __init__(self, store):
        super().__init__()
        self.store = store
        self.selected_id = None
        
        self.req_initial_method = ""
        self.req_initial_url = ""
        self.req_initial_headers = ""
        self.req_initial_body = ""
        
        self.res_initial_status = 0
        self.res_initial_headers = ""
        self.res_initial_body = ""
        
        self.current_document = None
        self.req_snapshot = None
        self.res_snapshot = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        controls = QHBoxLayout()
        title = QLabel("Jonli trafiklar")
        title.setStyleSheet("font-size: 16px; font-weight: 700;")
        controls.addWidget(title)
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("URL manzili, metod, holat kodi yoki mock bo'yicha qidirish...")
        self.search_input.textChanged.connect(self.refresh)
        controls.addWidget(self.search_input)
        
        controls.addStretch()
        controls.addWidget(button("Trafiklarni tozalash", self.clear))
        layout.addLayout(controls)

        self.info = QLabel("")
        self.info.setStyleSheet("color: red;")
        layout.addWidget(self.info)

        splitter = QSplitter()
        layout.addWidget(splitter, 1)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Method", "URL", "RPC Method", "Status", "Mock"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.itemSelectionChanged.connect(self.show_selected)

        splitter.addWidget(self.table)

        self.details = QTabWidget()
        
        # --- REQUEST TAB ---
        self.req_panel = QWidget()
        req_layout = QVBoxLayout(self.req_panel)
        
        req_form = QFormLayout()
        self.req_method = QLineEdit()
        self.req_url = QLineEdit()
        
        req_form.addRow("Method:", self.req_method)
        req_form.addRow("URL:", self.req_url)
        
        req_layout.addLayout(req_form)
        
        req_splitter = QSplitter(Qt.Orientation.Vertical)
        
        self.req_headers = HeadersTableWidget("Request Headers")
        req_headers_w = QWidget()
        rhl = QVBoxLayout(req_headers_w)
        rhl.setContentsMargins(0, 0, 0, 0)
        req_h_top = QHBoxLayout()
        req_h_top.addWidget(QLabel("Headers:"))
        req_h_top.addStretch()
        btn_req_h_edit = QPushButton("📝 Tahrirlash")
        btn_req_h_edit.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_req_h_edit.setStyleSheet("QPushButton { border:none; color: #0284c7; font-weight: bold; background: transparent; } QPushButton:hover { text-decoration: underline; }")
        btn_req_h_edit.clicked.connect(self.req_headers.open_editor)
        req_h_top.addWidget(btn_req_h_edit)
        rhl.addLayout(req_h_top)
        rhl.addWidget(self.req_headers)
        
        self.req_body = BodyTextEdit("Request Body")
        req_body_w = QWidget()
        rbl = QVBoxLayout(req_body_w)
        rbl.setContentsMargins(0, 0, 0, 0)
        req_b_top = QHBoxLayout()
        req_b_top.addWidget(QLabel("Body:"))
        req_b_top.addStretch()
        
        btn_req_b_copy = QPushButton("📋 Nusxa olish")
        btn_req_b_copy.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_req_b_copy.setStyleSheet("QPushButton { border:none; color: #16a34a; font-weight: bold; background: transparent; } QPushButton:hover { text-decoration: underline; }")
        btn_req_b_copy.clicked.connect(lambda: QGuiApplication.clipboard().setText(self.req_body.toPlainText()))
        req_b_top.addWidget(btn_req_b_copy)
        
        btn_req_b_edit = QPushButton("📝 Tahrirlash")
        btn_req_b_edit.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_req_b_edit.setStyleSheet("QPushButton { border:none; color: #0284c7; font-weight: bold; background: transparent; } QPushButton:hover { text-decoration: underline; }")
        btn_req_b_edit.clicked.connect(self.req_body.open_editor)
        req_b_top.addWidget(btn_req_b_edit)
        rbl.addLayout(req_b_top)
        rbl.addWidget(self.req_body)
        
        req_splitter.addWidget(req_headers_w)
        req_splitter.addWidget(req_body_w)
        
        req_layout.addWidget(req_splitter)
        
        self.req_save_btn = button("💾 Request Mock sifatida saqlash", self.save_req_mock)
        self.req_save_btn.setObjectName("actionBtnReq")
        self.req_save_btn.setVisible(False)
        req_layout.addWidget(self.req_save_btn)
        self.details.addTab(self.req_panel, "Request")
        
        # --- RESPONSE TAB ---
        self.res_panel = QWidget()
        res_layout = QVBoxLayout(self.res_panel)
        
        self.res_info = QLabel("")
        self.res_info.setWordWrap(True)
        res_layout.addWidget(self.res_info)
        
        res_form = QFormLayout()
        self.res_status = QSpinBox()
        self.res_status.setRange(0, 599)
        
        res_form.addRow("Status:", self.res_status)
        
        res_layout.addLayout(res_form)
        
        res_splitter = QSplitter(Qt.Orientation.Vertical)
        
        self.res_headers = HeadersTableWidget("Response Headers")
        res_headers_w = QWidget()
        reshl = QVBoxLayout(res_headers_w)
        reshl.setContentsMargins(0, 0, 0, 0)
        res_h_top = QHBoxLayout()
        res_h_top.addWidget(QLabel("Headers:"))
        res_h_top.addStretch()
        btn_res_h_edit = QPushButton("📝 Tahrirlash")
        btn_res_h_edit.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_res_h_edit.setStyleSheet("QPushButton { border:none; color: #0284c7; font-weight: bold; background: transparent; } QPushButton:hover { text-decoration: underline; }")
        btn_res_h_edit.clicked.connect(self.res_headers.open_editor)
        res_h_top.addWidget(btn_res_h_edit)
        reshl.addLayout(res_h_top)
        reshl.addWidget(self.res_headers)
        
        self.res_body = BodyTextEdit("Response Body")
        res_body_w = QWidget()
        resbl = QVBoxLayout(res_body_w)
        resbl.setContentsMargins(0, 0, 0, 0)
        res_b_top = QHBoxLayout()
        res_b_top.addWidget(QLabel("Body:"))
        res_b_top.addStretch()
        
        btn_res_b_copy = QPushButton("📋 Nusxa olish")
        btn_res_b_copy.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_res_b_copy.setStyleSheet("QPushButton { border:none; color: #16a34a; font-weight: bold; background: transparent; } QPushButton:hover { text-decoration: underline; }")
        btn_res_b_copy.clicked.connect(lambda: QGuiApplication.clipboard().setText(self.res_body.toPlainText()))
        res_b_top.addWidget(btn_res_b_copy)
        
        btn_res_b_edit = QPushButton("📝 Tahrirlash")
        btn_res_b_edit.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_res_b_edit.setStyleSheet("QPushButton { border:none; color: #0284c7; font-weight: bold; background: transparent; } QPushButton:hover { text-decoration: underline; }")
        btn_res_b_edit.clicked.connect(self.res_body.open_editor)
        res_b_top.addWidget(btn_res_b_edit)
        resbl.addLayout(res_b_top)
        resbl.addWidget(self.res_body)
        
        res_splitter.addWidget(res_headers_w)
        res_splitter.addWidget(res_body_w)
        
        res_layout.addWidget(res_splitter)
        
        btn_layout = QHBoxLayout()
        self.res_save_btn = button("💾 Response Mock sifatida saqlash", self.save_res_mock)
        self.res_save_btn.setObjectName("actionBtnRes")
        self.res_save_btn.setVisible(False)
        btn_layout.addWidget(self.res_save_btn)
        
        self.res_fixture_btn = button("📦 Fixture sifatida saqlash", lambda: self.save_mock("final"))
        btn_layout.addWidget(self.res_fixture_btn)
        
        res_layout.addLayout(btn_layout)
        self.details.addTab(self.res_panel, "Response")

        splitter.addWidget(self.details)
        splitter.setSizes([1000, 1000])

        # Connect signals for changes
        self.req_method.textChanged.connect(self.check_req_changes)
        self.req_url.textChanged.connect(self.check_req_changes)
        self.req_headers.textChanged.connect(self.check_req_changes)
        self.req_body.textChanged.connect(self.check_req_changes)
        
        self.res_status.valueChanged.connect(self.check_res_changes)
        self.res_headers.textChanged.connect(self.check_res_changes)
        self.res_body.textChanged.connect(self.check_res_changes)

        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.refresh)
        self.timer.start()
        self.refresh()

    def refresh(self):
        try:
            query = self.search_input.text().strip()
            rows = self.store.list_captures(query=query)
        except Exception as exc:
            self.info.setText(f"Storage xatosi: {exc}")
            return

        self.info.clear()
        
        selected_id = self.selected_id
        selected_row = None

        self.table.blockSignals(True)
        self.table.setRowCount(len(rows))

        for row, (flow_id, method, url, status, mock_action, rpc_method) in enumerate(rows):
            first = self.table.item(row, 0)
            if first is None:
                first = text_item("")
                self.table.setItem(row, 0, first)
                self.table.setItem(row, 1, text_item(""))
                self.table.setItem(row, 2, text_item(""))
                self.table.setItem(row, 3, text_item(""))
                self.table.setItem(row, 4, text_item(""))
                
            first = self.table.item(row, 0)
            first.setData(Qt.ItemDataRole.UserRole, flow_id)
            first.setText(method)
            
            self.table.item(row, 1).setText(url)
            self.table.item(row, 2).setText(rpc_method or "—")
            self.table.item(row, 3).setText(str(status) if status is not None else "—")
            
            mock_text = ""
            if mock_action == "local": mock_text = "[LOCAL]"
            elif mock_action == "patch": mock_text = "[PATCH]"
            elif mock_action == "request_patch": mock_text = "[REQ]"
            elif mock_action == "replace": mock_text = "[REPLACE]"
            self.table.item(row, 4).setText(mock_text)

            if flow_id == selected_id:
                selected_row = row

        self.table.clearSelection()
        if selected_row is not None:
            self.table.selectRow(selected_row)
        self.table.blockSignals(False)

        if selected_row is None and selected_id is not None:
            self.selected_id = None
            self.clear_panels()

    def clear_panels(self):
        self.req_method.clear()
        self.req_url.clear()
        self.req_headers.clear()
        self.req_body.clear()
        self.res_status.setValue(0)
        self.res_headers.clear()
        self.res_body.clear()
        self.res_info.clear()
        self.req_save_btn.setVisible(False)
        self.res_save_btn.setVisible(False)
        self.current_document = None
        self.req_snapshot = None
        self.res_snapshot = None

    def show_selected(self):
        row = self.table.currentRow()
        if row < 0 or not self.table.selectedItems():
            return

        self.selected_id = self.table.item(row, 0).data(Qt.ItemDataRole.UserRole)

        try:
            document = self.store.capture(self.selected_id)
            if not document: return
            
            self.current_document = document
            
            # Request Panel
            req = document.get("request")
            if req:
                self.req_snapshot = req
                self.req_initial_method = document.get("method", "")
                self.req_initial_url = document.get("url", "")
                self.req_method.setText(self.req_initial_method)
                self.req_url.setText(self.req_initial_url)
                
                headers_list = req.get("headers", [])
                hdrs = "\n".join(f"{k}: {v}" for k, v in headers_list)
                self.req_initial_headers = hdrs
                self.req_headers.setPlainText(hdrs)
                
                body = self.decode_body(req)
                self.req_initial_body = body
                self.req_body.setPlainText(body)
                self.req_save_btn.setVisible(False)
            
            # Response Panel
            res = document.get("final")
            if res:
                self.res_snapshot = res
                self.res_initial_status = res.get("status", 0)
                self.res_status.setValue(self.res_initial_status)
                
                headers_list = res.get("headers", [])
                hdrs = "\n".join(f"{k}: {v}" for k, v in headers_list)
                self.res_initial_headers = hdrs
                self.res_headers.setPlainText(hdrs)
                
                body = self.decode_body(res)
                self.res_initial_body = body
                self.res_body.setPlainText(body)
                
                info = f"Hajmi: {res.get('body_size', 0)} bytes."
                if res.get("truncated"): info += " (Katta hajmli fayl, body to'liq ko'rsatilmagan)"
                if document.get("error"): info += f" | Error: {document['error']}"
                self.res_info.setText(info)
                self.res_save_btn.setVisible(False)
            else:
                self.res_snapshot = None
                self.res_status.setValue(0)
                self.res_headers.clear()
                self.res_body.clear()
                self.res_info.setText("Javob olinmagan yoki xatolik.")

        except Exception as exc:
            self.info.setText(f"Capture xatosi: {exc}")

    def decode_body(self, snapshot):
        if not snapshot: return ""
        raw = base64.b64decode(snapshot.get("body_b64", ""))
        try:
            body = raw.decode("utf-8")
            try:
                return json.dumps(json.loads(body), ensure_ascii=False, indent=2)
            except ValueError:
                return body
        except UnicodeDecodeError:
            return "<binary data>"

    def check_req_changes(self):
        if not self.req_snapshot: return
        changed = (
            self.req_method.text() != self.req_initial_method or
            self.req_url.text() != self.req_initial_url or
            self.req_headers.toPlainText() != self.req_initial_headers or
            self.req_body.toPlainText() != self.req_initial_body
        )
        self.req_save_btn.setVisible(changed)

    def check_res_changes(self):
        if not self.res_snapshot: return
        changed = (
            self.res_status.value() != self.res_initial_status or
            self.res_headers.toPlainText() != self.res_initial_headers or
            self.res_body.toPlainText() != self.res_initial_body
        )
        self.res_save_btn.setVisible(changed)

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
            if values != before.get(name): replacements.extend(values)
        removed = [values[0][0] for name, values in before.items() if name not in after]
        return replacements, removed

    def build_conditions(self, parsed, req_snapshot):
        conds = [{"source": "query", "key": k, "op": "equals", "value": v} 
                 for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
        
        # Parse request body to extract RPC methods
        if req_snapshot and req_snapshot.get("body_b64"):
            try:
                raw = base64.b64decode(req_snapshot["body_b64"]).decode("utf-8")
                body = json.loads(raw)
                if isinstance(body, dict):
                    for key in ["method", "action", "operationName"]:
                        if key in body and isinstance(body[key], str):
                            conds.append({
                                "source": "json",
                                "key": key,
                                "op": "equals",
                                "value": body[key]
                            })
            except Exception:
                pass
        return conds

    def generate_rule_name(self, method, path, conditions, prefix=""):
        rpc = ""
        for c in conditions:
            if c.get("source") == "json" and c.get("key") in ("method", "action", "operationName"):
                rpc = f" [{c['value']}]"
                break
        short_path = path or "/"
        if len(short_path) > 40:
            short_path = "..." + short_path[-37:]
        base = f"{method} {short_path}{rpc}"
        return f"{prefix} {base}".strip()

    def parse_headers_text(self, text):
        headers = []
        for line in text.split('\n'):
            line = line.strip()
            if not line:
                continue
            if ':' in line:
                k, v = line.split(':', 1)
                headers.append([k.strip(), v.strip()])
            else:
                headers.append([line, ""])
        return headers

    def save_req_mock(self):
        headers = self.parse_headers_text(self.req_headers.toPlainText())
            
        doc = self.current_document
        parsed = urlsplit(doc["url"])
        replacements, removed = self.header_changes(self.req_snapshot["headers"], headers)
        
        body_changed = self.req_body.toPlainText() != self.req_initial_body
        method_changed = self.req_method.text() != self.req_initial_method
        url_changed = self.req_url.text() != self.req_initial_url
        
        conditions = self.build_conditions(parsed, self.req_snapshot)
        rule = default_rule()
        rule.update({
            "name": self.generate_rule_name(doc["method"], parsed.path, conditions, "ReqPatch:"),
            "method": doc["method"],
            "host": parsed.hostname or "",
            "path": parsed.path or "/",
            "action": "request_patch",
            "status": 0,
            "headers": replacements,
            "remove_headers": removed,
            "body": self.req_body.toPlainText() if body_changed else "",
            "preserve_body": not body_changed,
            "rewrite_method": self.req_method.text() if method_changed else "",
            "rewrite_url": self.req_url.text() if url_changed else "",
            "conditions": conditions,
        })
        
        self.store.save_rules(self.store.load_rules() + [rule])
        self.rules_changed.emit()
        self.req_save_btn.setVisible(False)
        self.req_initial_method = self.req_method.text()
        self.req_initial_url = self.req_url.text()
        self.req_initial_headers = self.req_headers.toPlainText()
        self.req_initial_body = self.req_body.toPlainText()
        QMessageBox.information(self, "Muvaffaqiyatli", "So'rovni o'zgartirish (Request Patch) qoidasi saqlandi!")

    def save_res_mock(self):
        headers = self.parse_headers_text(self.res_headers.toPlainText())
            
        doc = self.current_document
        parsed = urlsplit(doc["url"])
        replacements, removed = self.header_changes(self.res_snapshot["headers"], headers)
        
        body_changed = self.res_body.toPlainText() != self.res_initial_body
        status_changed = self.res_status.value() != self.res_initial_status
        
        conditions = self.build_conditions(parsed, self.req_snapshot)
        rule = default_rule()
        rule.update({
            "name": self.generate_rule_name(doc["method"], parsed.path, conditions),
            "method": doc["method"],
            "host": parsed.hostname or "",
            "path": parsed.path or "/",
            "action": "patch",
            "status": self.res_status.value() if status_changed else 0,
            "headers": replacements,
            "remove_headers": removed,
            "body": self.res_body.toPlainText() if body_changed else "",
            "preserve_body": not body_changed,
            "conditions": conditions,
        })
        
        self.store.save_rules(self.store.load_rules() + [rule])
        self.rules_changed.emit()
        self.res_save_btn.setVisible(False)
        self.res_initial_status = self.res_status.value()
        self.res_initial_headers = self.res_headers.toPlainText()
        self.res_initial_body = self.res_body.toPlainText()
        QMessageBox.information(self, "Muvaffaqiyatli", "Javob mock qoidasi saqlandi!")

    def save_mock(self, source: str):
        if not self.selected_id: return
        try:
            document = self.store.capture(self.selected_id)
            snapshot = document.get(source)
            if not snapshot: raise ValueError("Javob (Response) ma'lumoti topilmadi")
            if snapshot.get("truncated"): raise ValueError("Tana (Body) qismi to'liq saqlanmagan (kesilgan)!")
            
            fixture_id = self.store.put_fixture(base64.b64decode(snapshot["body_b64"]))
            parsed = urlsplit(document["url"])
            conditions = self.build_conditions(parsed, self.req_snapshot)
            rule = default_rule()
            rule.update({
                "name": self.generate_rule_name(document["method"], parsed.path, conditions, "Local:"),
                "method": document["method"],
                "host": parsed.hostname or "",
                "path": parsed.path or "/",
                "status": snapshot["status"],
                "headers": snapshot["headers"],
                "fixture": fixture_id,
                "conditions": conditions,
            })
            self.mock_requested.emit(rule)
        except Exception as exc:
            QMessageBox.warning(self, "Xatolik", str(exc))

    def clear(self):
        answer = QMessageBox.question(self, "Trafiklarni tozalash", "Barcha yozib olingan trafiklar tarixi o'chirilsinmi?")
        if answer == QMessageBox.StandardButton.Yes:
            self.store.clear_captures()
            self.clear_panels()
            self.refresh()
