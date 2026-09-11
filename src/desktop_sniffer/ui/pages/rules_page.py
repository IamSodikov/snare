import copy
import uuid

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)

from desktop_sniffer.ui.dialogs.rule_dialog import RuleDialog
from desktop_sniffer.ui.helpers.widgets import button, text_item


class ToggleSwitch(QWidget):
    toggled = Signal(bool)
    
    def __init__(self, checked=True, parent=None):
        super().__init__(parent)
        self._checked = checked
        self.setFixedSize(44, 24)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
    
    def isChecked(self):
        return self._checked
    
    def setChecked(self, val):
        self._checked = val
        self.update()
    
    def mousePressEvent(self, event):
        self._checked = not self._checked
        self.update()
        self.toggled.emit(self._checked)
    
    def paintEvent(self, event):
        from PySide6.QtGui import QPainter, QColor
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        r = h / 2
        if self._checked:
            p.setBrush(QColor("#22c55e"))
        else:
            p.setBrush(QColor("#cbd5e1"))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawRoundedRect(0, 0, w, h, r, r)
        p.setBrush(QColor("white"))
        cx = w - r - 2 if self._checked else r + 2
        p.drawEllipse(int(cx - r + 3), 3, h - 6, h - 6)
        p.end()


class RulesPage(QWidget):
    def __init__(self, store):
        super().__init__()
        self.store = store
        self.rules = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Yuqori boshqaruv paneli
        header = QHBoxLayout()
        header.setSpacing(8)

        title = QLabel("Mock Qoidalar")
        title.setStyleSheet("font-size: 16px; font-weight: 700; color: #0f172a;")
        header.addWidget(title)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Qoidalarni qidirish (URL, metod, nom yoki shartlar bo'yicha)...")
        self.search_input.textChanged.connect(self.render_table)
        header.addWidget(self.search_input)

        header.addStretch()

        self.btn_add = button("+ Yangi Qoida", self.add_rule)
        self.btn_add.setStyleSheet("""
            QPushButton {
                background-color: #0284c7;
                color: white;
                font-weight: bold;
                padding: 7px 16px;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover { background-color: #0369a1; }
            QPushButton:pressed { background-color: #075985; padding-top: 8px; }
        """)
        header.addWidget(self.btn_add)

        header.addWidget(button("Import", self.import_rules))
        header.addWidget(button("Export", self.export_rules))

        layout.addLayout(header)

        # Qoidalar jadvali
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels([
            "Endpoint", "Mock Turi", "Holat", "Amallar"
        ])

        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(56)

        header_view = self.table.horizontalHeader()
        header_view.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header_view.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)

        self.table.cellDoubleClicked.connect(self.on_double_click)
        layout.addWidget(self.table, 1)

        self.refresh()

    def refresh(self):
        self.rules = self.store.load_rules()
        self.render_table()

    def render_table(self):
        query = self.search_input.text().strip().lower()

        # Filtrlash
        displayed_rules = []
        for rule in self.rules:
            if not query:
                displayed_rules.append(rule)
                continue

            name = rule.get("name", "").lower()
            method = rule.get("method", "").lower()
            host = rule.get("host", "").lower()
            path = rule.get("path", "").lower()
            action = rule.get("action", "").lower()

            conds_text = ""
            for c in rule.get("conditions", []):
                conds_text += f" {c.get('key', '')} {c.get('value', '')}".lower()

            if (query in name or query in method or query in host or
                query in path or query in action or query in conds_text):
                displayed_rules.append(rule)

        self.table.setRowCount(len(displayed_rules))

        for row, rule in enumerate(displayed_rules):
            rid = rule["id"]
            enabled = rule.get("enabled", True)

            # --- 0. Endpoint va Shart (Widget) ---
            endpoint_widget = QWidget()
            endpoint_layout = QVBoxLayout(endpoint_widget)
            endpoint_layout.setContentsMargins(6, 4, 6, 4)
            endpoint_layout.setSpacing(2)

            path_display = rule.get("path", "") or "/"
            if rule.get("host"):
                path_display = f"{rule['host']}{path_display}"

            name_display = rule.get("name", "")
            if name_display and name_display != "Mock":
                title_lbl = QLabel(f"<b>{name_display}</b> <span style='color: #64748b;'>({path_display})</span>")
            else:
                title_lbl = QLabel(f"<b>{path_display}</b>")
            title_lbl.setTextFormat(Qt.TextFormat.RichText)
            endpoint_layout.addWidget(title_lbl)

            # Shartlar (agar mavjud bo'lsa)
            conds = rule.get("conditions", [])
            if conds:
                cond_tags = []
                for c in conds:
                    k = c.get("key", "")
                    v = c.get("value", "")
                    src = c.get("source", "")
                    if src == "json":
                        cond_tags.append(f"body.{k}={v}")
                    elif src == "query":
                        cond_tags.append(f"?{k}={v}")
                    else:
                        cond_tags.append(f"{k}={v}")
                cond_lbl = QLabel(f"<span style='color: #0369a1; font-size: 11px;'>{', '.join(cond_tags)}</span>")
                cond_lbl.setTextFormat(Qt.TextFormat.RichText)
                endpoint_layout.addWidget(cond_lbl)

            self.table.setCellWidget(row, 0, endpoint_widget)

            # --- 1. Mock Turi ---
            action = rule.get("action", "local")
            status = rule.get("status", 200)
            if action == "local":
                action_text = f"Local ({status})"
            elif action == "patch":
                action_text = f"Patch ({status if status else 'Original'})"
            elif action == "request_patch":
                action_text = "Request Patch"
            else:
                action_text = f"Replace ({status})"

            action_item = text_item(action_text)
            action_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            action_item.setData(Qt.ItemDataRole.UserRole, rid)
            self.table.setItem(row, 1, action_item)
            
            # --- 2. Holat (Toggle Switch) ---
            switch_widget = QWidget()
            switch_layout = QHBoxLayout(switch_widget)
            switch_layout.setContentsMargins(0, 0, 0, 0)
            switch_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            toggle_switch = ToggleSwitch(checked=enabled)
            toggle_switch.toggled.connect(lambda _, id_=rid: self.toggle_by_id(id_))
            switch_layout.addWidget(toggle_switch)
            self.table.setCellWidget(row, 2, switch_widget)

            # --- 3. Amallar (Action buttons) ---
            actions_widget = QWidget()
            actions_layout = QHBoxLayout(actions_widget)
            actions_layout.setContentsMargins(4, 2, 4, 2)
            actions_layout.setSpacing(4)

            btn_edit = button("Edit", lambda id_=rid: self.edit_by_id(id_))
            btn_edit.setToolTip("Tahrirlash")
            btn_edit.setStyleSheet("""
                QPushButton { background-color: #f1f5f9; color: #334155; border: 1px solid #cbd5e1; border-radius: 4px; padding: 4px 8px; }
                QPushButton:hover { background-color: #e2e8f0; }
            """)
            actions_layout.addWidget(btn_edit)

            btn_dup = button("Copy", lambda id_=rid: self.duplicate_by_id(id_))
            btn_dup.setToolTip("Nusxa olish")
            btn_dup.setStyleSheet("""
                QPushButton { background-color: #f1f5f9; color: #334155; border: 1px solid #cbd5e1; border-radius: 4px; padding: 4px 8px; }
                QPushButton:hover { background-color: #e2e8f0; }
            """)
            actions_layout.addWidget(btn_dup)

            btn_del = button("Del", lambda id_=rid: self.delete_by_id(id_))
            btn_del.setToolTip("O'chirish")
            btn_del.setStyleSheet("""
                QPushButton { background-color: #fee2e2; color: #dc2626; border: 1px solid #fca5a5; border-radius: 4px; padding: 4px 8px; }
                QPushButton:hover { background-color: #fecaca; }
            """)
            actions_layout.addWidget(btn_del)

            self.table.setCellWidget(row, 3, actions_widget)

    def find_index(self, rule_id: str) -> int:
        for idx, rule in enumerate(self.rules):
            if rule["id"] == rule_id:
                return idx
        return -1

    def commit(self, rules) -> bool:
        try:
            self.store.save_rules(rules)
            self.refresh()
            return True
        except Exception as exc:
            QMessageBox.warning(self, "Saqlash xatosi", str(exc))
            return False

    def toggle_by_id(self, rule_id: str):
        idx = self.find_index(rule_id)
        if idx < 0:
            return
        rules = copy.deepcopy(self.rules)
        rules[idx]["enabled"] = not rules[idx].get("enabled", True)
        self.commit(rules)

    def add_rule(self, seed=None):
        dialog = RuleDialog(
            self.store,
            seed if isinstance(seed, dict) else None,
            self,
        )
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.commit(self.rules + [dialog.result_rule])

    def edit_by_id(self, rule_id: str):
        idx = self.find_index(rule_id)
        if idx < 0:
            return
        dialog = RuleDialog(self.store, self.rules[idx], self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            rules = copy.deepcopy(self.rules)
            rules[idx] = dialog.result_rule
            self.commit(rules)

    def duplicate_by_id(self, rule_id: str):
        idx = self.find_index(rule_id)
        if idx < 0:
            return
        rule = copy.deepcopy(self.rules[idx])
        rule["id"] = str(uuid.uuid4())
        rule["name"] = rule.get("name", "Mock") + " (nusxa)"
        self.commit(self.rules + [rule])

    def delete_by_id(self, rule_id: str):
        idx = self.find_index(rule_id)
        if idx < 0:
            return
        name = self.rules[idx].get("name") or self.rules[idx].get("path")
        answer = QMessageBox.question(
            self,
            "O‘chirish",
            f"Qoidani o‘chirmoqchimisiz?\n'{name}'",
        )
        if answer == QMessageBox.StandardButton.Yes:
            rules = list(self.rules)
            rules.pop(idx)
            self.commit(rules)

    def on_double_click(self, row, _):
        item = self.table.item(row, 1)
        if item:
            rid = item.data(Qt.ItemDataRole.UserRole)
            if rid:
                self.edit_by_id(rid)

    def export_rules(self):
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Qoidalarni eksport qilish",
            "mocks.json",
            "JSON fayllari (*.json)",
        )
        if not filename:
            return
        try:
            self.store.export_bundle(filename)
            QMessageBox.information(self, "Muvaffaqiyatli", "Qoidalar muvaffaqiyatli eksport qilindi!")
        except Exception as exc:
            QMessageBox.warning(self, "Eksport xatosi", str(exc))

    def import_rules(self):
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Qoidalarni import qilish",
            "",
            "JSON fayllari (*.json)",
        )
        if not filename:
            return
        answer = QMessageBox.question(
            self,
            "Import qilish",
            "Joriy ish maydonidagi qoidalar tanlangan fayldagi qoidalar bilan almashtirilsinmi?",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            self.store.import_bundle(filename)
            self.refresh()
            QMessageBox.information(self, "Muvaffaqiyatli", "Qoidalar muvaffaqiyatli yuklandi!")
        except Exception as exc:
            QMessageBox.warning(self, "Import xatosi", str(exc))