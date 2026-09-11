import copy
import json
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from desktop_sniffer.core.constants import MAX_FIXTURE_SIZE
from desktop_sniffer.domain.rules.defaults import default_rule
from desktop_sniffer.domain.rules.validation import validate_rules
from desktop_sniffer.ui.helpers.widgets import button
from desktop_sniffer.ui.widgets.conditions_editor import ConditionsEditor


class RuleDialog(QDialog):
    def __init__(self, store, rule=None, parent=None):
        super().__init__(parent)

        self.store = store
        self.rule = default_rule()

        if rule:
            self.rule.update(copy.deepcopy(rule))

        self.result_rule = None
        self.fixture_id = self.rule.get("fixture")

        self.setWindowTitle("Mock qoidasini sozlash")
        self.resize(950, 750)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(12)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        main_layout.addWidget(scroll, 1)

        content = QWidget()
        scroll.setWidget(content)

        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 0, 8, 0)
        layout.setSpacing(14)

        # ----------------------------------------------------
        # 1. Asosiy Ma'lumotlar
        # ----------------------------------------------------
        top_group = QGroupBox("Asosiy ma'lumotlar")
        top_form = QFormLayout(top_group)

        self.name = QLineEdit(self.rule.get("name", ""))
        self.name.setPlaceholderText("Masalan: To'lovlar ro'yxati (ixtiyoriy)")

        self.enabled = QCheckBox("Ushbu qoida faol ishlasin")
        self.enabled.setChecked(self.rule.get("enabled", True))

        top_form.addRow("Qoida nomi:", self.name)
        top_form.addRow("Holati:", self.enabled)
        layout.addWidget(top_group)

        # ----------------------------------------------------
        # 2. Qaysi So'rov Ushlanadi? (Target)
        # ----------------------------------------------------
        target_group = QGroupBox("1. Qaysi so'rov ushlab qolinadi? (Target Endpoint)")
        target_form = QFormLayout(target_group)

        target_row = QHBoxLayout()
        self.method = QComboBox()
        self.method.setEditable(True)
        self.method.addItems(["*", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
        self.method.setCurrentText(self.rule.get("method", "*"))
        self.method.setFixedWidth(110)
        target_row.addWidget(self.method)

        self.path = QLineEdit(self.rule.get("path", ""))
        self.path.setPlaceholderText("/api/v1/... (URL yo'li)")
        target_row.addWidget(self.path, 1)
        target_form.addRow("Method va URL:", target_row)

        self.host = QLineEdit(self.rule.get("host", ""))
        self.host.setPlaceholderText("Masalan: api.sayt.uz (bo'sh qoldirilsa: barcha hostlar)")
        target_form.addRow("Host (Domen):", self.host)

        # Conditions tushuntirish bilan
        cond_header = QLabel(
            "<b>Maxsus shartlar (AND mantiqi):</b><br>"
            "<span style='color: #64748b; font-size: 11px;'>"
            "Agar endpoint bir xil bo'lsa (masalan /rpc), Request Body'dagi parametrlar "
            "(masalan 'method' = 'payment.list') yoki URL Query parametrlarini tekshirish uchun:</span>"
        )
        cond_header.setTextFormat(Qt.TextFormat.RichText)
        target_form.addRow(cond_header)

        self.conditions = ConditionsEditor(self.rule.get("conditions", []))
        target_form.addRow(self.conditions)

        layout.addWidget(target_group)

        # ----------------------------------------------------
        # 3. Qanday Javob Qaytariladi? (Response)
        # ----------------------------------------------------
        response_group = QGroupBox("2. Qanday javob qaytarilsin? (Mock Response)")
        response_form = QFormLayout(response_group)

        self.action = QComboBox()
        self.action.addItem("🎭 Mahalliy javob (Local — Serverga so'rov bormaydi)", "local")
        self.action.addItem("✏️ Server javobini o'zgartirish (Patch — Faqat belgilangan qismlar)", "patch")
        self.action.addItem("📤 Serverga ketayotgan so'rovni o'zgartirish (Request Patch)", "request_patch")
        self.action.addItem("🔄 Server javobini to'liq almashtirish (Replace)", "replace")
        self.action.setCurrentIndex(self.action.findData(self.rule.get("action", "local")))
        self.action.currentIndexChanged.connect(self.update_action_controls)
        response_form.addRow("Mock Amali:", self.action)

        status_row = QHBoxLayout()
        self.status = QSpinBox()
        self.status.setRange(0, 599)
        self.status.setSpecialValueText("0 (Asl status)")
        self.status.setValue(self.rule.get("status", 200))
        self.status.setFixedWidth(120)
        status_row.addWidget(self.status)

        status_row.addSpacing(20)
        status_row.addWidget(QLabel("Delay (Kechikish):"))
        self.delay = QSpinBox()
        self.delay.setRange(0, 120_000)
        self.delay.setSuffix(" ms")
        self.delay.setValue(self.rule.get("delay_ms", 0))
        self.delay.setFixedWidth(120)
        status_row.addWidget(self.delay)
        status_row.addStretch()

        response_form.addRow("Status va Delay:", status_row)

        self.body_source = QComboBox()
        self.body_source.addItems([
            "Matn / JSON formatida",
            "Fixture fayli (Binary)",
            "Asl body saqlansin (Preserve body)",
        ])
        if self.rule.get("preserve_body"):
            self.body_source.setCurrentIndex(2)
        elif self.fixture_id:
            self.body_source.setCurrentIndex(1)
        self.body_source.currentIndexChanged.connect(self.update_body_controls)
        response_form.addRow("Body manbasi:", self.body_source)

        self.body = QPlainTextEdit(self.rule.get("body", ""))
        self.body.setPlaceholderText("{\n  \"status\": \"success\",\n  \"data\": []\n}")
        self.body.setMinimumHeight(180)
        response_form.addRow("Javob body'si:", self.body)

        # Fixture qatori
        self.fixture_row = QWidget()
        f_layout = QHBoxLayout(self.fixture_row)
        f_layout.setContentsMargins(0, 0, 0, 0)
        self.fixture_label = QLabel(self.fixture_id or "Fayl tanlanmagan")
        f_layout.addWidget(self.fixture_label, 1)
        f_layout.addWidget(button("Fayl tanlash...", self.choose_fixture))
        response_form.addRow("Biriktirilgan Fixture:", self.fixture_row)

        layout.addWidget(response_group)

        # ----------------------------------------------------
        # 4. Kengaytirilgan Sozlamalar (Accordion / Toggle)
        # ----------------------------------------------------
        self.advanced_toggle = QCheckBox("⚙️ Kengaytirilgan sozlamalar (Headers, Scenarios, Max hits)")
        self.advanced_toggle.setStyleSheet("font-weight: bold; color: #475569; margin-top: 6px;")
        layout.addWidget(self.advanced_toggle)

        self.advanced_group = QGroupBox("Kengaytirilgan boshqaruv")
        adv_form = QFormLayout(self.advanced_group)

        self.match = QComboBox()
        self.match.addItems(["exact", "prefix", "regex"])
        self.match.setCurrentText(self.rule.get("match", "exact"))
        adv_form.addRow("URL Match turi:", self.match)

        self.headers = QPlainTextEdit(json.dumps(self.rule.get("headers", []), ensure_ascii=False, indent=2))
        self.headers.setMaximumHeight(90)
        adv_form.addRow("Qo'shiladigan Headers (JSON):", self.headers)

        self.remove_headers = QLineEdit(", ".join(self.rule.get("remove_headers", [])))
        self.remove_headers.setPlaceholderText("Masalan: Content-Security-Policy, ETag (vergul bilan)")
        adv_form.addRow("O'chiriladigan Headers:", self.remove_headers)

        self.scenario = QLineEdit(self.rule.get("scenario", ""))
        self.scenario.setPlaceholderText("Masalan: payment_retry")
        adv_form.addRow("Scenario nomi:", self.scenario)

        scen_row = QHBoxLayout()
        self.state = QLineEdit(self.rule.get("state", ""))
        self.state.setPlaceholderText("Started")
        scen_row.addWidget(QLabel("Talab qilinadigan holat:"))
        scen_row.addWidget(self.state)

        self.next_state = QLineEdit(self.rule.get("next_state", ""))
        scen_row.addWidget(QLabel("Keyingi holat:"))
        scen_row.addWidget(self.next_state)
        adv_form.addRow("Scenario holatlari:", scen_row)

        self.max_hits = QSpinBox()
        self.max_hits.setRange(0, 1_000_000)
        self.max_hits.setSpecialValueText("Cheklanmagan")
        self.max_hits.setValue(self.rule.get("max_hits", 0))
        adv_form.addRow("Max hits (Maksimal ishlash soni):", self.max_hits)

        layout.addWidget(self.advanced_group)
        self.advanced_group.setVisible(False)
        self.advanced_toggle.toggled.connect(self.advanced_group.setVisible)

        # Agar qoidada ilg'or parametrlar allaqachon ishlatilgan bo'lsa, avtomatik ochiladi
        if (self.rule.get("scenario") or self.rule.get("max_hits") or
            self.rule.get("headers") or self.rule.get("match") != "exact"):
            self.advanced_toggle.setChecked(True)

        # Dialog Tugmalari
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Save).setText("Saqlash")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Bekor qilish")
        buttons.accepted.connect(self.save)
        buttons.rejected.connect(self.reject)
        main_layout.addWidget(buttons)

        self.update_body_controls()
        self.update_action_controls()

    def update_body_controls(self, *_):
        source = self.body_source.currentIndex()
        self.body.setEnabled(source == 0)
        self.fixture_row.setVisible(source == 1)

    def update_action_controls(self, *_):
        is_req_patch = self.action.currentData() == "request_patch"
        self.status.setEnabled(not is_req_patch)
        if is_req_patch:
            self.status.setValue(0)

    def choose_fixture(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Biriktiriladigan faylni tanlang")
        if not filename:
            return
        try:
            path = Path(filename)
            if path.stat().st_size > MAX_FIXTURE_SIZE:
                raise ValueError("Fayl hajmi 32 MiB dan oshmasligi kerak")

            self.fixture_id = self.store.put_fixture(path.read_bytes())
            self.fixture_label.setText(f"{path.name} ({self.fixture_id[:8]}...)")
            self.body_source.setCurrentIndex(1)
        except Exception as exc:
            QMessageBox.warning(self, "Fayl xatosi", str(exc))

    def save(self):
        try:
            source = self.body_source.currentIndex()
            action = self.action.currentData()

            if source == 1 and not self.fixture_id:
                raise ValueError("Iltimos, biriktiriladigan faylni tanlang")

            if source == 2 and action != "patch":
                raise ValueError("Asl tanani saqlash faqat 'O'zgartirish (Patch)' amali uchun amal qiladi")

            headers_str = self.headers.toPlainText().strip() or "[]"
            try:
                headers = json.loads(headers_str)
            except Exception:
                raise ValueError("Sarlavhalar (Headers) JSON formati noto'g'ri")

            rule = {
                **self.rule,
                "enabled": self.enabled.isChecked(),
                "name": self.name.text().strip() or "Mock",
                "method": self.method.currentText().strip().upper() or "*",
                "host": self.host.text().strip(),
                "path": self.path.text().strip(),
                "match": self.match.currentText(),
                "conditions": self.conditions.value(),
                "action": action,
                "status": self.status.value(),
                "delay_ms": self.delay.value(),
                "headers": headers,
                "remove_headers": [
                    v.strip() for v in self.remove_headers.text().split(",") if v.strip()
                ],
                "body": self.body.toPlainText(),
                "fixture": self.fixture_id if source == 1 else None,
                "preserve_body": source == 2,
                "scenario": self.scenario.text().strip(),
                "state": self.state.text().strip() or "Started",
                "next_state": self.next_state.text().strip(),
                "max_hits": self.max_hits.value(),
            }

            validate_rules([rule])
            self.result_rule = rule
            self.accept()

        except Exception as exc:
            QMessageBox.warning(self, "Qoida xatosi", str(exc))
