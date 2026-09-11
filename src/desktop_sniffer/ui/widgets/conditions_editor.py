from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)

from desktop_sniffer.domain.rules.validation import OPERATORS, SOURCES
from desktop_sniffer.ui.helpers.widgets import button, text_item


class ConditionsEditor(QWidget):
    def __init__(self, conditions):
        super().__init__()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels([
            "Source",
            "Key / JSON path",
            "Operator",
            "Value",
        ])

        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.table.setMinimumHeight(150)

        layout.addWidget(self.table)

        controls = QHBoxLayout()
        controls.addWidget(button("+ Shart qo'shish", self.add_empty))
        controls.addWidget(button("− O'chirish", self.remove_selected))
        layout.addLayout(controls)

        for condition in conditions:
            self.add_condition(condition)

    def add_empty(self):
        self.add_condition({
            "source": "query",
            "key": "",
            "op": "equals",
            "value": "",
        })

    def add_condition(self, condition):
        row = self.table.rowCount()
        self.table.insertRow(row)

        source = QComboBox()
        source.addItems(SOURCES)
        source.setCurrentText(condition["source"])

        operator = QComboBox()
        operator.addItems(OPERATORS)
        operator.setCurrentText(condition["op"])

        self.table.setCellWidget(row, 0, source)
        self.table.setItem(
            row, 1, text_item(condition["key"])
        )
        self.table.setCellWidget(row, 2, operator)
        self.table.setItem(
            row, 3, text_item(condition.get("value", ""))
        )

    def remove_selected(self):
        row = self.table.currentRow()

        if row >= 0:
            self.table.removeRow(row)

    def value(self) -> list:
        conditions = []

        for row in range(self.table.rowCount()):
            key = self.table.item(row, 1)
            value = self.table.item(row, 3)

            conditions.append({
                "source": self.table.cellWidget(row, 0).currentText(),
                "key": key.text() if key else "",
                "op": self.table.cellWidget(row, 2).currentText(),
                "value": value.text() if value else "",
            })

        return conditions