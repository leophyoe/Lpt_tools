"""Security Findings and Evidence view."""

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from storage.db import Database
from storage.models import Finding, FindingSeverity


class FindingsView(QWidget):
    """Displays triageable security findings and remediation guidance."""

    SEVERITY_COLORS = {
        FindingSeverity.CRITICAL: QColor("#ef4444"),
        FindingSeverity.HIGH: QColor("#f97316"),
        FindingSeverity.MEDIUM: QColor("#eab308"),
        FindingSeverity.LOW: QColor("#3b82f6"),
        FindingSeverity.INFORMATIONAL: QColor("#94a3b8"),
    }

    def __init__(self, db: Database, parent=None):
        super().__init__(parent)
        self.db = db
        self.findings_cache: list[Finding] = []
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        header = QLabel("Security Findings & Evidence Records")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #f8fafc;")
        layout.addWidget(header)

        # Splitter between findings table and details panel
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["ID", "Severity", "Finding Title", "Affected Asset", "Validation"])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        splitter.addWidget(self.table)

        # Details Panel
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        details_layout.setContentsMargins(0, 8, 0, 0)

        details_title = QLabel("Finding Details & Remediation Guidance")
        details_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #38bdf8;")
        details_layout.addWidget(details_title)

        self.details_edit = QTextEdit()
        self.details_edit.setReadOnly(True)
        details_layout.addWidget(self.details_edit)

        splitter.addWidget(details_widget)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        layout.addWidget(splitter)

    def load_findings(self, project_id: Optional[int]):
        if project_id is None:
            self.table.setRowCount(0)
            self.details_edit.clear()
            return

        self.findings_cache = self.db.list_findings(project_id)
        self.table.setRowCount(len(self.findings_cache))

        for row, f in enumerate(self.findings_cache):
            self.table.setItem(row, 0, QTableWidgetItem(str(f.id)))

            sev_item = QTableWidgetItem(f.severity.value.upper())
            color = self.SEVERITY_COLORS.get(f.severity, QColor("#94a3b8"))
            sev_item.setForeground(color)
            self.table.setItem(row, 1, sev_item)

            self.table.setItem(row, 2, QTableWidgetItem(f.title))
            self.table.setItem(row, 3, QTableWidgetItem(f"{f.affected_asset} ({f.affected_port_service})"))
            self.table.setItem(row, 4, QTableWidgetItem(f.validation_status.value))

        if self.findings_cache:
            self.table.selectRow(0)

    def _on_selection_changed(self):
        selected = self.table.selectedItems()
        if not selected:
            self.details_edit.clear()
            return
        row = selected[0].row()
        if row < len(self.findings_cache):
            f = self.findings_cache[row]
            text = (
                f"### {f.title}\n\n"
                f"**Severity:** {f.severity.value.upper()} | **Validation Status:** {f.validation_status.value}\n"
                f"**Target Asset:** {f.affected_asset} | **Service:** {f.affected_port_service}\n"
                f"**Source Tool:** {f.source_tool} | **Execution ID:** #{f.execution_id}\n\n"
                f"#### Description:\n{f.description}\n\n"
                f"#### Recommended Remediation:\n{f.remediation}\n"
            )
            self.details_edit.setMarkdown(text)
