"""Security Findings and Evidence view with Report Generation."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from reports.builder import ReportBuilder
from storage.db import Database
from storage.models import Finding, FindingSeverity


class FindingsView(QWidget):
    """Displays triageable security findings, remediation guidance, and report export."""

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
        self.report_builder = ReportBuilder(db)
        self.active_project_id: Optional[int] = None
        self.findings_cache: list[Finding] = []
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Header and Report Export Toolbar
        header_row = QHBoxLayout()
        header = QLabel("Security Findings & Evidence Records")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #f8fafc;")
        header_row.addWidget(header)
        header_row.addStretch()

        # Action Buttons
        self.btn_export_html = QPushButton("📄 Export HTML")
        self.btn_export_html.setProperty("class", "action-primary")
        self.btn_export_html.clicked.connect(lambda: self._export_report("html"))
        header_row.addWidget(self.btn_export_html)

        self.btn_export_md = QPushButton("📝 Export Markdown")
        self.btn_export_md.setProperty("class", "action-secondary")
        self.btn_export_md.clicked.connect(lambda: self._export_report("markdown"))
        header_row.addWidget(self.btn_export_md)

        self.btn_export_json = QPushButton("⚙️ Export JSON")
        self.btn_export_json.setProperty("class", "action-secondary")
        self.btn_export_json.clicked.connect(lambda: self._export_report("json"))
        header_row.addWidget(self.btn_export_json)

        layout.addLayout(header_row)

        self.export_status = QLabel("")
        self.export_status.setStyleSheet("color: #4ade80; font-size: 12px; font-weight: 500;")
        layout.addWidget(self.export_status)

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
        self.active_project_id = project_id
        self.export_status.setText("")

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

    def _export_report(self, fmt: str):
        if self.active_project_id is None:
            QMessageBox.warning(
                self,
                "No Project Selected",
                "Please select an active project in 'Projects & Scope' before exporting assessment reports.",
            )
            return

        project = self.db.get_project(self.active_project_id)
        if not project:
            QMessageBox.critical(self, "Error", f"Project #{self.active_project_id} not found.")
            return

        out_dir = Path("reports/output")
        out_dir.mkdir(parents=True, exist_ok=True)
        clean_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in project.name.lower())
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        try:
            if fmt == "html":
                file_path = out_dir / f"{clean_name}_report_{stamp}.html"
                self.report_builder.generate_html(self.active_project_id, output_path=file_path)
            elif fmt == "markdown":
                file_path = out_dir / f"{clean_name}_report_{stamp}.md"
                self.report_builder.generate_markdown(self.active_project_id, output_path=file_path)
            elif fmt == "json":
                file_path = out_dir / f"{clean_name}_report_{stamp}.json"
                self.report_builder.generate_json(self.active_project_id, output_path=file_path)
            else:
                return

            self.export_status.setText(f"✓ Generated {fmt.upper()} report: {file_path.name}")
            QMessageBox.information(
                self,
                "Report Generated Successfully",
                f"Assessment report exported in {fmt.upper()} format to:\n\n{file_path.resolve()}",
            )
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"Failed to generate report: {e}")
