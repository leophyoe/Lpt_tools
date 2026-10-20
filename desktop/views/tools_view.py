"""Tool Integration Dashboard and Execution Verification View.

Displays a comprehensive inventory of planned open-source security tools,
live executable status, version detection, integration maturity matrix,
and provides safe non-intrusive diagnostic verification and installation guidance.
"""

from __future__ import annotations

import html
from typing import List, Optional

from PySide6.QtCore import Qt, QThread, Signal, Slot
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.registry import ToolMetadata, ToolRegistry
from storage.db import Database


class ToolTestWorker(QThread):
    """Background worker to run non-intrusive tool diagnostic test without freezing GUI."""

    test_completed = Signal(str, bool, str, int)  # tool_name, success, output, exit_code

    def __init__(self, registry: ToolRegistry, tool_name: str):
        super().__init__()
        self.registry = registry
        self.tool_name = tool_name

    def run(self):
        success, output, exit_code = self.registry.test_tool(self.tool_name, timeout=8.0)
        self.test_completed.emit(self.tool_name, success, output, exit_code)


class ToolsDashboardView(QWidget):
    """Native PySide6 security tools integration inventory and diagnostic dashboard."""

    open_scanner_requested = Signal(str)  # Emits tool name to navigate in MainWindow

    STATUS_COLORS = {
        "Installed": QColor("#22c55e"),
        "Missing": QColor("#ef4444"),
        "Error": QColor("#f59e0b"),
    }

    def __init__(self, db: Database, registry: Optional[ToolRegistry] = None, parent=None):
        super().__init__(parent)
        self.db = db
        self.registry = registry or ToolRegistry()
        self.selected_tool: Optional[ToolMetadata] = None
        self._test_worker: Optional[ToolTestWorker] = None

        self._init_ui()
        self.refresh_tools()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # 1. Header Row
        header_row = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("Security Tool Integration Dashboard")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #f8fafc;")
        subtitle = QLabel("Real-time environment discovery, execution readiness, and installation diagnostics.")
        subtitle.setStyleSheet("font-size: 11px; color: #94a3b8;")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header_row.addLayout(title_box)
        header_row.addStretch()

        self.btn_refresh = QPushButton("🔄 Rescan All Tools")
        self.btn_refresh.setProperty("class", "action-primary")
        self.btn_refresh.clicked.connect(self.refresh_tools)
        header_row.addWidget(self.btn_refresh)
        layout.addLayout(header_row)

        # 2. Metrics Cards Row
        metrics_row = QHBoxLayout()
        metrics_row.setSpacing(10)

        self.card_total = self._create_metric_card("Total Planned", "0", "#38bdf8")
        self.card_installed = self._create_metric_card("Ready & Functional", "0", "#4ade80")
        self.card_missing = self._create_metric_card("Missing / Unbuilt", "0", "#f87171")
        self.card_integrated = self._create_metric_card("GUI Integrated", "0", "#a855f7")

        metrics_row.addWidget(self.card_total)
        metrics_row.addWidget(self.card_installed)
        metrics_row.addWidget(self.card_missing)
        metrics_row.addWidget(self.card_integrated)
        layout.addLayout(metrics_row)

        # 3. Filter and Search Toolbar
        filter_row = QHBoxLayout()
        filter_row.setSpacing(10)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Search tools by name, command, or category...")
        self.search_input.textChanged.connect(self._apply_filters)
        filter_row.addWidget(self.search_input, 2)

        self.cat_filter = QComboBox()
        self.cat_filter.addItems([
            "All Categories",
            "Network",
            "Web",
            "System",
            "Code Security",
            "Vulnerability",
            "Cloud",
            "Mobile",
        ])
        self.cat_filter.currentTextChanged.connect(self._apply_filters)
        filter_row.addWidget(self.cat_filter, 1)

        self.status_filter = QComboBox()
        self.status_filter.addItems(["All Statuses", "Installed", "Missing", "Error"])
        self.status_filter.currentTextChanged.connect(self._apply_filters)
        filter_row.addWidget(self.status_filter, 1)

        layout.addLayout(filter_row)

        # 4. Main Splitter (Left: Table, Right: Details & Safe Test)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: Tools Table
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "Tool Name",
            "Category",
            "Status",
            "Detected Version",
            "CLI",
            "Adapter",
            "GUI",
            "Parser",
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.itemSelectionChanged.connect(self._on_tool_selected)
        splitter.addWidget(self.table)

        # Right: Detail & Safe Test Panel
        detail_scroll = QScrollArea()
        detail_scroll.setWidgetResizable(True)
        detail_widget = QWidget()
        self.detail_layout = QVBoxLayout(detail_widget)
        self.detail_layout.setContentsMargins(12, 12, 12, 12)
        self.detail_layout.setSpacing(10)

        # Selected Tool Header
        self.lbl_tool_title = QLabel("Select a Tool")
        self.lbl_tool_title.setStyleSheet("font-size: 15px; font-weight: bold; color: #38bdf8;")
        self.lbl_tool_desc = QLabel("Click any tool from the table to view integration status, verify safe diagnostics, or view install commands.")
        self.lbl_tool_desc.setWordWrap(True)
        self.lbl_tool_desc.setStyleSheet("color: #94a3b8; font-size: 12px;")

        self.lbl_tool_path = QLabel("Executable: —")
        self.lbl_tool_path.setStyleSheet("color: #cbd5e1; font-family: monospace; font-size: 11px;")
        self.lbl_tool_path.setWordWrap(True)

        self.lbl_tool_caps = QLabel("Integration Capabilities: —")
        self.lbl_tool_caps.setStyleSheet("color: #cbd5e1; font-size: 12px;")

        self.detail_layout.addWidget(self.lbl_tool_title)
        self.detail_layout.addWidget(self.lbl_tool_desc)
        self.detail_layout.addWidget(self.lbl_tool_path)
        self.detail_layout.addWidget(self.lbl_tool_caps)

        # Action Buttons Row
        action_row = QHBoxLayout()
        self.btn_test = QPushButton("🧪 Run Safe Diagnostic")
        self.btn_test.setProperty("class", "action-primary")
        self.btn_test.setEnabled(False)
        self.btn_test.clicked.connect(self._run_tool_test)
        action_row.addWidget(self.btn_test)

        self.btn_open_gui = QPushButton("🚀 Open in Scanner")
        self.btn_open_gui.setProperty("class", "action-secondary")
        self.btn_open_gui.setEnabled(False)
        self.btn_open_gui.clicked.connect(self._on_open_gui_clicked)
        action_row.addWidget(self.btn_open_gui)
        self.detail_layout.addLayout(action_row)

        # Diagnostic Output Area
        lbl_diag = QLabel("Diagnostic Execution Output:")
        lbl_diag.setStyleSheet("font-weight: 600; font-size: 11px; color: #94a3b8;")
        self.detail_layout.addWidget(lbl_diag)

        self.txt_output = QTextEdit()
        self.txt_output.setReadOnly(True)
        self.txt_output.setFont(QFont("Monospace", 9))
        self.txt_output.setPlaceholderText("Click 'Run Safe Diagnostic' to execute a non-intrusive version or help check...")
        self.txt_output.setStyleSheet("background-color: #0b0d13; color: #38bdf8; border: 1px solid #1e2433; min-height: 120px;")
        self.detail_layout.addWidget(self.txt_output)

        # Installation & Guidance Box
        lbl_install = QLabel("Installation & Configuration Guide:")
        lbl_install.setStyleSheet("font-weight: 600; font-size: 11px; color: #94a3b8;")
        self.detail_layout.addWidget(lbl_install)

        self.txt_install = QTextEdit()
        self.txt_install.setReadOnly(True)
        self.txt_install.setFont(QFont("Monospace", 9))
        self.txt_install.setStyleSheet("background-color: #1a1e29; color: #f8fafc; border: 1px solid #334155; max-height: 90px;")
        self.detail_layout.addWidget(self.txt_install)

        self.btn_copy_cmd = QPushButton("📋 Copy Install Command")
        self.btn_copy_cmd.setFixedHeight(26)
        self.btn_copy_cmd.clicked.connect(self._copy_install_command)
        self.detail_layout.addWidget(self.btn_copy_cmd)

        self.detail_layout.addStretch()
        detail_scroll.setWidget(detail_widget)
        splitter.addWidget(detail_scroll)

        # 60% Table, 40% Details
        splitter.setStretchFactor(0, 6)
        splitter.setStretchFactor(1, 4)
        layout.addWidget(splitter)

    def _create_metric_card(self, title: str, value: str, color: str) -> QFrame:
        card = QFrame()
        card.setStyleSheet(
            f"background-color: #181d29; border: 1px solid #232936; border-radius: 6px; padding: 8px 12px;"
        )
        c_layout = QVBoxLayout(card)
        c_layout.setContentsMargins(0, 0, 0, 0)
        c_layout.setSpacing(2)

        lbl_title = QLabel(title)
        lbl_title.setStyleSheet("color: #94a3b8; font-size: 11px; font-weight: 500;")
        lbl_val = QLabel(value)
        lbl_val.setObjectName(f"val_{title.replace(' ', '_').lower()}")
        lbl_val.setStyleSheet(f"color: {color}; font-size: 18px; font-weight: bold;")

        c_layout.addWidget(lbl_title)
        c_layout.addWidget(lbl_val)
        return card

    def _update_metric_card(self, card: QFrame, value: str):
        label = card.findChild(QLabel)
        for child in card.findChildren(QLabel):
            if child.text().isdigit() or "+" in child.text():
                child.setText(value)
                break

    @Slot()
    def refresh_tools(self):
        """Refreshes tool status across system PATH and repository sources."""
        self.registry.refresh()
        self._apply_filters()
        self._update_metrics()

    def _update_metrics(self):
        all_tools = self.registry.list_tools()
        total = len(all_tools)
        installed = sum(1 for t in all_tools if t.is_installed)
        missing = total - installed
        integrated = sum(1 for t in all_tools if t.has_gui)

        for child in self.card_total.findChildren(QLabel):
            if child.text().isdigit():
                child.setText(str(total))
        for child in self.card_installed.findChildren(QLabel):
            if child.text().isdigit():
                child.setText(str(installed))
        for child in self.card_missing.findChildren(QLabel):
            if child.text().isdigit():
                child.setText(str(missing))
        for child in self.card_integrated.findChildren(QLabel):
            if child.text().isdigit():
                child.setText(str(integrated))

    def _apply_filters(self):
        search = self.search_input.text().strip().lower()
        cat_sel = self.cat_filter.currentText().lower()
        status_sel = self.status_filter.currentText().lower()

        tools = self.registry.list_tools()
        filtered: List[ToolMetadata] = []

        for t in tools:
            # Category match
            if cat_sel != "all categories":
                category_key = cat_sel.replace(" ", "_")
                if category_key not in t.category.lower():
                    continue

            # Status match
            t_status = "installed" if t.is_installed else ("error" if t.error_message and "unbuilt" in t.error_message else "missing")
            if status_sel != "all statuses" and t_status != status_sel:
                continue

            # Search text match
            if search:
                haystack = f"{t.name} {t.display_name} {t.category} {t.binary_name} {t.description}".lower()
                if search not in haystack:
                    continue

            filtered.append(t)

        self._populate_table(filtered)

    def _populate_table(self, tools: List[ToolMetadata]):
        self.table.setRowCount(len(tools))
        for row, tool in enumerate(tools):
            # Tool Name
            item_name = QTableWidgetItem(tool.display_name)
            item_name.setData(Qt.ItemDataRole.UserRole, tool.name)
            self.table.setItem(row, 0, item_name)

            # Category
            item_cat = QTableWidgetItem(tool.category.replace("_", " ").title())
            item_cat.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row, 1, item_cat)

            # Status
            if tool.is_installed:
                status_text = "Installed"
                color = self.STATUS_COLORS["Installed"]
            elif tool.error_message and "unbuilt" in tool.error_message:
                status_text = "Source Unbuilt"
                color = self.STATUS_COLORS["Error"]
            else:
                status_text = "Missing"
                color = self.STATUS_COLORS["Missing"]

            item_status = QTableWidgetItem(status_text)
            item_status.setForeground(color)
            item_status.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            item_status.setFont(QFont("Sans", 10, QFont.Weight.Bold))
            self.table.setItem(row, 2, item_status)

            # Version
            ver_text = tool.version or (tool.error_message or "Not Detected")
            item_ver = QTableWidgetItem(ver_text)
            self.table.setItem(row, 3, item_ver)

            # Capabilities: CLI, Adapter, GUI, Parser
            for col_idx, cap_val in enumerate([tool.has_cli, tool.has_adapter, tool.has_gui, tool.has_parser], start=4):
                item_cap = QTableWidgetItem("✅" if cap_val else "❌")
                item_cap.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.table.setItem(row, col_idx, item_cap)

        if len(tools) > 0 and self.table.currentRow() < 0:
            self.table.selectRow(0)

    @Slot()
    def _on_tool_selected(self):
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            return

        row = selected_rows[0].row()
        item = self.table.item(row, 0)
        if not item:
            return

        tool_name = item.data(Qt.ItemDataRole.UserRole)
        tool = self.registry.get_tool(tool_name)
        if not tool:
            return

        self.selected_tool = tool
        self.lbl_tool_title.setText(f"{tool.display_name} ({tool.name})")
        self.lbl_tool_desc.setText(tool.description or "No description provided.")

        status_str = "Installed & Verified" if tool.is_installed else "Missing / Unavailable"
        color_hex = "#4ade80" if tool.is_installed else "#f87171"
        self.lbl_tool_path.setText(
            f"Path: {tool.binary_path or 'Not in PATH'}\n"
            f"Category: {tool.category.title()} | Status: {status_str}"
        )
        self.lbl_tool_path.setStyleSheet(f"color: {color_hex}; font-family: monospace; font-size: 11px;")

        caps = [
            f"CLI: {'✅ Yes' if tool.has_cli else '❌ No'}",
            f"Adapter: {'✅ Yes' if tool.has_adapter else '❌ No'}",
            f"GUI: {'✅ Yes' if tool.has_gui else '❌ No'}",
            f"Parser: {'✅ Yes' if tool.has_parser else '❌ No'}",
        ]
        self.lbl_tool_caps.setText(" | ".join(caps))

        self.btn_test.setEnabled(True)
        self.btn_open_gui.setEnabled(tool.has_gui)

        self.txt_install.setPlainText(tool.install_guide or "No installation instructions needed.")

    @Slot()
    def _run_tool_test(self):
        if not self.selected_tool:
            return

        self.btn_test.setEnabled(False)
        self.txt_output.setPlainText(f"Running safe diagnostic check for '{self.selected_tool.name}'...\n")

        self._test_worker = ToolTestWorker(self.registry, self.selected_tool.name)
        self._test_worker.test_completed.connect(self._on_test_completed)
        self._test_worker.start()

    @Slot(str, bool, str, int)
    def _on_test_completed(self, tool_name: str, success: bool, output: str, exit_code: int):
        self.btn_test.setEnabled(True)
        status_label = "SUCCESS" if success else "FAILED / UNAVAILABLE"
        log = (
            f"=== Safe Tool Diagnostic: {tool_name} [{status_label}] ===\n"
            f"Exit Code: {exit_code}\n\n"
            f"{output}\n"
        )
        self.txt_output.setPlainText(log)

    @Slot()
    def _copy_install_command(self):
        cmd = self.txt_install.toPlainText().strip()
        if cmd:
            QApplication.clipboard().setText(cmd)
            QMessageBox.information(self, "Copied", "Installation command copied to clipboard.")

    @Slot()
    def _on_open_gui_clicked(self):
        if self.selected_tool and self.selected_tool.has_gui:
            self.open_scanner_requested.emit(self.selected_tool.name)

