"""Web Application and API assessment view integrating c0desec."""

import threading
from pathlib import Path
from typing import Optional

from PySide6.QtCore import QObject, Qt, Signal, Slot
from PySide6.QtWidgets import (
    QCheckBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from modules.web.c0desec_adapter import (
    WebScanOptions,
    WebScanResult,
    WebSecurityAdapter,
)
from storage.db import Database
from storage.models import Project, ToolExecution


class WebWorkerSignals(QObject):
    output_received = Signal(str, str)
    scan_completed = Signal(bool, str, object, object)


class WebScanView(QWidget):
    """Web & API assessment interface with scope enforcement and secret detection."""

    def __init__(self, db: Database, parent=None):
        super().__init__(parent)
        self.db = db
        self.adapter = WebSecurityAdapter(db)
        self.active_project: Optional[Project] = None

        self.signals = WebWorkerSignals()
        self.signals.output_received.connect(self._on_output_received)
        self.signals.scan_completed.connect(self._on_scan_completed)

        self._init_ui()

    def set_active_project(self, project: Optional[Project]):
        self.active_project = project
        if project:
            self.project_label.setText(f"Active Project: {project.name} (ID: {project.id})")
        else:
            self.project_label.setText("No project selected.")

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Header bar
        top_bar = QHBoxLayout()
        header = QLabel("Web & API Security Assessment (c0desec)")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #f8fafc;")
        top_bar.addWidget(header)
        top_bar.addStretch()

        self.project_label = QLabel("No project selected.")
        self.project_label.setStyleSheet("color: #38bdf8; font-weight: 500;")
        top_bar.addWidget(self.project_label)
        layout.addLayout(top_bar)

        # Config Box
        config_group = QGroupBox("Target Scope & Assessment Profiles")
        form = QFormLayout(config_group)

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter target URL (e.g. http://127.0.0.1:8080, https://app.targetlab.corp)")
        form.addRow("Target Web URL *:", self.url_input)

        # Checkboxes for modules
        check_bar = QHBoxLayout()
        self.cb_headers = QCheckBox("HTTP Security Headers")
        self.cb_headers.setChecked(True)
        self.cb_cors = QCheckBox("CORS Misconfiguration")
        self.cb_cors.setChecked(True)
        self.cb_secrets = QCheckBox("JS Secret Scanning")
        self.cb_secrets.setChecked(True)
        self.cb_endpoints = QCheckBox("Endpoint Discovery")
        self.cb_endpoints.setChecked(True)

        check_bar.addWidget(self.cb_headers)
        check_bar.addWidget(self.cb_cors)
        check_bar.addWidget(self.cb_secrets)
        check_bar.addWidget(self.cb_endpoints)
        check_bar.addStretch()
        form.addRow("Enabled Checks:", check_bar)

        # Buttons bar
        btn_bar = QHBoxLayout()
        self.scan_btn = QPushButton("Execute Authorized Web Scan")
        self.scan_btn.setProperty("class", "action-primary")
        self.scan_btn.clicked.connect(self._start_scan)
        btn_bar.addWidget(self.scan_btn)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setProperty("class", "action-secondary")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._cancel_scan)
        btn_bar.addWidget(self.cancel_btn)

        btn_bar.addStretch()
        self.status_label = QLabel("Status: Idle")
        btn_bar.addWidget(self.status_label)
        form.addRow(btn_bar)

        layout.addWidget(config_group)

        # Results Tabs
        self.results_tabs = QTabWidget()

        # Tab 1: Endpoints
        self.endpoints_table = QTableWidget()
        self.endpoints_table.setColumnCount(1)
        self.endpoints_table.setHorizontalHeaderLabels(["Discovered Endpoint / Route URL"])
        self.endpoints_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.results_tabs.addTab(self.endpoints_table, "🌐 Discovered Routes")

        # Tab 2: Secrets
        self.secrets_table = QTableWidget()
        self.secrets_table.setColumnCount(4)
        self.secrets_table.setHorizontalHeaderLabels(["Secret Kind", "Redacted Preview", "Source Asset", "Context Snippet"])
        self.secrets_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.secrets_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.results_tabs.addTab(self.secrets_table, "🔑 JS Secret Candidates")

        # Tab 3: Headers
        self.headers_table = QTableWidget()
        self.headers_table.setColumnCount(2)
        self.headers_table.setHorizontalHeaderLabels(["Header Name", "Header Value"])
        self.headers_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.headers_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.results_tabs.addTab(self.headers_table, "📋 Response Headers")

        layout.addWidget(self.results_tabs)

    def _start_scan(self):
        if not self.active_project:
            QMessageBox.warning(self, "No Project", "Please select or create an assessment project first.")
            return

        target_url = self.url_input.text().strip()
        if not target_url:
            QMessageBox.warning(self, "Input Error", "Please specify a target URL.")
            return

        options = WebScanOptions(
            target_url=target_url,
            check_headers=self.cb_headers.isChecked(),
            check_cors=self.cb_cors.isChecked(),
            check_js_secrets=self.cb_secrets.isChecked(),
            discover_endpoints=self.cb_endpoints.isChecked(),
            check_dns=True,
            timeout=10.0,
        )

        scopes = self.db.list_scopes(self.active_project.id)

        self.scan_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.status_label.setText(f"Status: Probing {target_url}...")

        def worker():
            ev_dir = Path("storage/evidence")
            success, msg, res, exec_rec = self.adapter.execute_scan(
                project_id=self.active_project.id,
                options=options,
                scopes=scopes,
                on_output=lambda chunk, stream: self.signals.output_received.emit(chunk, stream),
                evidence_dir=ev_dir,
            )
            self.signals.scan_completed.emit(success, msg, res, exec_rec)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()

    def _cancel_scan(self):
        self.adapter.cancel()
        self.status_label.setText("Status: Cancellation requested...")
        self.cancel_btn.setEnabled(False)

    @Slot(str, str)
    def _on_output_received(self, chunk: str, stream: str):
        window = self.window()
        if hasattr(window, "terminal_widget"):
            window.terminal_widget.append_output(chunk, stream)

    @Slot(bool, str, object, object)
    def _on_scan_completed(
        self,
        success: bool,
        message: str,
        result: Optional[WebScanResult],
        execution: Optional[ToolExecution],
    ):
        self.scan_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)

        if not success:
            self.status_label.setText("Status: Scope Check Failed!")
            QMessageBox.critical(
                self,
                "Unauthorized Target Scope",
                f"Web Assessment blocked by Scope Guard:\n\n{message}\n\n"
                "Please add this domain/IP to the authorized project scopes first.",
            )
            return

        self.status_label.setText(
            f"Status: Assessment finished ({execution.status.value if execution else 'OK'})"
        )

        if not result:
            return

        # 1. Populate endpoints
        self.endpoints_table.setRowCount(len(result.endpoints))
        for row, ep in enumerate(result.endpoints):
            self.endpoints_table.setItem(row, 0, QTableWidgetItem(ep))

        # 2. Populate secrets
        self.secrets_table.setRowCount(len(result.secrets))
        for row, sec in enumerate(result.secrets):
            self.secrets_table.setItem(row, 0, QTableWidgetItem(sec.secret_type))
            self.secrets_table.setItem(row, 1, QTableWidgetItem(sec.redacted_preview))
            self.secrets_table.setItem(row, 2, QTableWidgetItem(sec.source_url))
            self.secrets_table.setItem(row, 3, QTableWidgetItem(sec.context_snippet))

        # 3. Populate headers
        self.headers_table.setRowCount(len(result.headers))
        for row, (hname, hval) in enumerate(result.headers.items()):
            self.headers_table.setItem(row, 0, QTableWidgetItem(hname))
            self.headers_table.setItem(row, 1, QTableWidgetItem(hval))

        # Refresh findings view
        window = self.window()
        if hasattr(window, "findings_view") and self.active_project:
            window.findings_view.load_findings(self.active_project.id)
