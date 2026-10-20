"""Web Application and API assessment view integrating c0desec."""

import threading
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

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
    QProgressBar,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.scope import ScopeAuthorizationService
from modules.web.c0desec_adapter import (
    WebScanOptions,
    WebScanResult,
    WebSecurityAdapter,
)
from modules.web.gobuster_adapter import GobusterAdapter, GobusterOptions
from modules.web.sqlmap_adapter import SQLMapAdapter, SQLMapOptions
from modules.web.wafw00f_adapter import WAFW00FAdapter, WAFW00FOptions
from storage.db import Database
from storage.models import Finding, FindingSeverity, Project, ToolExecution


class WebWorkerSignals(QObject):
    output_received = Signal(str, str)
    scan_completed = Signal(bool, str, object, object)


class WebScanView(QWidget):
    """Web & API assessment interface with scope enforcement, live validation, and secret detection."""

    def __init__(self, db: Database, parent=None):
        super().__init__(parent)
        self.db = db
        self.adapter = WebSecurityAdapter(db)
        self.wafw00f_adapter = WAFW00FAdapter(db)
        self.sqlmap_adapter = SQLMapAdapter(db)
        self.gobuster_adapter = GobusterAdapter(db)
        self.active_project: Optional[Project] = None
        self._current_findings: List[Finding] = []

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
        self._validate_scope_live()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # 1. Header bar
        top_bar = QHBoxLayout()
        header = QLabel("Web & API Security Assessment (c0desec)")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #f8fafc;")
        top_bar.addWidget(header)
        top_bar.addStretch()

        self.project_label = QLabel("No project selected.")
        self.project_label.setStyleSheet("color: #38bdf8; font-weight: 500;")
        top_bar.addWidget(self.project_label)
        layout.addLayout(top_bar)

        # 2. Config & Scope Guard Box
        config_group = QGroupBox("Target Scope & Assessment Profiles")
        form = QFormLayout(config_group)

        # Target URL & Live Scope Status
        url_row = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter target URL (e.g. http://127.0.0.1:8080, https://app.targetlab.corp)")
        self.url_input.textChanged.connect(self._validate_scope_live)
        url_row.addWidget(self.url_input, 4)

        self.scope_status_label = QLabel("Scope: No Project Selected")
        self.scope_status_label.setStyleSheet("color: #94a3b8; font-weight: 500; padding-left: 8px;")
        url_row.addWidget(self.scope_status_label, 2)
        form.addRow("Target Web URL *:", url_row)

        # Checkboxes for modules
        check_box = QVBoxLayout()
        row1 = QHBoxLayout()
        self.cb_headers = QCheckBox("HTTP Security Headers")
        self.cb_headers.setChecked(True)
        self.cb_cors = QCheckBox("CORS Policy")
        self.cb_cors.setChecked(True)
        self.cb_secrets = QCheckBox("JS Secret Scanning")
        self.cb_secrets.setChecked(True)
        self.cb_endpoints = QCheckBox("Endpoint Discovery")
        self.cb_endpoints.setChecked(True)
        row1.addWidget(self.cb_headers)
        row1.addWidget(self.cb_cors)
        row1.addWidget(self.cb_secrets)
        row1.addWidget(self.cb_endpoints)
        row1.addStretch()

        row2 = QHBoxLayout()
        self.cb_waf = QCheckBox("WAF Fingerprint (WAFW00F)")
        self.cb_waf.setChecked(True)
        self.cb_sqlmap = QCheckBox("SQL Injection (SQLMap)")
        self.cb_sqlmap.setChecked(False)
        self.cb_gobuster = QCheckBox("Directory Fuzzing (Gobuster)")
        self.cb_gobuster.setChecked(False)
        row2.addWidget(self.cb_waf)
        row2.addWidget(self.cb_sqlmap)
        row2.addWidget(self.cb_gobuster)
        row2.addStretch()

        check_box.addLayout(row1)
        check_box.addLayout(row2)
        form.addRow("Security Modules:", check_box)

        # Execution Controls & Progress
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

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(14)
        self.progress_bar.setStyleSheet(
            "QProgressBar { background-color: #1e293b; border-radius: 4px; text-align: center; font-size: 10px; color: #94a3b8; }"
            "QProgressBar::chunk { background-color: #0284c7; border-radius: 4px; }"
        )
        btn_bar.addWidget(self.progress_bar, 2)

        self.status_label = QLabel("Status: Idle")
        self.status_label.setStyleSheet("color: #94a3b8;")
        btn_bar.addWidget(self.status_label, 2)
        form.addRow(btn_bar)

        layout.addWidget(config_group)

        # 3. Multi-Tab Results Display
        self.results_tabs = QTabWidget()

        # Tab 0: Structured Findings (Primary Table + Details Pane)
        findings_widget = QWidget()
        findings_layout = QVBoxLayout(findings_widget)
        findings_layout.setContentsMargins(4, 4, 4, 4)

        findings_splitter = QSplitter(Qt.Orientation.Vertical)

        # Findings Table
        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(4)
        self.findings_table.setHorizontalHeaderLabels(["Severity", "Affected Asset / URL", "Finding Title", "Remediation"])
        self.findings_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.findings_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.findings_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.findings_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.findings_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.findings_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.findings_table.itemSelectionChanged.connect(self._on_finding_selected)
        findings_splitter.addWidget(self.findings_table)

        # Details Panel
        detail_container = QWidget()
        detail_layout = QVBoxLayout(detail_container)
        detail_layout.setContentsMargins(6, 6, 6, 6)
        detail_layout.setSpacing(6)

        detail_header = QLabel("Finding Details & Redacted Evidence")
        detail_header.setStyleSheet("font-weight: 600; color: #38bdf8;")
        detail_layout.addWidget(detail_header)

        self.finding_details_text = QTextEdit()
        self.finding_details_text.setReadOnly(True)
        self.finding_details_text.setPlaceholderText("Select a finding row above to view technical details, explanation, and redacted evidence.")
        detail_layout.addWidget(self.finding_details_text)

        findings_splitter.addWidget(detail_container)
        findings_splitter.setStretchFactor(0, 6)
        findings_splitter.setStretchFactor(1, 4)

        findings_layout.addWidget(findings_splitter)
        self.results_tabs.addTab(findings_widget, "🛡️ Structured Findings")

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
        self.secrets_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.secrets_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.secrets_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
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

    def _validate_scope_live(self):
        """Live scope validation as user types the target URL."""
        if not self.active_project:
            self.scope_status_label.setText("Scope: No Project Selected")
            self.scope_status_label.setStyleSheet("color: #94a3b8; font-weight: 500;")
            return

        raw_url = self.url_input.text().strip()
        if not raw_url:
            self.scope_status_label.setText("Scope: Awaiting Target URL")
            self.scope_status_label.setStyleSheet("color: #94a3b8; font-weight: 500;")
            return

        target = raw_url if raw_url.startswith(("http://", "https://")) else f"http://{raw_url}"
        parsed = urlparse(target)
        host = parsed.hostname or target

        scopes = self.db.list_scopes(self.active_project.id)
        check = ScopeAuthorizationService.is_target_authorized(host, scopes)
        if check.is_allowed:
            self.scope_status_label.setText("Scope: Authorized (In-Scope) ✓")
            self.scope_status_label.setStyleSheet("color: #4ade80; font-weight: bold;")
        else:
            self.scope_status_label.setText("Scope: Unauthorized / Out of Scope ✗")
            self.scope_status_label.setStyleSheet("color: #f87171; font-weight: bold;")

    def _start_scan(self):
        if not self.active_project:
            QMessageBox.warning(self, "No Project", "Please select or create an assessment project first.")
            return

        target_url = self.url_input.text().strip()
        if not target_url:
            QMessageBox.warning(self, "Input Error", "Please specify a target URL.")
            return

        # Active assessment confirmation guard
        if self.cb_sqlmap.isChecked() or self.cb_gobuster.isChecked():
            confirm = QMessageBox.question(
                self,
                "Confirm Active Security Assessment",
                f"You have selected ACTIVE assessment tools (SQLMap / Gobuster) targeting:\n\n{target_url}\n\n"
                "Active scans send fuzzing requests and test injection vectors.\n"
                "Do you confirm that you have explicit, documented authorization to test this target?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if confirm != QMessageBox.StandardButton.Yes:
                self.status_label.setText("Status: Active scan aborted by user.")
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
        self.progress_bar.setRange(0, 0)  # Indeterminate animation
        self.status_label.setText(f"Status: Probing {target_url}...")
        self.status_label.setStyleSheet("color: #38bdf8;")

        run_waf = self.cb_waf.isChecked()
        run_sqlmap = self.cb_sqlmap.isChecked()
        run_gobuster = self.cb_gobuster.isChecked()

        def worker():
            ev_dir = Path("storage/evidence")
            all_findings = []
            all_endpoints = []
            all_secrets = []
            all_headers = {}
            primary_exec = None

            # 1. c0desec passive scan
            if options.check_headers or options.check_cors or options.check_js_secrets or options.discover_endpoints:
                success, msg, res, exec_rec = self.adapter.execute_scan(
                    project_id=self.active_project.id,
                    options=options,
                    scopes=scopes,
                    on_output=lambda chunk, stream: self.signals.output_received.emit(chunk, stream),
                    evidence_dir=ev_dir,
                )
                primary_exec = exec_rec
                if not success:
                    self.signals.scan_completed.emit(False, msg, None, exec_rec)
                    return
                if res:
                    all_findings.extend(res.findings)
                    all_endpoints.extend(res.endpoints)
                    all_secrets.extend(res.secrets)
                    all_headers.update(res.headers)

            # 2. WAFW00F fingerprinting
            if run_waf:
                self.signals.output_received.emit("\n[*] Launching WAFW00F Fingerprinting...\n", "stdout")
                waf_opts = WAFW00FOptions(target_url=target_url)
                w_ok, w_msg, w_findings, w_exec = self.wafw00f_adapter.execute_scan(
                    project_id=self.active_project.id,
                    options=waf_opts,
                    scopes=scopes,
                    on_output=lambda chunk, stream: self.signals.output_received.emit(chunk, stream),
                    evidence_dir=ev_dir,
                )
                if w_exec and not primary_exec:
                    primary_exec = w_exec
                all_findings.extend(w_findings)

            # 3. SQLMap injection check
            if run_sqlmap:
                self.signals.output_received.emit("\n[*] Launching SQLMap Injection Checks...\n", "stdout")
                s_opts = SQLMapOptions(target_url=target_url)
                s_ok, s_msg, s_findings, s_exec = self.sqlmap_adapter.execute_scan(
                    project_id=self.active_project.id,
                    options=s_opts,
                    scopes=scopes,
                    on_output=lambda chunk, stream: self.signals.output_received.emit(chunk, stream),
                    evidence_dir=ev_dir,
                )
                if s_exec and not primary_exec:
                    primary_exec = s_exec
                all_findings.extend(s_findings)

            # 4. Gobuster directory discovery
            if run_gobuster:
                self.signals.output_received.emit("\n[*] Launching Gobuster Directory Discovery...\n", "stdout")
                g_opts = GobusterOptions(target_url=target_url)
                g_ok, g_msg, g_findings, g_exec = self.gobuster_adapter.execute_scan(
                    project_id=self.active_project.id,
                    options=g_opts,
                    scopes=scopes,
                    on_output=lambda chunk, stream: self.signals.output_received.emit(chunk, stream),
                    evidence_dir=ev_dir,
                )
                if g_exec and not primary_exec:
                    primary_exec = g_exec
                all_findings.extend(g_findings)
                for f in g_findings:
                    if f.affected_asset and f.affected_asset not in all_endpoints:
                        all_endpoints.append(f.affected_asset)

            composite_res = WebScanResult(
                target_url=target_url,
                findings=all_findings,
                endpoints=all_endpoints,
                secrets=all_secrets,
                headers=all_headers,
                response_status=200,
            )
            self.signals.scan_completed.emit(True, "Assessment complete", composite_res, primary_exec)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()

    def _cancel_scan(self):
        self.adapter.cancel()
        self.wafw00f_adapter.cancel()
        self.sqlmap_adapter.cancel()
        self.gobuster_adapter.cancel()
        self.status_label.setText("Status: Cancellation requested...")
        self.status_label.setStyleSheet("color: #fbbf24;")
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
        self.progress_bar.setRange(0, 100)

        if not success:
            self.progress_bar.setValue(0)
            self.status_label.setText("Status: Scope Check Failed!")
            self.status_label.setStyleSheet("color: #f87171; font-weight: bold;")
            QMessageBox.critical(
                self,
                "Unauthorized Target Scope",
                f"Web Assessment blocked by Scope Guard:\n\n{message}\n\n"
                "Please add this domain/IP to the authorized project scopes first.",
            )
            return

        status_str = execution.status.value if execution else "OK"
        if status_str == "completed":
            self.progress_bar.setValue(100)
            self.status_label.setText("Status: Assessment completed successfully")
            self.status_label.setStyleSheet("color: #4ade80;")
        elif status_str == "timeout":
            self.progress_bar.setValue(0)
            self.status_label.setText(f"Status: Request Timeout ({message})")
            self.status_label.setStyleSheet("color: #f87171;")
        elif status_str == "cancelled":
            self.progress_bar.setValue(0)
            self.status_label.setText("Status: Assessment cancelled")
            self.status_label.setStyleSheet("color: #fbbf24;")
        else:
            self.progress_bar.setValue(0)
            self.status_label.setText(f"Status: Error - {message}")
            self.status_label.setStyleSheet("color: #f87171;")

        if not result:
            return

        # 1. Populate Structured Findings Table
        self._current_findings = result.findings
        self.findings_table.setRowCount(len(result.findings))
        for row, f in enumerate(result.findings):
            # Severity Item with Color
            sev_item = QTableWidgetItem(f.severity.value.upper())
            sev_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if f.severity == FindingSeverity.CRITICAL:
                sev_item.setForeground(Qt.GlobalColor.red)
            elif f.severity == FindingSeverity.HIGH:
                sev_item.setForeground(Qt.GlobalColor.magenta)
            elif f.severity == FindingSeverity.MEDIUM:
                sev_item.setForeground(Qt.GlobalColor.yellow)
            elif f.severity == FindingSeverity.LOW:
                sev_item.setForeground(Qt.GlobalColor.cyan)
            else:
                sev_item.setForeground(Qt.GlobalColor.gray)

            self.findings_table.setItem(row, 0, sev_item)
            self.findings_table.setItem(row, 1, QTableWidgetItem(f.affected_asset))
            self.findings_table.setItem(row, 2, QTableWidgetItem(f.title))
            self.findings_table.setItem(row, 3, QTableWidgetItem(f.remediation))

        # 2. Populate Endpoints
        self.endpoints_table.setRowCount(len(result.endpoints))
        for row, ep in enumerate(result.endpoints):
            self.endpoints_table.setItem(row, 0, QTableWidgetItem(ep))

        # 3. Populate Secrets (With Redacted Values)
        self.secrets_table.setRowCount(len(result.secrets))
        for row, sec in enumerate(result.secrets):
            self.secrets_table.setItem(row, 0, QTableWidgetItem(sec.secret_type))
            self.secrets_table.setItem(row, 1, QTableWidgetItem(sec.redacted_preview))
            self.secrets_table.setItem(row, 2, QTableWidgetItem(sec.source_url))
            self.secrets_table.setItem(row, 3, QTableWidgetItem(sec.context_snippet))

        # 4. Populate Response Headers
        self.headers_table.setRowCount(len(result.headers))
        for row, (hname, hval) in enumerate(result.headers.items()):
            self.headers_table.setItem(row, 0, QTableWidgetItem(hname))
            self.headers_table.setItem(row, 1, QTableWidgetItem(hval))

        # Select first finding if available
        if result.findings:
            self.findings_table.selectRow(0)

        # Refresh global findings view
        window = self.window()
        if hasattr(window, "findings_view") and self.active_project:
            window.findings_view.load_findings(self.active_project.id)

    def _on_finding_selected(self):
        """Displays technical details, CVSS, and redacted evidence when finding row is selected."""
        selected_rows = self.findings_table.selectionModel().selectedRows()
        if not selected_rows:
            return

        row_idx = selected_rows[0].row()
        if 0 <= row_idx < len(self._current_findings):
            f = self._current_findings[row_idx]
            details = (
                f"### {f.title}\n\n"
                f"**Severity:** {f.severity.value.upper()} (CVSS: {f.cvss_score or 'N/A'})\n"
                f"**Affected Asset / URL:** {f.affected_asset}\n"
                f"**Service / Component:** {f.affected_port_service or 'Web Asset'}\n"
                f"**Verification Status:** {f.validation_status.value}\n\n"
                f"#### Description & Technical Explanation:\n"
                f"{f.description}\n\n"
                f"#### Actionable Remediation Guidance:\n"
                f"{f.remediation}\n"
            )
            self.finding_details_text.setMarkdown(details)
