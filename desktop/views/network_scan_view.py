"""Network assessment and Nmap scanning view."""

import threading
from pathlib import Path
from typing import Optional

from PySide6.QtCore import QObject, Qt, Signal, Slot
from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from modules.network.nmap_adapter import (
    NmapAdapter,
    NmapExecutionResult,
    NmapScanOptions,
    ScanProfile,
)
from storage.db import Database
from storage.models import Project


class WorkerSignals(QObject):
    output_received = Signal(str, str)
    scan_completed = Signal(object)


class NetworkScanView(QWidget):
    """Network scanning panel with scope enforcement and live terminal streaming."""

    def __init__(self, db: Database, parent=None):
        super().__init__(parent)
        self.db = db
        self.adapter = NmapAdapter(db)
        self.active_project: Optional[Project] = None
        self.signals = WorkerSignals()
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

        # Header & Project status
        top_bar = QHBoxLayout()
        header = QLabel("Network Discovery & Service Assessment")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #f8fafc;")
        top_bar.addWidget(header)
        top_bar.addStretch()

        self.project_label = QLabel("No project selected.")
        self.project_label.setStyleSheet("color: #38bdf8; font-weight: 500;")
        top_bar.addWidget(self.project_label)
        layout.addLayout(top_bar)

        # Scan Configuration Box
        config_group = QGroupBox("Scan Configuration & Scope Guard")
        form = QFormLayout(config_group)

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter target IP, CIDR, or Hostname (e.g. 127.0.0.1, 192.168.1.10)")
        form.addRow("Target Address *:", self.target_input)

        self.profile_combo = QComboBox()
        self.profile_combo.addItem("Top Ports Fast Scan (-F -T4)", ScanProfile.TOP_PORTS)
        self.profile_combo.addItem("Ping Sweep Discovery (-sn)", ScanProfile.PING_DISCOVERY)
        self.profile_combo.addItem("Service & Version Detection (-sV -T4)", ScanProfile.SERVICE_VERSION)
        self.profile_combo.addItem("Custom Ports Scan", ScanProfile.CUSTOM)
        self.profile_combo.currentIndexChanged.connect(self._on_profile_changed)
        form.addRow("Scan Profile:", self.profile_combo)

        self.ports_input = QLineEdit()
        self.ports_input.setPlaceholderText("e.g. 21,22,80,443,8080 or 1-1000")
        self.ports_input.setEnabled(False)
        form.addRow("Custom Ports:", self.ports_input)

        # Buttons
        btn_bar = QHBoxLayout()
        self.scan_btn = QPushButton("Execute Authorized Scan")
        self.scan_btn.setProperty("class", "action-primary")
        self.scan_btn.clicked.connect(self._start_scan)
        btn_bar.addWidget(self.scan_btn)

        self.cancel_btn = QPushButton("Cancel Scan")
        self.cancel_btn.setProperty("class", "action-secondary")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._cancel_scan)
        btn_bar.addWidget(self.cancel_btn)

        btn_bar.addStretch()
        self.status_label = QLabel("Status: Idle")
        btn_bar.addWidget(self.status_label)
        form.addRow(btn_bar)

        layout.addWidget(config_group)

        # Discovered Services Table
        results_header = QLabel("Discovered Hosts & Open Services")
        results_header.setStyleSheet("font-size: 14px; font-weight: bold; margin-top: 8px;")
        layout.addWidget(results_header)

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(["Host IP", "Port", "Protocol", "State", "Service / Version"])
        self.results_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        layout.addWidget(self.results_table)

    def _on_profile_changed(self):
        is_custom = self.profile_combo.currentData() == ScanProfile.CUSTOM
        self.ports_input.setEnabled(is_custom)

    def _start_scan(self):
        if not self.active_project:
            QMessageBox.warning(self, "No Project", "Please select or create an assessment project first.")
            return

        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Input Error", "Please specify a target IP, CIDR, or hostname.")
            return

        profile = self.profile_combo.currentData()
        ports = self.ports_input.text().strip() if profile == ScanProfile.CUSTOM else None

        options = NmapScanOptions(
            target=target,
            profile=profile,
            ports=ports,
        )

        scopes = self.db.list_scopes(self.active_project.id)

        self.scan_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.status_label.setText(f"Status: Scanning {target}...")

        # Run scan in background thread to prevent blocking GUI
        def worker():
            evidence_dir = Path("storage/evidence")
            res = self.adapter.execute_scan(
                project_id=self.active_project.id,
                options=options,
                scopes=scopes,
                on_output=lambda chunk, stream: self.signals.output_received.emit(chunk, stream),
                evidence_dir=evidence_dir,
            )
            self.signals.scan_completed.emit(res)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()

    def _cancel_scan(self):
        self.adapter.runner.cancel()
        self.status_label.setText("Status: Cancellation requested...")
        self.cancel_btn.setEnabled(False)

    @Slot(str, str)
    def _on_output_received(self, chunk: str, stream: str):
        # We also pass output to the main terminal widget via a callback if connected
        window = self.window()
        if hasattr(window, "terminal_widget"):
            window.terminal_widget.append_output(chunk, stream)

    @Slot(object)
    def _on_scan_completed(self, result: NmapExecutionResult):
        self.scan_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)

        if not result.is_authorized:
            self.status_label.setText("Status: Scope Check Failed!")
            QMessageBox.critical(
                self,
                "Unauthorized Target Scope",
                f"Execution blocked by Scope Guard:\n\n{result.scope_reason}\n\n"
                "Please add this target to the authorized project scopes first.",
            )
            return

        self.status_label.setText(
            f"Status: Scan finished with status {result.execution.status.value} ({result.execution.duration_seconds}s)"
        )

        # Populate results table
        self.results_table.setRowCount(0)
        if result.scan_result and result.scan_result.hosts:
            row = 0
            for host in result.scan_result.hosts:
                for port in host.ports:
                    self.results_table.insertRow(row)
                    self.results_table.setItem(row, 0, QTableWidgetItem(host.ip))
                    self.results_table.setItem(row, 1, QTableWidgetItem(str(port.port_id)))
                    self.results_table.setItem(row, 2, QTableWidgetItem(port.protocol))
                    self.results_table.setItem(row, 3, QTableWidgetItem(port.state))
                    self.results_table.setItem(row, 4, QTableWidgetItem(port.service_summary))
                    row += 1

        window = self.window()
        if hasattr(window, "findings_view") and self.active_project:
            window.findings_view.load_findings(self.active_project.id)
