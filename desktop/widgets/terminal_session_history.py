"""Terminal Session History & Evidence Vault Widget for CyberSecuritySuite.

Displays vaulted terminal sessions with cryptographic SHA-256 hashes, recorded
commands, working directories, and execution exit statuses. Supports inspection of
raw ANSI, clean plain text, and redacted report-ready outputs.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List, Optional

from PySide6.QtCore import Qt, Slot
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from storage.db import Database
from storage.models import Project, TerminalSessionRecord
from terminal.recorder import redact_sensitive_text


class SessionViewerDialog(QDialog):
    """Dialog showing detailed session logs with tabs for Plain Text, Redacted, Raw, and JSON."""

    def __init__(self, session: TerminalSessionRecord, parent=None):
        super().__init__(parent)
        self.session = session
        self.setWindowTitle(f"Terminal Session Vault — {session.session_id}")
        self.resize(850, 550)

        layout = QVBoxLayout(self)

        # Header Info Banner
        header = QVBoxLayout()
        title = QLabel(f"🖥️ Terminal Session: {session.session_id}")
        title.setStyleSheet("font-weight: bold; font-size: 14px; color: #38bdf8;")
        header.addWidget(title)

        time_range = f"{session.started_at} to {session.ended_at or 'Incomplete'}"
        meta = QLabel(
            f"Directory: {session.working_directory} | Exit: {session.exit_status} | Commands: {session.command_count}\n"
            f"Recorded: {time_range}\n"
            f"SHA-256: {session.sha256_hash}"
        )
        meta.setStyleSheet("color: #94a3b8; font-family: monospace; font-size: 11px;")
        header.addWidget(meta)
        layout.addLayout(header)

        # Tabs for different representations
        tabs = QTabWidget()

        # 1. Clean Plain Text
        self.txt_plain = QPlainTextEdit()
        self.txt_plain.setReadOnly(True)
        if session.plain_text_path and os.path.exists(session.plain_text_path):
            try:
                plain_content = Path(session.plain_text_path).read_text(encoding="utf-8", errors="replace")
                self.txt_plain.setPlainText(plain_content)
            except Exception as e:
                self.txt_plain.setPlainText(f"Error loading plain text log: {e}")
        else:
            self.txt_plain.setPlainText("Plain text log file not found on disk.")
        tabs.addTab(self.txt_plain, "📄 Clean Plain Text")

        # 2. Redacted Report View
        self.txt_redacted = QPlainTextEdit()
        self.txt_redacted.setReadOnly(True)
        redacted_content = redact_sensitive_text(self.txt_plain.toPlainText())
        self.txt_redacted.setPlainText(redacted_content)
        tabs.addTab(self.txt_redacted, "🛡️ Redacted Report Preview")

        # 3. Raw ANSI Log
        self.txt_raw = QPlainTextEdit()
        self.txt_raw.setReadOnly(True)
        if session.raw_output_path and os.path.exists(session.raw_output_path):
            try:
                raw_content = Path(session.raw_output_path).read_text(encoding="utf-8", errors="replace")
                self.txt_raw.setPlainText(raw_content)
            except Exception as e:
                self.txt_raw.setPlainText(f"Error loading raw ANSI log: {e}")
        else:
            self.txt_raw.setPlainText("Raw ANSI log file not found on disk.")
        tabs.addTab(self.txt_raw, "🖥️ Raw ANSI Stream")

        # 4. JSON Events & Commands
        self.txt_json = QPlainTextEdit()
        self.txt_json.setReadOnly(True)
        events_json_path = (
            Path(session.plain_text_path).with_suffix(".json")
            if session.plain_text_path
            else None
        )
        if events_json_path and events_json_path.exists():
            try:
                json_content = events_json_path.read_text(encoding="utf-8", errors="replace")
                self.txt_json.setPlainText(json_content)
            except Exception:
                self.txt_json.setPlainText(session.commands_json or "[]")
        else:
            self.txt_json.setPlainText(session.commands_json or "[]")
        tabs.addTab(self.txt_json, "📊 Structured JSON Events")

        layout.addWidget(tabs)

        # Bottom Buttons
        btn_bar = QHBoxLayout()
        btn_bar.addStretch()

        btn_copy = QPushButton("📋 Copy Current View")
        btn_copy.clicked.connect(lambda: QApplication.clipboard().setText(tabs.currentWidget().toPlainText()))
        btn_bar.addWidget(btn_copy)

        btn_close = QPushButton("Close")
        btn_close.clicked.connect(self.accept)
        btn_bar.addWidget(btn_close)

        layout.addLayout(btn_bar)


class TerminalSessionHistoryWidget(QWidget):
    """Vault and management interface for recorded terminal sessions."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.active_project: Optional[Project] = None
        self.db: Optional[Database] = None
        self._sessions: List[TerminalSessionRecord] = []

        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        # Top Control Bar
        top_bar = QHBoxLayout()
        self.lbl_title = QLabel("🔒 Recorded Terminal Sessions & Cryptographic Vault")
        self.lbl_title.setStyleSheet("font-weight: bold; font-size: 12px; color: #38bdf8;")
        top_bar.addWidget(self.lbl_title)
        top_bar.addStretch()

        self.btn_refresh = QPushButton("🔄 Refresh Sessions")
        self.btn_refresh.setFixedHeight(24)
        self.btn_refresh.clicked.connect(self.load_sessions)
        top_bar.addWidget(self.btn_refresh)

        self.btn_view = QPushButton("👁️ View Session Content")
        self.btn_view.setFixedHeight(24)
        self.btn_view.setEnabled(False)
        self.btn_view.clicked.connect(self._on_view_clicked)
        top_bar.addWidget(self.btn_view)

        self.btn_export = QPushButton("📤 Export Plain Text")
        self.btn_export.setFixedHeight(24)
        self.btn_export.setEnabled(False)
        self.btn_export.clicked.connect(self._on_export_clicked)
        top_bar.addWidget(self.btn_export)

        self.btn_copy_hash = QPushButton("📋 Copy Hash")
        self.btn_copy_hash.setFixedHeight(24)
        self.btn_copy_hash.setEnabled(False)
        self.btn_copy_hash.clicked.connect(self._on_copy_hash_clicked)
        top_bar.addWidget(self.btn_copy_hash)

        layout.addLayout(top_bar)

        # Sessions Table
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "Session ID",
            "Recorded At",
            "Directory",
            "Exit",
            "Commands",
            "SHA-256 Hash",
            "Evidence Link",
        ])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)

        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        self.table.itemDoubleClicked.connect(self._on_view_clicked)
        layout.addWidget(self.table)

    def set_context(self, project: Optional[Project], db: Optional[Database]):
        """Sets current active project and database instance."""
        self.active_project = project
        self.db = db
        self.load_sessions()

    def load_sessions(self):
        """Loads and displays all sessions for the active project from SQLite."""
        self.table.setRowCount(0)
        self._sessions.clear()
        self.btn_view.setEnabled(False)
        self.btn_export.setEnabled(False)
        self.btn_copy_hash.setEnabled(False)

        if not self.active_project or not self.db:
            return

        try:
            self._sessions = self.db.list_terminal_sessions(self.active_project.id)
            self.table.setRowCount(len(self._sessions))

            for row_idx, s in enumerate(self._sessions):
                item_id = QTableWidgetItem(s.session_id)
                item_id.setFlags(item_id.flags() & ~Qt.ItemFlag.ItemIsEditable)

                item_time = QTableWidgetItem(s.started_at[:19].replace("T", " "))
                item_time.setFlags(item_time.flags() & ~Qt.ItemFlag.ItemIsEditable)

                item_cwd = QTableWidgetItem(s.working_directory)
                item_cwd.setFlags(item_cwd.flags() & ~Qt.ItemFlag.ItemIsEditable)

                exit_str = str(s.exit_status) if s.exit_status is not None else "0"
                item_exit = QTableWidgetItem(exit_str)
                item_exit.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                item_exit.setFlags(item_exit.flags() & ~Qt.ItemFlag.ItemIsEditable)

                item_cmds = QTableWidgetItem(str(s.command_count))
                item_cmds.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                item_cmds.setFlags(item_cmds.flags() & ~Qt.ItemFlag.ItemIsEditable)

                hash_str = s.sha256_hash or "-"
                item_hash = QTableWidgetItem(hash_str)
                item_hash.setToolTip(s.sha256_hash)
                item_hash.setFlags(item_hash.flags() & ~Qt.ItemFlag.ItemIsEditable)

                ev_str = f"Evidence #{s.evidence_id}" if s.evidence_id else "Not Vaulted"
                item_ev = QTableWidgetItem(ev_str)
                item_ev.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                item_ev.setFlags(item_ev.flags() & ~Qt.ItemFlag.ItemIsEditable)

                self.table.setItem(row_idx, 0, item_id)
                self.table.setItem(row_idx, 1, item_time)
                self.table.setItem(row_idx, 2, item_cwd)
                self.table.setItem(row_idx, 3, item_exit)
                self.table.setItem(row_idx, 4, item_cmds)
                self.table.setItem(row_idx, 5, item_hash)
                self.table.setItem(row_idx, 6, item_ev)
        except Exception:
            pass

    @Slot()
    def _on_selection_changed(self):
        has_sel = len(self.table.selectedItems()) > 0
        self.btn_view.setEnabled(has_sel)
        self.btn_export.setEnabled(has_sel)
        self.btn_copy_hash.setEnabled(has_sel)

    def _get_selected_session(self) -> Optional[TerminalSessionRecord]:
        row = self.table.currentRow()
        if 0 <= row < len(self._sessions):
            return self._sessions[row]
        return None

    @Slot()
    def _on_view_clicked(self):
        sess = self._get_selected_session()
        if not sess:
            return
        dlg = SessionViewerDialog(sess, parent=self)
        dlg.exec()

    @Slot()
    def _on_export_clicked(self):
        sess = self._get_selected_session()
        if not sess or not sess.plain_text_path or not os.path.exists(sess.plain_text_path):
            QMessageBox.warning(self, "Export Failed", "Plain text session file is not available on disk.")
            return

        default_name = f"export_{sess.session_id}.txt"
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Session Plain Text",
            default_name,
            "Text Files (*.txt);;All Files (*)",
        )
        if file_path:
            try:
                content = Path(sess.plain_text_path).read_text(encoding="utf-8")
                Path(file_path).write_text(content, encoding="utf-8")
                QMessageBox.information(self, "Export Complete", f"Session log exported successfully to:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export session log: {e}")

    @Slot()
    def _on_copy_hash_clicked(self):
        sess = self._get_selected_session()
        if sess and sess.sha256_hash:
            QApplication.clipboard().setText(sess.sha256_hash)
            QMessageBox.information(self, "Hash Copied", f"SHA-256 Hash copied to clipboard:\n\n{sess.sha256_hash}")

