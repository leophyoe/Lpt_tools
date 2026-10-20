"""Integrated Execution Terminal & Application Console for CyberSecuritySuite.

Provides:
1. Interactive Command Shell with line input, command history, working directory
   tracking, cancellation, and real-time streaming output.
2. Application & Tool Log Console for background scanners and framework events.
"""

from __future__ import annotations

import hashlib
import os
import shlex
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from PySide6.QtCore import QObject, Qt, Signal, Slot
from PySide6.QtGui import QColor, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from storage.db import Database
from storage.models import Evidence, ExecutionStatus, Project, ToolExecution
from terminal.recorder import TerminalSessionRecorder
from terminal.runner import ProcessRunner


class CommandHistoryLineEdit(QLineEdit):
    """Line edit with Up/Down arrow history navigation."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.history: List[str] = []
        self.history_idx: int = -1

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Up:
            if self.history and self.history_idx > 0:
                self.history_idx -= 1
                self.setText(self.history[self.history_idx])
            elif self.history and self.history_idx == -1:
                self.history_idx = len(self.history) - 1
                self.setText(self.history[self.history_idx])
            return
        elif event.key() == Qt.Key.Key_Down:
            if self.history and 0 <= self.history_idx < len(self.history) - 1:
                self.history_idx += 1
                self.setText(self.history[self.history_idx])
            elif self.history and self.history_idx == len(self.history) - 1:
                self.history_idx = -1
                self.clear()
            return
        super().keyPressEvent(event)

    def add_to_history(self, cmd: str):
        clean = cmd.strip()
        if clean and (not self.history or self.history[-1] != clean):
            self.history.append(clean)
        self.history_idx = -1


class ShellWorkerSignals(QObject):
    output_received = Signal(str, str)
    execution_finished = Signal(int, float)


class TerminalWidget(QWidget):
    """Two-tier execution environment: Interactive Command Shell and Tool Log Console."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.runner = ProcessRunner()
        self.cwd = os.getcwd()
        self._current_thread: Optional[threading.Thread] = None
        self.active_project: Optional[Project] = None
        self.db: Optional[Database] = None
        self.shell_recorder = TerminalSessionRecorder()
        self._last_cmd: str = ""

        self.signals = ShellWorkerSignals()
        self.signals.output_received.connect(self._on_shell_output)
        self.signals.execution_finished.connect(self._on_shell_finished)

        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Tab Widget separating Shell vs Application Logs
        self.tabs = QTabWidget()

        # -------------------------------------------------------------
        # Tab 1: VS Code-like Interactive PTY Terminal (xterm.js)
        # -------------------------------------------------------------
        self.vscode_term = None
        if os.environ.get("QT_QPA_PLATFORM") != "offscreen":
            try:
                from desktop.widgets.vscode_terminal import VSCodeTerminal
                self.vscode_term = VSCodeTerminal(cwd=self.cwd)
                self.tabs.addTab(self.vscode_term, "🖥️ VS Code Terminal (Interactive PTY)")
            except Exception:
                self.vscode_term = None

        # -------------------------------------------------------------
        # Tab 2: Interactive Command Shell
        # -------------------------------------------------------------
        shell_widget = QWidget()
        shell_layout = QVBoxLayout(shell_widget)
        shell_layout.setContentsMargins(4, 4, 4, 4)
        shell_layout.setSpacing(4)

        # Top status toolbar for shell
        shell_bar = QHBoxLayout()
        self.shell_status_label = QLabel("Shell: Ready")
        self.shell_status_label.setStyleSheet("color: #4ade80; font-weight: bold; font-size: 11px;")
        shell_bar.addWidget(self.shell_status_label)

        self.cwd_label = QLabel(f"cwd: {self._format_cwd()}")
        self.cwd_label.setStyleSheet("color: #94a3b8; font-size: 11px;")
        shell_bar.addWidget(self.cwd_label)
        shell_bar.addStretch()

        self.btn_clear_shell = QPushButton("Clear")
        self.btn_clear_shell.setFixedHeight(22)
        self.btn_clear_shell.clicked.connect(self.clear_shell)
        shell_bar.addWidget(self.btn_clear_shell)

        self.btn_copy_shell = QPushButton("Copy Output")
        self.btn_copy_shell.setFixedHeight(22)
        self.btn_copy_shell.clicked.connect(self.copy_shell)
        shell_bar.addWidget(self.btn_copy_shell)

        self.lbl_shell_rec_status = QLabel("⚪ Rec: Off")
        self.lbl_shell_rec_status.setStyleSheet("color: #94a3b8; font-size: 11px;")
        shell_bar.addWidget(self.lbl_shell_rec_status)

        self.btn_toggle_shell_rec = QPushButton("🔴 Start Recording")
        self.btn_toggle_shell_rec.setFixedHeight(22)
        self.btn_toggle_shell_rec.clicked.connect(self.toggle_shell_recording)
        shell_bar.addWidget(self.btn_toggle_shell_rec)

        self.btn_save_shell_evidence = QPushButton("💾 Save to Evidence")
        self.btn_save_shell_evidence.setFixedHeight(22)
        self.btn_save_shell_evidence.setStyleSheet("background-color: #0369a1; color: #ffffff; font-weight: bold;")
        self.btn_save_shell_evidence.clicked.connect(lambda: self.save_session_as_evidence("shell"))
        shell_bar.addWidget(self.btn_save_shell_evidence)

        shell_layout.addLayout(shell_bar)

        # Shell Output Display
        self.shell_text = QPlainTextEdit()
        self.shell_text.setObjectName("terminalView")
        self.shell_text.setReadOnly(True)
        self.shell_text.setMaximumBlockCount(10000)
        shell_layout.addWidget(self.shell_text)

        # Command Input Row
        input_bar = QHBoxLayout()
        input_bar.setSpacing(6)

        prompt_label = QLabel("$")
        prompt_label.setStyleSheet("color: #38bdf8; font-weight: bold; font-family: monospace; font-size: 14px;")
        input_bar.addWidget(prompt_label)

        self.cmd_input = CommandHistoryLineEdit()
        self.cmd_input.setPlaceholderText("Type command (e.g. nmap --version, python3 source/web/sqlmap/sqlmap.py --version, ls -la)...")
        self.cmd_input.returnPressed.connect(self.run_command)
        input_bar.addWidget(self.cmd_input, 1)

        self.btn_run = QPushButton("Run")
        self.btn_run.setProperty("class", "action-primary")
        self.btn_run.setFixedHeight(28)
        self.btn_run.clicked.connect(self.run_command)
        input_bar.addWidget(self.btn_run)

        self.btn_stop = QPushButton("Stop")
        self.btn_stop.setProperty("class", "action-secondary")
        self.btn_stop.setFixedHeight(28)
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_command)
        input_bar.addWidget(self.btn_stop)

        shell_layout.addLayout(input_bar)

        self.tabs.addTab(shell_widget, "🖥️ Command Shell")

        # -------------------------------------------------------------
        # Tab 2: Application & Tool Logs Console
        # -------------------------------------------------------------
        logs_widget = QWidget()
        logs_layout = QVBoxLayout(logs_widget)
        logs_layout.setContentsMargins(4, 4, 4, 4)
        logs_layout.setSpacing(4)

        logs_bar = QHBoxLayout()
        self.title_label = QLabel("Application & Automated Tool Event Log")
        self.title_label.setStyleSheet("font-weight: bold; color: #38bdf8; font-size: 11px;")
        logs_bar.addWidget(self.title_label)
        logs_bar.addStretch()

        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setFixedHeight(22)
        self.clear_btn.clicked.connect(self.clear_logs)
        logs_bar.addWidget(self.clear_btn)

        self.copy_btn = QPushButton("Copy All")
        self.copy_btn.setFixedHeight(22)
        self.copy_btn.clicked.connect(self.copy_all)
        logs_bar.addWidget(self.copy_btn)

        self.btn_save_log_evidence = QPushButton("💾 Save Logs to Evidence")
        self.btn_save_log_evidence.setFixedHeight(22)
        self.btn_save_log_evidence.setStyleSheet("background-color: #0369a1; color: #ffffff; font-weight: bold;")
        self.btn_save_log_evidence.clicked.connect(lambda: self.save_session_as_evidence("logs"))
        logs_bar.addWidget(self.btn_save_log_evidence)

        logs_layout.addLayout(logs_bar)

        self.log_text = QPlainTextEdit()
        self.log_text.setObjectName("terminalView")
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumBlockCount(5000)
        logs_layout.addWidget(self.log_text)

        # Backward compatibility reference for existing tests
        self.text_edit = self.log_text

        self.tabs.addTab(logs_widget, "📋 Tool & System Logs")

        # -------------------------------------------------------------
        # Tab 4: AI Copilot & Analyzer
        # -------------------------------------------------------------
        from desktop.widgets.terminal_ai_assistant import TerminalAIAssistantWidget
        self.ai_assistant = TerminalAIAssistantWidget()
        self.ai_assistant.terminal_get_output_cb = self.get_latest_output
        self.ai_assistant.command_ready.connect(self._on_ai_command_ready)
        self.tabs.addTab(self.ai_assistant, "🤖 AI Copilot & Analyzer")

        # -------------------------------------------------------------
        # Tab 5: Sessions & Cryptographic Evidence Vault
        # -------------------------------------------------------------
        from desktop.widgets.terminal_session_history import TerminalSessionHistoryWidget
        self.session_vault = TerminalSessionHistoryWidget()
        self.tabs.addTab(self.session_vault, "📜 Sessions & Evidence Vault")

        layout.addWidget(self.tabs)

        # Display initial shell banner
        self._append_shell_text(
            f"CyberSecuritySuite Command Shell [Ready]\n"
            f"Working Directory: {self.cwd}\n"
            f"Type Ubuntu commands, scripts, or security tools. Press Enter to run.\n\n",
            "system",
        )

    def _format_cwd(self) -> str:
        home = str(Path.home())
        if self.cwd.startswith(home):
            return "~" + self.cwd[len(home):]
        return self.cwd

    def run_command(self):
        """Execute user command entered in the prompt."""
        raw_cmd = self.cmd_input.text().strip()
        if not raw_cmd:
            return

        self.cmd_input.add_to_history(raw_cmd)
        self.cmd_input.clear()

        # Handle built-in 'cd'
        if raw_cmd == "cd" or raw_cmd.startswith("cd "):
            parts = raw_cmd.split(maxsplit=1)
            target_dir = parts[1].strip() if len(parts) > 1 else str(Path.home())
            target_dir = os.path.expanduser(target_dir)
            target_path = Path(self.cwd) / target_dir if not os.path.isabs(target_dir) else Path(target_dir)
            target_path = target_path.resolve()

            if target_path.is_dir():
                self.cwd = str(target_path)
                self.cwd_label.setText(f"cwd: {self._format_cwd()}")
                self._append_shell_text(f"$ {raw_cmd}\n", "prompt")
                self._append_shell_text(f"[+] Directory changed to: {self.cwd}\n\n", "success")
            else:
                self._append_shell_text(f"$ {raw_cmd}\n", "prompt")
                self._append_shell_text(f"[-] cd: {target_dir}: No such directory\n\n", "stderr")
            return

        # Handle 'clear' command in shell
        if raw_cmd == "clear":
            self.shell_text.clear()
            return

        # Parse command with shlex
        try:
            cmd_args = shlex.split(raw_cmd)
        except ValueError as e:
            self._append_shell_text(f"$ {raw_cmd}\n", "prompt")
            self._append_shell_text(f"[-] Command parse error: {e}\n\n", "stderr")
            return

        self._append_shell_text(f"$ {raw_cmd}\n", "prompt")
        self._last_cmd = raw_cmd
        if self.shell_recorder.is_recording:
            self.shell_recorder.record_input(f"$ {raw_cmd}\n")

        self.btn_run.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.shell_status_label.setText("Shell: Running...")
        self.shell_status_label.setStyleSheet("color: #38bdf8; font-weight: bold; font-size: 11px;")

        def worker():
            import time
            start = time.time()
            try:
                res = self.runner.run(
                    cmd_args,
                    cwd=self.cwd,
                    on_output=lambda chunk, stream: self.signals.output_received.emit(chunk, stream),
                )
                dur = time.time() - start
                code = res.exit_code if res.exit_code is not None else 0
                self.signals.execution_finished.emit(code, dur)
            except Exception as e:
                dur = time.time() - start
                self.signals.output_received.emit(f"[-] Execution error: {e}\n", "stderr")
                self.signals.execution_finished.emit(1, dur)

        self._current_thread = threading.Thread(target=worker, daemon=True)
        self._current_thread.start()

    def stop_command(self):
        """Cancel actively running shell command."""
        self.runner.cancel()
        self._append_shell_text("\n[^C Process cancellation sent]\n", "stderr")
        self.btn_stop.setEnabled(False)

    @Slot(str, str)
    def _on_shell_output(self, chunk: str, stream: str):
        if self.shell_recorder.is_recording:
            self.shell_recorder.record_output(chunk)
        self._append_shell_text(chunk, stream)

    @Slot(int, float)
    def _on_shell_finished(self, exit_code: int, duration: float):
        if self.shell_recorder.is_recording:
            self.shell_recorder.record_command(
                self._last_cmd,
                exit_code=exit_code,
                cwd=self.cwd,
                duration=duration,
            )
            self.lbl_shell_rec_status.setText(f"🔴 Rec: Active ({len(self.shell_recorder.events)} events)")

        self.btn_run.setEnabled(True)
        self.btn_stop.setEnabled(False)

        if exit_code == 0:
            status_msg = f"[Process finished with exit code {exit_code} ({duration:.2f}s)]\n\n"
            self._append_shell_text(status_msg, "success")
            self.shell_status_label.setText("Shell: Ready")
            self.shell_status_label.setStyleSheet("color: #4ade80; font-weight: bold; font-size: 11px;")
        else:
            status_msg = f"[Process exited with code {exit_code} ({duration:.2f}s)]\n\n"
            self._append_shell_text(status_msg, "stderr")
            self.shell_status_label.setText(f"Shell: Exited ({exit_code})")
            self.shell_status_label.setStyleSheet("color: #f87171; font-weight: bold; font-size: 11px;")

    def _append_shell_text(self, text: str, stream: str = "stdout"):
        cursor = self.shell_text.textCursor()
        cursor.movePosition(QTextCursor.End)

        fmt = QTextCharFormat()
        if stream == "prompt":
            fmt.setForeground(QColor("#38bdf8"))  # Light blue for prompt
            fmt.setFontWeight(700)
        elif stream == "stderr":
            fmt.setForeground(QColor("#f87171"))  # Red
        elif stream == "system":
            fmt.setForeground(QColor("#a855f7"))  # Purple
        elif stream == "success":
            fmt.setForeground(QColor("#4ade80"))  # Green
        else:
            fmt.setForeground(QColor("#e2e8f0"))  # Light gray

        cursor.insertText(text, fmt)
        self.shell_text.setTextCursor(cursor)
        self.shell_text.ensureCursorVisible()

    # -------------------------------------------------------------
    # Application & Tool Log Methods (Backward Compatible)
    # -------------------------------------------------------------
    @Slot(str, str)
    def append_output(self, text: str, stream: str = "stdout"):
        """Append streamed output to the tool log tab."""
        cursor = self.log_text.textCursor()
        cursor.movePosition(QTextCursor.End)

        fmt = QTextCharFormat()
        if stream == "stderr":
            fmt.setForeground(QColor("#f87171"))
        elif stream == "system":
            fmt.setForeground(QColor("#38bdf8"))
            fmt.setFontWeight(600)
        elif stream == "success":
            fmt.setForeground(QColor("#4ade80"))
        else:
            fmt.setForeground(QColor("#e2e8f0"))

        cursor.insertText(text, fmt)
        self.log_text.setTextCursor(cursor)
        self.log_text.ensureCursorVisible()

    def append_system_msg(self, message: str):
        self.append_output(f"\n[*] {message}\n", stream="system")

    def append_error_msg(self, message: str):
        self.append_output(f"\n[-] ERROR: {message}\n", stream="stderr")

    def append_success_msg(self, message: str):
        self.append_output(f"\n[+] {message}\n", stream="success")

    def clear(self):
        """Clears both shell and log outputs."""
        self.clear_shell()
        self.clear_logs()

    def clear_shell(self):
        self.shell_text.clear()

    def clear_logs(self):
        self.log_text.clear()

    def copy_shell(self):
        QApplication.clipboard().setText(self.shell_text.toPlainText())

    def set_active_project(self, project: Optional[Project], db: Optional[Database] = None):
        """Updates active project and database context for evidence saving and AI scope validation."""
        self.active_project = project
        self.db = db
        if project:
            self.shell_recorder.project_id = project.id
            if not self.shell_recorder.is_recording:
                self.lbl_shell_rec_status.setText("⚪ Rec: Off")
        else:
            self.shell_recorder.project_id = None
            self.lbl_shell_rec_status.setText("⚪ Rec: Disabled (No Project)")

        if hasattr(self, "ai_assistant"):
            self.ai_assistant.set_context(project, db)
        if hasattr(self, "session_vault"):
            self.session_vault.set_context(project, db)
        if self.vscode_term and hasattr(self.vscode_term, "set_context"):
            self.vscode_term.set_context(project, db)

    @Slot()
    def toggle_shell_recording(self):
        """Toggles Command Shell session recording on or off."""
        if not self.active_project:
            QMessageBox.warning(
                self,
                "No Active Project",
                "Please select an assessment project in Projects & Scope before recording terminal sessions.",
            )
            return

        if not self.shell_recorder.is_recording:
            self.shell_recorder.start(project_id=self.active_project.id, cwd=self.cwd)
            self.btn_toggle_shell_rec.setText("⏹️ Stop Recording")
            self.lbl_shell_rec_status.setText("🔴 Rec: Active (0 events)")
            self.lbl_shell_rec_status.setStyleSheet("color: #ef4444; font-size: 11px; font-weight: bold;")
        else:
            self.shell_recorder.stop(exit_status=0)
            self.btn_toggle_shell_rec.setText("🔴 Start Recording")
            self.lbl_shell_rec_status.setText(f"⚪ Rec: Stopped ({len(self.shell_recorder.events)} events)")
            self.lbl_shell_rec_status.setStyleSheet("color: #94a3b8; font-size: 11px;")

    def get_latest_output(self) -> str:
        """Returns the most recent output from shell or logs for AI analysis."""
        shell_out = self.shell_text.toPlainText().strip()
        if shell_out:
            return shell_out
        return self.log_text.toPlainText().strip()

    @Slot(str)
    def _on_ai_command_ready(self, cmd: str):
        """Inserts AI-generated or suggested command into the command line input."""
        self.cmd_input.setText(cmd)
        for i in range(self.tabs.count()):
            if "Command Shell" in self.tabs.tabText(i):
                self.tabs.setCurrentIndex(i)
                break
        self.cmd_input.setFocus()

    def save_session_as_evidence(self, source: str = "shell") -> Optional[Evidence]:
        """Saves current terminal session or logs as cryptographic project evidence for reports."""
        if not self.active_project or not self.db:
            QMessageBox.warning(
                self,
                "No Active Project",
                "Please select an assessment project first in Projects & Scope to link this session as evidence.",
            )
            return None

        content = self.shell_text.toPlainText().strip() if source == "shell" else self.log_text.toPlainText().strip()
        if not content:
            QMessageBox.warning(
                self,
                "Empty Output",
                "No output recorded to save. Run commands or tools first.",
            )
            return None

        # If saving from shell and recorder has events, use the recorder
        if source == "shell" and self.shell_recorder.events:
            rec = self.shell_recorder
        else:
            rec = TerminalSessionRecorder(project_id=self.active_project.id)
            rec.start(project_id=self.active_project.id, cwd=self.cwd)
            rec.record_output(content)
            rec.stop(exit_status=0)

        res = rec.save_session_as_evidence(db=self.db, project_id=self.active_project.id)

        # Refresh vault view if available
        if hasattr(self, "session_vault"):
            self.session_vault.load_sessions()

        self.append_system_msg(
            f"💾 Terminal {source} session saved as Evidence #{res.evidence.id} (SHA-256: {res.sha256_hash[:12]}...). Included in report."
        )

        dup_msg = "\n(Session record verified in cryptographic vault)" if res.is_duplicate else ""
        QMessageBox.information(
            self,
            "Evidence Saved",
            f"Terminal session successfully vaulted as Project Evidence #{res.evidence.id}!\n\n"
            f"File: {Path(res.plain_path).name}\n"
            f"SHA-256 Hash:\n{res.sha256_hash}\n\n"
            f"This session record is permanently vaulted and will appear in generated reports.{dup_msg}",
        )
        return res.evidence

    def copy_all(self):
        QApplication.clipboard().setText(self.log_text.toPlainText())

    def closeEvent(self, event):
        if self.vscode_term:
            self.vscode_term.close_pty()
        super().closeEvent(event)
