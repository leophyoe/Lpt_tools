"""Integrated Execution Terminal & Application Console for CyberSecuritySuite.

Provides:
1. Interactive Command Shell with line input, command history, working directory
   tracking, cancellation, and real-time streaming output.
2. Application & Tool Log Console for background scanners and framework events.
"""

from __future__ import annotations

import os
import shlex
import threading
from pathlib import Path
from typing import List, Optional

from PySide6.QtCore import QObject, Qt, Signal, Slot
from PySide6.QtGui import QColor, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

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

        logs_layout.addLayout(logs_bar)

        self.log_text = QPlainTextEdit()
        self.log_text.setObjectName("terminalView")
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumBlockCount(5000)
        logs_layout.addWidget(self.log_text)

        # Backward compatibility reference for existing tests
        self.text_edit = self.log_text

        self.tabs.addTab(logs_widget, "📋 Tool & System Logs")

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
        self._append_shell_text(chunk, stream)

    @Slot(int, float)
    def _on_shell_finished(self, exit_code: int, duration: float):
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

    def copy_all(self):
        QApplication.clipboard().setText(self.log_text.toPlainText())

    def closeEvent(self, event):
        if self.vscode_term:
            self.vscode_term.close_pty()
        super().closeEvent(event)
