"""Tests for the interactive command shell in TerminalWidget."""

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import time
import pytest
from PySide6.QtCore import Qt
from PySide6.QtGui import QKeyEvent

from desktop.widgets.terminal_view import TerminalWidget


def test_command_history_line_edit(qtbot):
    terminal = TerminalWidget()
    qtbot.addWidget(terminal)
    terminal.show()

    input_widget = terminal.cmd_input
    input_widget.add_to_history("nmap 127.0.0.1")
    input_widget.add_to_history("sqlmap -u http://127.0.0.1")
    input_widget.add_to_history("gobuster dir -u http://127.0.0.1")

    assert len(input_widget.history) == 3

    # Up arrow retrieves last command
    key_up = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Up, Qt.KeyboardModifier.NoModifier)
    input_widget.keyPressEvent(key_up)
    assert input_widget.text() == "gobuster dir -u http://127.0.0.1"

    # Up arrow again retrieves previous command
    input_widget.keyPressEvent(key_up)
    assert input_widget.text() == "sqlmap -u http://127.0.0.1"

    # Down arrow navigates back down
    key_down = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Down, Qt.KeyboardModifier.NoModifier)
    input_widget.keyPressEvent(key_down)
    assert input_widget.text() == "gobuster dir -u http://127.0.0.1"


def test_terminal_builtin_cd(qtbot, tmp_path):
    terminal = TerminalWidget()
    qtbot.addWidget(terminal)
    terminal.show()

    original_cwd = terminal.cwd
    target_dir = str(tmp_path)

    terminal.cmd_input.setText(f"cd {target_dir}")
    terminal.run_command()

    assert terminal.cwd == target_dir
    assert target_dir in terminal.shell_text.toPlainText()

    # Invalid directory
    terminal.cmd_input.setText("cd /non_existent_folder_xyz_123")
    terminal.run_command()
    assert "No such directory" in terminal.shell_text.toPlainText()


def test_terminal_shell_executes_echo_command(qtbot):
    terminal = TerminalWidget()
    qtbot.addWidget(terminal)
    terminal.show()

    terminal.cmd_input.setText("echo CybersecuritySuiteShellActive")
    terminal.run_command()

    # Wait for execution thread to finish
    qtbot.waitUntil(lambda: "Process finished with exit code 0" in terminal.shell_text.toPlainText(), timeout=4000)
    assert terminal.btn_run.isEnabled()
    assert not terminal.btn_stop.isEnabled()


def test_terminal_shell_handles_failed_command(qtbot):
    terminal = TerminalWidget()
    qtbot.addWidget(terminal)
    terminal.show()

    # Run non-existent command
    terminal.cmd_input.setText("nonexistentcommand987xyz")
    terminal.run_command()

    qtbot.waitUntil(lambda: "Execution error" in terminal.shell_text.toPlainText() or "exited with code" in terminal.shell_text.toPlainText(), timeout=4000)
    assert terminal.btn_run.isEnabled()
