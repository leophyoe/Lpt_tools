"""VS Code-like Interactive PTY Terminal Widget for CyberSecuritySuite.

Uses xterm.js inside QWebEngineView connected to a real Linux Pseudo-Terminal (PTY)
via local loopback WebSocket server. Provides full ANSI color support, tab completion,
interactive cursor navigation, and full-screen TUI support (nano, htop, msfconsole).
"""

from __future__ import annotations

import fcntl
import json
import os
import pty
import struct
import subprocess
import termios
import threading
from pathlib import Path
from typing import Optional

# Ensure Chromium WebEngine initializes cleanly without sandbox issues in Linux container/desktop
os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--no-sandbox --disable-gpu")

from PySide6.QtCore import QObject, QUrl, Signal, Slot
from PySide6.QtNetwork import QHostAddress
from PySide6.QtWebSockets import QWebSocket, QWebSocketServer
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class PTYSignals(QObject):
    data_received = Signal(str)
    process_exited = Signal(int)


class VSCodeTerminal(QWidget):
    """Real interactive pseudo-terminal running xterm.js over a Linux PTY."""

    def __init__(self, cwd: Optional[str] = None, parent=None):
        super().__init__(parent)
        self.cwd = cwd or os.getcwd()
        self.master_fd: Optional[int] = None
        self.process: Optional[subprocess.Popen] = None
        self._closed: bool = False
        self._reader_thread: Optional[threading.Thread] = None

        self.client_socket: Optional[QWebSocket] = None
        self.server: Optional[QWebSocketServer] = None
        self.signals = PTYSignals()
        self.signals.data_received.connect(self._on_pty_data)

        self._init_server()
        self._init_pty()
        self._init_ui()

    def _init_server(self):
        """Starts a local loopback WebSocket server for xterm.js bridge."""
        self.server = QWebSocketServer(
            "CyberSecuritySuiteTerminalBridge",
            QWebSocketServer.SslMode.NonSecureMode,
            self,
        )
        self.server.listen(QHostAddress.SpecialAddress.LocalHost, 0)
        self.server.newConnection.connect(self._on_client_connected)

    def _init_pty(self):
        """Spawns an interactive login shell inside a Linux pseudo-terminal."""
        self.master_fd, slave_fd = pty.openpty()

        env = dict(os.environ)
        env["TERM"] = "xterm-256color"
        env["COLORTERM"] = "truecolor"

        shell_bin = os.environ.get("SHELL", "/bin/bash")

        self.process = subprocess.Popen(
            [shell_bin],
            preexec_fn=os.setsid,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
            cwd=self.cwd,
            env=env,
        )
        os.close(slave_fd)

        def pty_reader():
            while not self._closed and self.master_fd is not None:
                try:
                    data = os.read(self.master_fd, 4096)
                    if not data:
                        break
                    text = data.decode("utf-8", errors="replace")
                    self.signals.data_received.emit(text)
                except OSError:
                    break

        self._reader_thread = threading.Thread(target=pty_reader, daemon=True)
        self._reader_thread.start()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header bar
        header = QHBoxLayout()
        header.setContentsMargins(6, 4, 6, 4)

        title = QLabel("🖥️ Linux Pseudo-Terminal (xterm.js + PTY)")
        title.setStyleSheet("font-weight: bold; color: #38bdf8; font-size: 11px;")
        header.addWidget(title)

        status = QLabel("● Live Bash Session")
        status.setStyleSheet("color: #4ade80; font-size: 11px; font-weight: 500;")
        header.addWidget(status)
        header.addStretch()

        self.btn_restart = QPushButton("Restart Shell")
        self.btn_restart.setFixedHeight(22)
        self.btn_restart.clicked.connect(self.restart_shell)
        header.addWidget(self.btn_restart)

        layout.addLayout(header)

        # WebEngine View
        from PySide6.QtWebEngineWidgets import QWebEngineView

        self.web_view = QWebEngineView()
        self.web_view.setStyleSheet("background-color: #0b0d13;")

        # HTML file path
        html_file = Path(__file__).parent.parent / "resources" / "terminal" / "terminal.html"
        port = self.server.serverPort()

        url = QUrl.fromLocalFile(str(html_file.resolve()))
        url.setQuery(f"port={port}")
        self.web_view.load(url)

        layout.addWidget(self.web_view)

    @Slot()
    def _on_client_connected(self):
        self.client_socket = self.server.nextPendingConnection()
        self.client_socket.textMessageReceived.connect(self._on_message_from_xterm)
        self.client_socket.disconnected.connect(self._on_client_disconnected)

    @Slot(str)
    def _on_message_from_xterm(self, msg: str):
        if not self.master_fd or self._closed:
            return

        try:
            payload = json.loads(msg)
            msg_type = payload.get("type")

            if msg_type == "input":
                data = payload.get("data", "")
                os.write(self.master_fd, data.encode("utf-8"))
            elif msg_type == "resize":
                cols = int(payload.get("cols", 80))
                rows = int(payload.get("rows", 24))
                # Set PTY window size using TIOCSWINSZ ioctl
                winsize = struct.pack("HHHH", rows, cols, 0, 0)
                fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, winsize)
        except Exception:
            pass

    @Slot()
    def _on_client_disconnected(self):
        self.client_socket = None

    @Slot(str)
    def _on_pty_data(self, text: str):
        """Sends data read from Linux PTY to the xterm.js client."""
        if self.client_socket and self.client_socket.isValid():
            self.client_socket.sendTextMessage(text)

    def stop_pty(self):
        """Stops the underlying PTY process and closes master file descriptor."""
        self._closed = True
        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.master_fd = None

        if self.process is not None:
            try:
                self.process.terminate()
            except OSError:
                pass
            self.process = None

    def restart_shell(self):
        """Terminates existing shell and spawns a fresh PTY session."""
        self.stop_pty()
        self._closed = False
        self._init_pty()
        if hasattr(self, "web_view") and self.web_view is not None:
            self.web_view.reload()

    def close_pty(self):
        self.stop_pty()
        if hasattr(self, "web_view") and self.web_view is not None:
            try:
                page = self.web_view.page()
                self.web_view.setPage(None)
                if page:
                    page.deleteLater()
                self.web_view.deleteLater()
            except Exception:
                pass
            self.web_view = None

    def closeEvent(self, event):
        self.close_pty()
        if self.server:
            self.server.close()
        super().closeEvent(event)
