"""Terminal display widget with real-time stream formatting."""

from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import QColor, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class TerminalWidget(QWidget):
    """Real-time console output streamer with status headers and actions."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        # Header toolbar
        header = QHBoxLayout()
        header.setContentsMargins(4, 2, 4, 2)

        self.title_label = QLabel("Integrated Execution Terminal")
        self.title_label.setStyleSheet("font-weight: bold; color: #38bdf8;")
        header.addWidget(self.title_label)
        header.addStretch()

        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setObjectName("clearBtn")
        self.clear_btn.clicked.connect(self.clear)
        header.addWidget(self.clear_btn)

        self.copy_btn = QPushButton("Copy All")
        self.copy_btn.setObjectName("copyBtn")
        self.copy_btn.clicked.connect(self.copy_all)
        header.addWidget(self.copy_btn)

        layout.addLayout(header)

        # Text display area
        self.text_edit = QPlainTextEdit()
        self.text_edit.setObjectName("terminalView")
        self.text_edit.setReadOnly(True)
        self.text_edit.setMaximumBlockCount(5000)  # Keep last 5000 lines
        layout.addWidget(self.text_edit)

    @Slot(str, str)
    def append_output(self, text: str, stream: str = "stdout"):
        """Append streamed output with stream-specific formatting."""
        cursor = self.text_edit.textCursor()
        cursor.movePosition(QTextCursor.End)

        fmt = QTextCharFormat()
        if stream == "stderr":
            fmt.setForeground(QColor("#f87171"))  # Red/Amber
        elif stream == "system":
            fmt.setForeground(QColor("#38bdf8"))  # Light Cyan
            fmt.setFontWeight(600)
        elif stream == "success":
            fmt.setForeground(QColor("#4ade80"))  # Green
        else:
            fmt.setForeground(QColor("#e2e8f0"))  # White/Light Gray

        cursor.insertText(text, fmt)
        self.text_edit.setTextCursor(cursor)
        self.text_edit.ensureCursorVisible()

    def append_system_msg(self, message: str):
        self.append_output(f"\n[*] {message}\n", stream="system")

    def append_error_msg(self, message: str):
        self.append_output(f"\n[-] ERROR: {message}\n", stream="stderr")

    def append_success_msg(self, message: str):
        self.append_output(f"\n[+] {message}\n", stream="success")

    def clear(self):
        self.text_edit.clear()

    def copy_all(self):
        QApplication.clipboard().setText(self.text_edit.toPlainText())
