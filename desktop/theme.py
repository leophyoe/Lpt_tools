"""Workstation dark theme styling for CyberSecuritySuite."""

DARK_THEME_QSS = """
QMainWindow, QDialog {
    background-color: #12151c;
    color: #e2e8f0;
}

QWidget {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    font-size: 13px;
    color: #e2e8f0;
}

/* Sidebar navigation */
#sidebar {
    background-color: #0b0d13;
    border-right: 1px solid #1e2433;
    min-width: 210px;
    max-width: 210px;
}

#sidebar QLabel#appTitle {
    color: #38bdf8;
    font-size: 15px;
    font-weight: bold;
    padding: 16px 12px 4px 12px;
}

#sidebar QLabel#appSubtitle {
    color: #94a3b8;
    font-size: 11px;
    padding: 0px 12px 14px 12px;
}

QPushButton.nav-btn {
    background-color: transparent;
    color: #94a3b8;
    border: none;
    border-radius: 6px;
    padding: 10px 14px;
    text-align: left;
    font-weight: 500;
}

QPushButton.nav-btn:hover {
    background-color: #1e293b;
    color: #f8fafc;
}

QPushButton.nav-btn:checked {
    background-color: #0284c7;
    color: #ffffff;
    font-weight: 600;
}

/* Primary and action buttons */
QPushButton.action-primary {
    background-color: #0284c7;
    color: #ffffff;
    border: 1px solid #0369a1;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 600;
}

QPushButton.action-primary:hover {
    background-color: #0369a1;
}

QPushButton.action-secondary {
    background-color: #1e293b;
    color: #f1f5f9;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 8px 16px;
}

QPushButton.action-secondary:hover {
    background-color: #334155;
}

/* Text Inputs, ComboBoxes, and Form Controls */
QLineEdit, QComboBox, QTextEdit, QPlainTextEdit {
    background-color: #1a202c;
    color: #f8fafc;
    border: 1px solid #2d3748;
    border-radius: 6px;
    padding: 6px 10px;
}

QLineEdit:focus, QComboBox:focus, QTextEdit:focus, QPlainTextEdit:focus {
    border: 1px solid #38bdf8;
}

QComboBox::drop-down {
    border: none;
}

/* Tables and Tree Views */
QTableWidget, QTableView {
    background-color: #141923;
    border: 1px solid #1e293b;
    gridline-color: #1e293b;
    color: #f1f5f9;
    selection-background-color: #0369a1;
    selection-color: #ffffff;
}

QHeaderView::section {
    background-color: #0f172a;
    color: #94a3b8;
    padding: 6px 8px;
    border: none;
    border-bottom: 1px solid #1e293b;
    font-weight: 600;
}

/* Terminal View */
#terminalView {
    background-color: #090c10;
    color: #38bdf8;
    font-family: "JetBrains Mono", "Fira Code", "Courier New", monospace;
    font-size: 12px;
    border: 1px solid #1e293b;
    border-radius: 6px;
}

/* Status Bar */
QStatusBar {
    background-color: #0b0d13;
    color: #94a3b8;
    border-top: 1px solid #1e2433;
}
"""
