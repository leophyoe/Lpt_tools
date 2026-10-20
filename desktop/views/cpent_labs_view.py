"""CPENT Learning Platform & Practical Labs view."""

from PySide6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


class CPENTLabsView(QWidget):
    """Educational environment for EC-Council CPENT practical preparation."""

    DOMAINS = [
        ("Network Penetration Testing & Lateral Movement", "Multi-subnet discovery, port scanning, pivoting, and proxy chaining.", "Ready"),
        ("Active Directory & Enterprise Security", "Kerberos attacks, LLMNR/NBT-NS poisoning, BloodHound path analysis.", "Lab Config"),
        ("Web Application & API Pentesting", "SQL injection, SSRF, IDOR, JWT tampering, and business logic flaws.", "Ready"),
        ("Pivoting & Segmented Network Routing", "SSH tunneling, Chisel, Socat, and double-pivot routing techniques.", "Ready"),
        ("Linux & Windows Privilege Escalation", "SUID binaries, misconfigured capabilities, sudo rights, and Windows services.", "Ready"),
        ("Binary Analysis & Buffer Overflows", "32-bit & 64-bit stack-based buffer overflows in isolated testbeds.", "Planned"),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Header
        top_bar = QHBoxLayout()
        header = QLabel("CPENT Practical Learning & Lab Environment")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #f8fafc;")
        top_bar.addWidget(header)
        top_bar.addStretch()

        disclaimer = QLabel("Original, self-contained educational curriculum")
        disclaimer.setStyleSheet("color: #94a3b8; font-style: italic;")
        top_bar.addWidget(disclaimer)
        layout.addLayout(top_bar)

        # Progress Overview
        prog_group = QGroupBox("Overall Certification Track Progress")
        prog_layout = QVBoxLayout(prog_group)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(25)
        prog_layout.addWidget(self.progress_bar)

        prog_info = QLabel("2 of 6 Core Practical Domains in Progress • 100% Authorized Local Lab Scenarios")
        prog_info.setStyleSheet("color: #38bdf8;")
        prog_layout.addWidget(prog_info)
        layout.addWidget(prog_group)

        # Domains Table
        domains_label = QLabel("CPENT Curriculum & Practical Attack-Path Labs")
        domains_label.setStyleSheet("font-size: 14px; font-weight: bold; margin-top: 8px;")
        layout.addWidget(domains_label)

        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Domain Track", "Practical Objectives & Concepts", "Lab Environment Status"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.setRowCount(len(self.DOMAINS))

        for row, (track, desc, status) in enumerate(self.DOMAINS):
            self.table.setItem(row, 0, QTableWidgetItem(track))
            self.table.setItem(row, 1, QTableWidgetItem(desc))
            self.table.setItem(row, 2, QTableWidgetItem(status))

        layout.addWidget(self.table)

        # AI Tutor Guidance Panel
        tutor_group = QGroupBox("AI Cybersecurity Tutor: Lab Concept Brief")
        tutor_layout = QVBoxLayout(tutor_group)

        self.tutor_text = QTextEdit()
        self.tutor_text.setReadOnly(True)
        self.tutor_text.setMarkdown(
            "**Welcome to the CPENT Practical Study Track!**\n\n"
            "- **Tip for Pivoting:** In CPENT labs, you often compromise an edge host that has multiple network interfaces. "
            "Mastering `socat`, `chisel`, and SSH local/dynamic port forwarding is essential for routing traffic into internal DMZ subnets.\n"
            "- **Tip for Methodology:** Always maintain rigorous documentation during the assessment phase. "
            "Record exact commands, timestamps, and hash all proof files for your final report."
        )
        self.tutor_text.setMaximumHeight(110)
        tutor_layout.addWidget(self.tutor_text)

        layout.addWidget(tutor_group)
