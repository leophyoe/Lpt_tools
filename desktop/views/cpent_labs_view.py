"""Interactive CPENT Learning Platform, 30-Day Study Roadmap & Command Cheat Sheet."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QProgressBar,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from labs.cpent.curriculum import (
    CPENTTestItem,
    get_all_cpent_tests,
    get_tests_by_methodology,
)
from labs.cpent.study_plan import CPENT_30_DAY_PLAN, StudyDay


class CPENTLabsView(QWidget):
    """Complete CPENT educational workspace integrating 30-day roadmap, methodologies, and cheat sheet."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.tests_cache: list[CPENTTestItem] = []
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Header
        top_bar = QHBoxLayout()
        header = QLabel("CPENT Practical Assessment & Learning Platform")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #f8fafc;")
        top_bar.addWidget(header)
        top_bar.addStretch()

        disclaimer = QLabel("Original, Self-Contained Educational Curriculum")
        disclaimer.setStyleSheet("color: #94a3b8; font-style: italic;")
        top_bar.addWidget(disclaimer)
        layout.addLayout(top_bar)

        # Tab Widget
        self.tabs = QTabWidget()

        # Tab 1: 30-Day Study Roadmap
        self.tab_roadmap = self._create_roadmap_tab()
        self.tabs.addTab(self.tab_roadmap, "🗓️ 30-Day Study Roadmap")

        # Tab 2: Methodologies & Test Items
        self.tab_methodologies = self._create_methodology_tab()
        self.tabs.addTab(self.tab_methodologies, "🛡️ Assessment Methodologies")

        # Tab 3: Practical Command & One-Liner Cheat Sheet
        self.tab_cheatsheet = self._create_cheatsheet_tab()
        self.tabs.addTab(self.tab_cheatsheet, "⚡ Command Cheat Sheet")

        layout.addWidget(self.tabs)

    # ----------------------------------------------------------------------
    # Tab 1: 30-Day Study Plan
    # ----------------------------------------------------------------------
    def _create_roadmap_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        prog_bar = QHBoxLayout()
        prog_label = QLabel("Study Track Progress (Day 1 - 30):")
        prog_label.setStyleSheet("font-weight: 500; color: #38bdf8;")
        prog_bar.addWidget(prog_label)
        self.plan_progress = QProgressBar()
        self.plan_progress.setValue(20)
        prog_bar.addWidget(self.plan_progress)
        layout.addLayout(prog_bar)

        splitter = QSplitter(Qt.Orientation.Vertical)

        # Table
        self.plan_table = QTableWidget()
        self.plan_table.setColumnCount(4)
        self.plan_table.setHorizontalHeaderLabels(["Day", "Week", "Focus Domain", "Study Topic Title"])
        self.plan_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.plan_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.plan_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.plan_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.plan_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.plan_table.setRowCount(len(CPENT_30_DAY_PLAN))

        for row, day in enumerate(CPENT_30_DAY_PLAN):
            self.plan_table.setItem(row, 0, QTableWidgetItem(f"Day {day.day}"))
            self.plan_table.setItem(row, 1, QTableWidgetItem(f"Week {day.week}"))
            self.plan_table.setItem(row, 2, QTableWidgetItem(day.focus_area))
            self.plan_table.setItem(row, 3, QTableWidgetItem(day.title))

        self.plan_table.itemSelectionChanged.connect(self._on_plan_selection_changed)
        splitter.addWidget(self.plan_table)

        # Detail Panel
        self.plan_detail_edit = QTextEdit()
        self.plan_detail_edit.setReadOnly(True)
        splitter.addWidget(self.plan_detail_edit)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        layout.addWidget(splitter)
        if CPENT_30_DAY_PLAN:
            self.plan_table.selectRow(0)

        return widget

    def _on_plan_selection_changed(self):
        selected = self.plan_table.selectedItems()
        if not selected:
            return
        row = selected[0].row()
        day = CPENT_30_DAY_PLAN[row]

        topics_text = "\n".join([f"- {t}" for t in day.topics])
        tasks_text = "\n".join([f"- [ ] {task}" for task in day.hands_on_tasks])
        tools_text = ", ".join(day.recommended_tools)

        text = (
            f"### [Day {day.day}] {day.title}\n\n"
            f"**Week:** {day.week} | **Focus Domain:** `{day.focus_area}`\n\n"
            f"**Recommended Tools:** `{tools_text}`\n\n"
            f"#### 📚 Theory & Core Topics:\n{topics_text}\n\n"
            f"#### 💻 Practical Hands-On Lab Tasks:\n{tasks_text}\n"
        )
        self.plan_detail_edit.setMarkdown(text)

    # ----------------------------------------------------------------------
    # Tab 2: Methodologies Explorer
    # ----------------------------------------------------------------------
    def _create_methodology_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        filter_bar = QHBoxLayout()
        filter_label = QLabel("Filter Track:")
        filter_bar.addWidget(filter_label)

        self.methodology_combo = QComboBox()
        self.methodology_combo.addItem("All Methodologies", "All")
        self.methodology_combo.addItem("Network Penetration Testing", "Network Pentest")
        self.methodology_combo.addItem("Open-Source Intelligence (OSINT)", "OSINT")
        self.methodology_combo.addItem("Social Engineering", "Social Engineering")
        self.methodology_combo.currentIndexChanged.connect(self._on_methodology_filter_changed)
        filter_bar.addWidget(self.methodology_combo)
        filter_bar.addStretch()
        layout.addLayout(filter_bar)

        splitter = QSplitter(Qt.Orientation.Vertical)

        self.method_table = QTableWidget()
        self.method_table.setColumnCount(4)
        self.method_table.setHorizontalHeaderLabels(["Test ID", "Methodology / Phase", "Test Title", "Suggested Tools"])
        self.method_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.method_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.method_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.method_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.method_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.method_table.itemSelectionChanged.connect(self._on_method_selection_changed)
        splitter.addWidget(self.method_table)

        self.method_detail_edit = QTextEdit()
        self.method_detail_edit.setReadOnly(True)
        splitter.addWidget(self.method_detail_edit)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        layout.addWidget(splitter)
        self._load_method_tests("All")
        return widget

    def _load_method_tests(self, filter_name: str):
        if filter_name == "All":
            self.tests_cache = get_all_cpent_tests()
        else:
            self.tests_cache = get_tests_by_methodology(filter_name)

        self.method_table.setRowCount(len(self.tests_cache))
        for row, test in enumerate(self.tests_cache):
            self.method_table.setItem(row, 0, QTableWidgetItem(test.test_id))
            self.method_table.setItem(row, 1, QTableWidgetItem(f"{test.methodology} ({test.category})"))
            self.method_table.setItem(row, 2, QTableWidgetItem(test.title))
            self.method_table.setItem(row, 3, QTableWidgetItem(", ".join(test.suggested_tools)))

        if self.tests_cache:
            self.method_table.selectRow(0)

    def _on_methodology_filter_changed(self):
        methodology = self.methodology_combo.currentData()
        self._load_method_tests(methodology)

    def _on_method_selection_changed(self):
        selected = self.method_table.selectedItems()
        if not selected:
            return
        row = selected[0].row()
        test = self.tests_cache[row]

        cmd_section = f"#### Command Template:\n```bash\n{test.command_template}\n```\n\n" if test.command_template else ""
        points_section = ""
        if test.learning_points:
            bullet_points = "\n".join([f"- {p}" for p in test.learning_points])
            points_section = f"#### Key Concepts & Learning Points:\n{bullet_points}\n\n"

        markdown_content = (
            f"### [{test.test_id}] {test.title}\n\n"
            f"**Methodology:** {test.methodology} | **Phase / Category:** {test.category}\n\n"
            f"**Tools Required:** `{', '.join(test.suggested_tools)}`\n\n"
            f"#### Objective & Description:\n{test.description}\n\n"
            f"{cmd_section}"
            f"{points_section}"
        )
        self.method_detail_edit.setMarkdown(markdown_content)

    # ----------------------------------------------------------------------
    # Tab 3: Command & One-Liner Cheat Sheet
    # ----------------------------------------------------------------------
    def _create_cheatsheet_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 8, 8, 8)

        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setMarkdown(
            "# ⚡ CPENT Practical Command & One-Liner Cheat Sheet\n\n"
            "### 1. Network Discovery & Host Sweeps\n"
            "- **Quick Ping Sweep:** `sudo nmap -sn 192.168.1.0/24`\n"
            "- **Active Netdiscover:** `sudo netdiscover -i eth0 -r 192.168.1.0/24`\n"
            "- **TCP SYN Fast Scan:** `sudo nmap -sS -F -T4 192.168.1.50`\n"
            "- **Fragmentation Firewall Bypass:** `sudo nmap -sS -A -f 192.168.1.50`\n\n"
            "### 2. Service & OS Enumeration\n"
            "- **Banner Grabbing with Netcat:** `nc -nv 192.168.1.50 80`\n"
            "- **SMB Share Enumeration:** `netexec smb 192.168.1.50 --shares`\n"
            "- **SMB OS & Vulnerability Probe:** `nmap --script smb-os-discovery,smb-vuln* -p 445 192.168.1.50`\n"
            "- **NFS Share Discovery & Mount:** `showmount -e 192.168.1.50 && sudo mount -t nfs 192.168.1.50:/home /mnt -o nolock`\n"
            "- **SNMP Community Walk:** `snmpwalk -v2c -c public 192.168.1.50`\n\n"
            "### 3. DNS Interrogation & OSINT\n"
            "- **DNS Zone Transfer (AXFR):** `dig axfr @ns1.target.lab target.lab`\n"
            "- **Reverse IP Range Lookup:** `dnsrecon -r 192.168.1.1-192.168.1.254`\n"
            "- **Subdomain Enumeration:** `subfinder -d target.lab -silent`\n\n"
            "### 4. Pivoting & Tunneling\n"
            "- **Dynamic SOCKS Proxy via SSH:** `ssh -D 1080 -N -f user@192.168.1.10`\n"
            "- **Chisel SOCKS Server:** `./chisel server -p 8080 --reverse`\n"
            "- **Chisel Client Pivot:** `./chisel client 10.10.10.5:8080 R:socks`\n\n"
            "### 5. Post-Exploitation & State Restoration\n"
            "- **Disable Windows Defender:** `Set-MpPreference -DisableRealtimeMonitoring $true`\n"
            "- **Windows Hash Extraction:** `run post/windows/gather/hashdump` (in Meterpreter)\n"
            "- **Target Cleanup:** Remove temporary payloads, kill spawned listener tasks, and restore default firewall rules."
        )
        layout.addWidget(text_edit)
        return widget
