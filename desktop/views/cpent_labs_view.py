"""Interactive CPENT Learning Platform & Methodology View."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QProgressBar,
    QSplitter,
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


class CPENTLabsView(QWidget):
    """Interactive learning and assessment environment based on CPENT methodologies."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.tests_cache: list[CPENTTestItem] = []
        self._init_ui()
        self.load_tests("All")

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

        filter_label = QLabel("Methodology Track:")
        filter_label.setStyleSheet("color: #94a3b8; font-weight: 500;")
        top_bar.addWidget(filter_label)

        self.methodology_combo = QComboBox()
        self.methodology_combo.addItem("All Methodologies", "All")
        self.methodology_combo.addItem("Network Penetration Testing", "Network Pentest")
        self.methodology_combo.addItem("Open-Source Intelligence (OSINT)", "OSINT")
        self.methodology_combo.addItem("Social Engineering", "Social Engineering")
        self.methodology_combo.currentIndexChanged.connect(self._on_filter_changed)
        top_bar.addWidget(self.methodology_combo)

        layout.addLayout(top_bar)

        # Progress Overview
        prog_group = QGroupBox("Methodology Completion & Practical Lab Readiness")
        prog_layout = QVBoxLayout(prog_group)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(35)
        prog_layout.addWidget(self.progress_bar)

        prog_info = QLabel("Practical Modules Aligned to Official Assessment Methodology • 100% Isolated Labs")
        prog_info.setStyleSheet("color: #38bdf8;")
        prog_layout.addWidget(prog_info)
        layout.addWidget(prog_group)

        # Splitter between test list and detail/guidance panel
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Table of Tests
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Test ID", "Methodology / Phase", "Test Title", "Suggested Tools"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        splitter.addWidget(self.table)

        # Details Panel
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        details_layout.setContentsMargins(0, 8, 0, 0)

        details_title = QLabel("Practical Lab Objective & Technical Guidance")
        details_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #38bdf8;")
        details_layout.addWidget(details_title)

        self.details_edit = QTextEdit()
        self.details_edit.setReadOnly(True)
        details_layout.addWidget(self.details_edit)

        splitter.addWidget(details_widget)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        layout.addWidget(splitter)

    def load_tests(self, filter_name: str):
        if filter_name == "All":
            self.tests_cache = get_all_cpent_tests()
        else:
            self.tests_cache = get_tests_by_methodology(filter_name)

        self.table.setRowCount(len(self.tests_cache))
        for row, test in enumerate(self.tests_cache):
            self.table.setItem(row, 0, QTableWidgetItem(test.test_id))
            self.table.setItem(row, 1, QTableWidgetItem(f"{test.methodology} ({test.category})"))
            self.table.setItem(row, 2, QTableWidgetItem(test.title))
            self.table.setItem(row, 3, QTableWidgetItem(", ".join(test.suggested_tools)))

        if self.tests_cache:
            self.table.selectRow(0)

    def _on_filter_changed(self):
        methodology = self.methodology_combo.currentData()
        self.load_tests(methodology)

    def _on_selection_changed(self):
        selected = self.table.selectedItems()
        if not selected:
            self.details_edit.clear()
            return

        row = selected[0].row()
        if row < len(self.tests_cache):
            test = self.tests_cache[row]

            cmd_section = ""
            if test.command_template:
                cmd_section = f"#### Command Template:\n```bash\n{test.command_template}\n```\n\n"

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
            self.details_edit.setMarkdown(markdown_content)
