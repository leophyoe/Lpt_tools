"""Main application window for CyberSecuritySuite desktop platform."""

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QButtonGroup,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from core.registry import ToolRegistry
from desktop.theme import DARK_THEME_QSS
from desktop.views.cpent_labs_view import CPENTLabsView
from desktop.views.findings_view import FindingsView
from desktop.views.network_scan_view import NetworkScanView
from desktop.views.projects_view import ProjectsView
from desktop.widgets.terminal_view import TerminalWidget
from storage.db import Database
from storage.models import Project


class MainWindow(QMainWindow):
    """Core desktop window integrating sidebar, workspace views, and terminal."""

    def __init__(self, db: Database, registry: Optional[ToolRegistry] = None):
        super().__init__()
        self.db = db
        self.registry = registry or ToolRegistry()
        self.active_project: Optional[Project] = None

        self.setWindowTitle("CyberSecuritySuite — Security Testing & CPENT Platform")
        self.resize(1280, 850)
        self.setStyleSheet(DARK_THEME_QSS)

        self._init_ui()
        self._init_status_bar()

    def _init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # 1. Left Sidebar Navigation
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        side_layout = QVBoxLayout(sidebar)
        side_layout.setContentsMargins(8, 12, 8, 12)
        side_layout.setSpacing(6)

        title = QLabel("CyberSecuritySuite")
        title.setObjectName("appTitle")
        subtitle = QLabel("Security Testing & CPENT Platform")
        subtitle.setObjectName("appSubtitle")
        side_layout.addWidget(title)
        side_layout.addWidget(subtitle)

        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)

        self.btn_projects = self._create_nav_btn("📁  Projects & Scope", 0)
        self.btn_network = self._create_nav_btn("🌐  Network Discovery", 1)
        self.btn_findings = self._create_nav_btn("🛡️  Findings & Evidence", 2)
        self.btn_cpent = self._create_nav_btn("🎓  CPENT Learning Labs", 3)

        side_layout.addWidget(self.btn_projects)
        side_layout.addWidget(self.btn_network)
        side_layout.addWidget(self.btn_findings)
        side_layout.addWidget(self.btn_cpent)
        side_layout.addStretch()

        main_layout.addWidget(sidebar)

        # 2. Right Content Area (Splitter between Views and Terminal)
        content_splitter = QSplitter(Qt.Orientation.Vertical)

        # Top Views Stack
        self.view_stack = QStackedWidget()
        self.projects_view = ProjectsView(self.db)
        self.network_view = NetworkScanView(self.db)
        self.findings_view = FindingsView(self.db)
        self.cpent_view = CPENTLabsView()

        self.view_stack.addWidget(self.projects_view)
        self.view_stack.addWidget(self.network_view)
        self.view_stack.addWidget(self.findings_view)
        self.view_stack.addWidget(self.cpent_view)

        content_splitter.addWidget(self.view_stack)

        # Bottom Integrated Terminal Panel
        self.terminal_widget = TerminalWidget()
        content_splitter.addWidget(self.terminal_widget)

        # 70% Views, 30% Terminal
        content_splitter.setStretchFactor(0, 7)
        content_splitter.setStretchFactor(1, 3)

        main_layout.addWidget(content_splitter)

        # Connect inter-view signals
        self.projects_view.project_selected.connect(self._on_project_selected)
        self.btn_projects.setChecked(True)

    def _create_nav_btn(self, label: str, view_index: int) -> QPushButton:
        btn = QPushButton(label)
        btn.setProperty("class", "nav-btn")
        btn.setCheckable(True)
        self.nav_group.addButton(btn, view_index)
        btn.clicked.connect(lambda: self.view_stack.setCurrentIndex(view_index))
        return btn

    def _init_status_bar(self):
        status = QStatusBar()
        self.setStatusBar(status)

        self.status_project_label = QLabel("Project: None")
        self.status_nmap_label = QLabel(
            "Nmap: Ready" if self.registry.is_available("nmap") else "Nmap: Not Found"
        )
        self.status_nmap_label.setStyleSheet("color: #4ade80;" if self.registry.is_available("nmap") else "color: #f87171;")

        status.addWidget(self.status_project_label, 1)
        status.addPermanentWidget(self.status_nmap_label)

    def _on_project_selected(self, project: Project):
        self.active_project = project
        self.status_project_label.setText(f"Project: {project.name} (Client: {project.client_name or 'N/A'})")
        self.network_view.set_active_project(project)
        self.findings_view.load_findings(project.id)
        self.terminal_widget.append_system_msg(f"Active project switched to: '{project.name}'")
