"""Projects and Target Scope management view."""

from PySide6.QtCore import Signal, Qt
from PySide6.QtWidgets import (
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from storage.db import Database
from storage.models import Project, TargetScope, TargetType


class NewProjectDialog(QDialog):
    """Dialog for creating a new assessment project."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Create New Assessment Project")
        self.setMinimumWidth(400)
        self._init_ui()

    def _init_ui(self):
        layout = QFormLayout(self)

        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("e.g. CPENT Enterprise Lab Assessment")
        layout.addRow("Project Name *:", self.name_input)

        self.client_input = QLineEdit()
        self.client_input.setPlaceholderText("e.g. Acme Corp / Internal Lab")
        layout.addRow("Client / Target Lab:", self.client_input)

        self.desc_input = QTextEdit()
        self.desc_input.setPlaceholderText("Assessment scope details, rules of engagement, objectives...")
        self.desc_input.setMaximumHeight(80)
        layout.addRow("Description:", self.desc_input)

        buttons = QHBoxLayout()
        buttons.addStretch()

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setProperty("class", "action-secondary")
        self.cancel_btn.clicked.connect(self.reject)
        buttons.addWidget(self.cancel_btn)

        self.save_btn = QPushButton("Create Project")
        self.save_btn.setProperty("class", "action-primary")
        self.save_btn.clicked.connect(self._validate_and_accept)
        buttons.addWidget(self.save_btn)

        layout.addRow(buttons)

    def _validate_and_accept(self):
        if not self.name_input.text().strip():
            QMessageBox.warning(self, "Validation Error", "Project name is required.")
            return
        self.accept()

    def get_data(self) -> dict:
        return {
            "name": self.name_input.text().strip(),
            "client_name": self.client_input.text().strip(),
            "description": self.desc_input.toPlainText().strip(),
        }


class ProjectsView(QWidget):
    """Main view for project selection and scope configuration."""

    project_selected = Signal(Project)

    def __init__(self, db: Database, parent=None):
        super().__init__(parent)
        self.db = db
        self.active_project: Project | None = None
        self._init_ui()
        self.load_projects()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Header
        top_bar = QHBoxLayout()
        header = QLabel("Assessment Projects & Target Scopes")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #f8fafc;")
        top_bar.addWidget(header)
        top_bar.addStretch()

        self.new_proj_btn = QPushButton("+ New Project")
        self.new_proj_btn.setProperty("class", "action-primary")
        self.new_proj_btn.clicked.connect(self._on_new_project)
        top_bar.addWidget(self.new_proj_btn)
        layout.addLayout(top_bar)

        # Projects Table
        self.projects_table = QTableWidget()
        self.projects_table.setColumnCount(4)
        self.projects_table.setHorizontalHeaderLabels(["ID", "Project Name", "Client / Lab", "Status"])
        self.projects_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.projects_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.projects_table.itemSelectionChanged.connect(self._on_project_selection_changed)
        layout.addWidget(self.projects_table)

        # Target Scope Section
        scope_header = QLabel("Authorized Target Scopes (IPs, CIDRs, Hostnames)")
        scope_header.setStyleSheet("font-size: 14px; font-weight: bold; margin-top: 8px;")
        layout.addWidget(scope_header)

        # Scope input bar
        scope_bar = QHBoxLayout()
        self.scope_input = QLineEdit()
        self.scope_input.setPlaceholderText("Enter IP, CIDR subnet, or hostname (e.g. 192.168.1.0/24, 127.0.0.1, lab.internal)")
        scope_bar.addWidget(self.scope_input)

        self.add_scope_btn = QPushButton("Add to Scope")
        self.add_scope_btn.setProperty("class", "action-secondary")
        self.add_scope_btn.clicked.connect(self._on_add_scope)
        scope_bar.addWidget(self.add_scope_btn)
        layout.addLayout(scope_bar)

        # Scopes Table
        self.scopes_table = QTableWidget()
        self.scopes_table.setColumnCount(4)
        self.scopes_table.setHorizontalHeaderLabels(["ID", "Target", "Type", "Authorized"])
        self.scopes_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        layout.addWidget(self.scopes_table)

    def load_projects(self):
        projects = self.db.list_projects()
        self.projects_table.setRowCount(len(projects))
        for row, p in enumerate(projects):
            self.projects_table.setItem(row, 0, QTableWidgetItem(str(p.id)))
            self.projects_table.setItem(row, 1, QTableWidgetItem(p.name))
            self.projects_table.setItem(row, 2, QTableWidgetItem(p.client_name))
            self.projects_table.setItem(row, 3, QTableWidgetItem(p.status.value))

        if projects and self.active_project is None:
            self.projects_table.selectRow(0)

    def _on_new_project(self):
        dialog = NewProjectDialog(self)
        if dialog.exec() == QDialog.Accepted:
            data = dialog.get_data()
            project = Project(
                name=data["name"],
                client_name=data["client_name"],
                description=data["description"],
            )
            created = self.db.create_project(project)
            self.load_projects()
            self.select_project_by_id(created.id)

    def select_project_by_id(self, project_id: int):
        for row in range(self.projects_table.rowCount()):
            if int(self.projects_table.item(row, 0).text()) == project_id:
                self.projects_table.selectRow(row)
                self._on_project_selection_changed()
                break

    def _on_project_selection_changed(self):
        selected_rows = self.projects_table.selectedItems()
        if not selected_rows:
            return
        row = selected_rows[0].row()
        project_id = int(self.projects_table.item(row, 0).text())
        project = self.db.get_project(project_id)
        if project:
            self.active_project = project
            self.project_selected.emit(project)
            self.load_scopes(project.id)

    def load_scopes(self, project_id: int):
        scopes = self.db.list_scopes(project_id)
        self.scopes_table.setRowCount(len(scopes))
        for row, s in enumerate(scopes):
            self.scopes_table.setItem(row, 0, QTableWidgetItem(str(s.id)))
            self.scopes_table.setItem(row, 1, QTableWidgetItem(s.target))
            self.scopes_table.setItem(row, 2, QTableWidgetItem(s.target_type.value))
            status_item = QTableWidgetItem("YES" if s.is_authorized else "NO")
            status_item.setForeground(Qt.green if s.is_authorized else Qt.red)
            self.scopes_table.setItem(row, 3, status_item)

    def _on_add_scope(self):
        if not self.active_project:
            QMessageBox.warning(self, "No Project", "Please select or create an assessment project first.")
            return

        target_text = self.scope_input.text().strip()
        if not target_text:
            return

        target_type = TargetType.CIDR_RANGE if "/" in target_text else TargetType.IP_ADDRESS
        scope = TargetScope(
            project_id=self.active_project.id,
            target=target_text,
            target_type=target_type,
            is_authorized=True,
        )
        self.db.add_scope(scope)
        self.scope_input.clear()
        self.load_scopes(self.active_project.id)
