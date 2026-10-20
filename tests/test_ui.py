"""GUI tests for PySide6 MainWindow using pytest-qt."""

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import pytest
from PySide6.QtCore import Qt
from desktop.main_window import MainWindow
from storage.db import Database
from storage.models import Project


@pytest.fixture
def test_db():
    return Database(":memory:")


def test_main_window_initialization(qtbot, test_db):
    window = MainWindow(db=test_db)
    qtbot.addWidget(window)
    window.show()

    # Check window title and widgets
    assert "CyberSecuritySuite" in window.windowTitle()
    assert window.view_stack.count() == 4
    assert window.view_stack.currentIndex() == 0  # Projects view default

    # Verify status bar
    assert "Nmap: Ready" in window.status_nmap_label.text()
    assert "Project: None" in window.status_project_label.text()


def test_main_window_navigation(qtbot, test_db):
    window = MainWindow(db=test_db)
    qtbot.addWidget(window)
    window.show()

    # Click Network Discovery button
    qtbot.mouseClick(window.btn_network, Qt.MouseButton.LeftButton)
    assert window.view_stack.currentIndex() == 1

    # Click Findings button
    qtbot.mouseClick(window.btn_findings, Qt.MouseButton.LeftButton)
    assert window.view_stack.currentIndex() == 2

    # Click CPENT Labs button
    qtbot.mouseClick(window.btn_cpent, Qt.MouseButton.LeftButton)
    assert window.view_stack.currentIndex() == 3

    # Click back to Projects
    qtbot.mouseClick(window.btn_projects, Qt.MouseButton.LeftButton)
    assert window.view_stack.currentIndex() == 0


def test_project_selection_updates_views_and_terminal(qtbot, test_db):
    # Create a project directly in test DB
    project = test_db.create_project(Project(name="Test Assessment Alpha", client_name="TestCorp"))
    assert project.id is not None

    window = MainWindow(db=test_db)
    qtbot.addWidget(window)
    window.show()

    # Reload and select the project
    window.projects_view.load_projects()
    window.projects_view.select_project_by_id(project.id)

    # Check status bar update
    assert "Test Assessment Alpha" in window.status_project_label.text()
    assert window.network_view.active_project is not None
    assert window.network_view.active_project.name == "Test Assessment Alpha"

    # Verify message in terminal
    terminal_text = window.terminal_widget.text_edit.toPlainText()
    assert "Active project switched to: 'Test Assessment Alpha'" in terminal_text


def test_terminal_widget_operations(qtbot, test_db):
    window = MainWindow(db=test_db)
    qtbot.addWidget(window)
    window.show()

    terminal = window.terminal_widget
    terminal.append_output("Standard output line\n", "stdout")
    terminal.append_output("Error alert line\n", "stderr")
    terminal.append_system_msg("System ready")

    content = terminal.text_edit.toPlainText()
    assert "Standard output line" in content
    assert "Error alert line" in content
    assert "System ready" in content

    # Test clear
    terminal.clear()
    assert terminal.text_edit.toPlainText() == ""
