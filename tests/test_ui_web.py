"""Unit and UI tests for WebScanView."""

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import pytest
from PySide6.QtCore import Qt
from desktop.views.web_scan_view import WebScanView
from storage.db import Database
from storage.models import Project, TargetScope, TargetType


@pytest.fixture
def test_db():
    return Database(":memory:")


def test_web_scan_view_initial_state(qtbot, test_db):
    view = WebScanView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    assert "No project selected" in view.project_label.text()
    assert view.scan_btn.isEnabled()
    assert not view.cancel_btn.isEnabled()
    assert view.cb_headers.isChecked()
    assert view.cb_cors.isChecked()
    assert view.cb_secrets.isChecked()
    assert view.cb_endpoints.isChecked()
    assert view.endpoints_table.rowCount() == 0
    assert view.secrets_table.rowCount() == 0
    assert view.headers_table.rowCount() == 0


def test_web_scan_view_set_active_project(qtbot, test_db):
    project = test_db.create_project(Project(name="Web Target Engagement", client_name="Acme"))
    view = WebScanView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    view.set_active_project(project)
    assert "Web Target Engagement" in view.project_label.text()
    assert str(project.id) in view.project_label.text()

    view.set_active_project(None)
    assert "No project selected" in view.project_label.text()


def test_web_scan_view_validation_without_url(qtbot, test_db, monkeypatch):
    project = test_db.create_project(Project(name="Acme Web Project"))
    view = WebScanView(db=test_db)
    qtbot.addWidget(view)
    view.show()
    view.set_active_project(project)

    # Mock QMessageBox to prevent blocking
    warn_calls = []
    from PySide6.QtWidgets import QMessageBox
    monkeypatch.setattr(QMessageBox, "warning", lambda parent, title, msg: warn_calls.append((title, msg)))

    # Empty URL click
    view.url_input.setText("")
    qtbot.mouseClick(view.scan_btn, Qt.MouseButton.LeftButton)
    assert len(warn_calls) == 1
    assert "Input Error" in warn_calls[0][0]
