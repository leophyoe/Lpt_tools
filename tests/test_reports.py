"""Unit and GUI tests for Phase 6 Reporting Service."""

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from reports.builder import AssessmentReportData, ReportBuilder
from storage.db import Database
from storage.models import (
    Evidence,
    ExecutionStatus,
    Finding,
    FindingSeverity,
    Project,
    TargetScope,
    TargetType,
    ToolExecution,
    ValidationStatus,
)


@pytest.fixture
def db():
    return Database(":memory:")


@pytest.fixture
def populated_project(db: Database) -> int:
    """Creates a realistic assessment project with scopes, executions, findings, and evidence."""
    project = db.create_project(
        Project(
            name="Alpha Corp Penetration Test",
            client_name="Alpha Corp Ltd",
            description="External network and web API penetration testing engagement.",
        )
    )
    p_id = project.id
    assert p_id is not None

    # 1. Scopes
    db.add_scope(
        TargetScope(
            project_id=p_id,
            target="192.168.1.0/24",
            target_type=TargetType.CIDR_RANGE,
            is_authorized=True,
            notes="Corporate subnet",
        )
    )
    db.add_scope(
        TargetScope(
            project_id=p_id,
            target="api.alphacorp.internal",
            target_type=TargetType.HOSTNAME,
            is_authorized=True,
            notes="Internal API gateway",
        )
    )

    # 2. Tool Executions
    exec1 = db.create_execution(
        ToolExecution(
            project_id=p_id,
            tool_name="nmap",
            command="nmap -sV -p 22,80,443 192.168.1.50",
            status=ExecutionStatus.COMPLETED,
            exit_code=0,
            duration_seconds=4.2,
        )
    )
    exec2 = db.create_execution(
        ToolExecution(
            project_id=p_id,
            tool_name="c0desec",
            command="c0desec-web-assessment https://api.alphacorp.internal",
            status=ExecutionStatus.COMPLETED,
            exit_code=0,
            duration_seconds=3.1,
        )
    )

    # 3. Findings
    f1 = db.create_finding(
        Finding(
            project_id=p_id,
            title="Insecure Cross-Origin Resource Sharing (CORS) Misconfiguration",
            severity=FindingSeverity.HIGH,
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
            affected_asset="api.alphacorp.internal",
            affected_port_service="443/https",
            description="The API reflects arbitrary origin headers with credentials allowed.",
            reproduction_steps="curl -H 'Origin: https://evil.corp' -I https://api.alphacorp.internal",
            remediation="Enforce an explicit whitelist of trusted origins.",
            validation_status=ValidationStatus.CONFIRMED,
            source_tool="c0desec",
            execution_id=exec2.id,
        )
    )

    f2 = db.create_finding(
        Finding(
            project_id=p_id,
            title="Remote Code Execution via Apache Log4j",
            severity=FindingSeverity.CRITICAL,
            cvss_score=10.0,
            affected_asset="192.168.1.50",
            affected_port_service="8080/http",
            description="JNDI lookup evaluation in log messages enables unauthenticated RCE.",
            remediation="Upgrade Log4j to version 2.17.1 or higher.",
            validation_status=ValidationStatus.CONFIRMED,
            source_tool="nmap",
            execution_id=exec1.id,
        )
    )

    f3 = db.create_finding(
        Finding(
            project_id=p_id,
            title="Missing Content-Security-Policy (CSP) Header",
            severity=FindingSeverity.MEDIUM,
            cvss_score=4.3,
            affected_asset="api.alphacorp.internal",
            affected_port_service="443/https",
            description="Absence of CSP reduces defense against XSS.",
            remediation="Implement a strict CSP header.",
            validation_status=ValidationStatus.UNVERIFIED,
            source_tool="c0desec",
            execution_id=exec2.id,
        )
    )

    # 4. Evidence
    db.add_evidence(
        Evidence(
            project_id=p_id,
            finding_id=f1.id,
            execution_id=exec2.id,
            file_path="storage/evidence/cors_capture.json",
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            description="Captured HTTP OPTIONS response headers",
            mime_type="application/json",
        )
    )

    return p_id


def test_report_builder_empty_project(db: Database, tmp_path: Path):
    project = db.create_project(Project(name="Empty Project Assessment"))
    builder = ReportBuilder(db)

    # JSON
    json_path = tmp_path / "empty.json"
    json_res = builder.generate_json(project.id, output_path=json_path)
    parsed = json.loads(json_res)
    assert parsed["project"]["name"] == "Empty Project Assessment"
    assert parsed["metrics"]["total_findings"] == 0
    assert json_path.exists()

    # Markdown
    md_path = tmp_path / "empty.md"
    md_res = builder.generate_markdown(project.id, output_path=md_path)
    assert "Empty Project Assessment" in md_res
    assert "*No security vulnerabilities identified*" in md_res
    assert md_path.exists()

    # HTML
    html_path = tmp_path / "empty.html"
    html_res = builder.generate_html(project.id, output_path=html_path)
    assert "<!DOCTYPE html>" in html_res
    assert "Empty Project Assessment" in html_res
    assert html_path.exists()


def test_report_builder_with_populated_project(db: Database, populated_project: int, tmp_path: Path):
    builder = ReportBuilder(db)
    p_id = populated_project

    # 1. Test ReportData aggregation
    data = builder.build_report_data(p_id)
    assert isinstance(data, AssessmentReportData)
    assert data.project.name == "Alpha Corp Penetration Test"
    assert data.metrics.total_findings == 3
    assert data.metrics.critical_count == 1
    assert data.metrics.high_count == 1
    assert data.metrics.medium_count == 1
    assert data.metrics.max_cvss == 10.0
    assert data.metrics.total_targets == 2
    assert data.metrics.total_evidence_files == 1

    # 2. Test JSON Generation
    json_str = builder.generate_json(p_id)
    report_json = json.loads(json_str)
    assert report_json["generator"] == "CyberSecuritySuite Assessment Engine"
    assert len(report_json["findings"]) == 3
    assert len(report_json["scopes"]) == 2
    assert len(report_json["evidence"]) == 1
    assert report_json["evidence"][0]["sha256_hash"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    # 3. Test Markdown Generation
    md_str = builder.generate_markdown(p_id)
    assert "# Security Assessment & Penetration Testing Report" in md_str
    assert "Alpha Corp Ltd" in md_str
    assert "Remote Code Execution via Apache Log4j" in md_str
    assert "EC-Council CPENT" in md_str
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in md_str

    # 4. Test HTML Generation
    html_str = builder.generate_html(p_id)
    assert "<!DOCTYPE html>" in html_str
    assert "Alpha Corp Penetration Test" in html_str
    assert "CONFIDENTIAL" in html_str.upper()
    assert "CRITICAL" in html_str
    assert "JNDI lookup evaluation" in html_str
    assert "@media print" in html_str


def test_report_builder_generate_all(db: Database, populated_project: int, tmp_path: Path):
    builder = ReportBuilder(db)
    out_dict = builder.generate_all(populated_project, output_dir=tmp_path / "reports_out")

    assert "html" in out_dict
    assert "markdown" in out_dict
    assert "json" in out_dict

    assert out_dict["html"].exists()
    assert out_dict["markdown"].exists()
    assert out_dict["json"].exists()

    assert out_dict["html"].suffix == ".html"
    assert out_dict["markdown"].suffix == ".md"
    assert out_dict["json"].suffix == ".json"


def test_report_builder_nonexistent_project_raises(db: Database):
    builder = ReportBuilder(db)
    with pytest.raises(ValueError, match="does not exist"):
        builder.build_report_data(99999)


def test_findings_view_report_export_gui(qtbot, db: Database, populated_project: int, monkeypatch, tmp_path: Path):
    from desktop.views.findings_view import FindingsView
    from PySide6.QtWidgets import QMessageBox

    view = FindingsView(db=db)
    qtbot.addWidget(view)
    view.show()

    # 1. Without active project: export warns user
    warn_calls = []
    monkeypatch.setattr(QMessageBox, "warning", lambda parent, title, msg: warn_calls.append((title, msg)))
    view._export_report("html")
    assert len(warn_calls) == 1
    assert "No Project Selected" in warn_calls[0][0]

    # 2. With loaded project: export generates file
    info_calls = []
    monkeypatch.setattr(QMessageBox, "information", lambda parent, title, msg: info_calls.append((title, msg)))

    view.load_findings(populated_project)
    assert view.active_project_id == populated_project
    assert view.table.rowCount() == 3

    # Click export HTML
    view._export_report("html")
    assert len(info_calls) == 1
    assert "Report Generated Successfully" in info_calls[0][0]
    assert "HTML report" in view.export_status.text()

    # Click export Markdown
    view._export_report("markdown")
    assert len(info_calls) == 2
    assert "MARKDOWN report" in view.export_status.text()

    # Click export JSON
    view._export_report("json")
    assert len(info_calls) == 3
    assert "JSON report" in view.export_status.text()
