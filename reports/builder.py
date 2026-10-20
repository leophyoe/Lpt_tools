"""Professional Assessment Reporting Service for CyberSecuritySuite.

Generates self-contained HTML, portable Markdown, and machine-readable JSON
reports incorporating CPENT penetration testing methodology, executive summaries,
severity distributions, technical findings, and cryptographic evidence hashes.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from storage.db import Database
from storage.models import (
    Evidence,
    Finding,
    FindingSeverity,
    Project,
    TargetScope,
    ToolExecution,
)


class ReportFormat(str, Enum):
    HTML = "html"
    MARKDOWN = "markdown"
    JSON = "json"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ReportSummaryMetrics:
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    max_cvss: float = 0.0
    confirmed_findings: int = 0
    total_targets: int = 0
    total_executions: int = 0
    total_evidence_files: int = 0


@dataclass
class AssessmentReportData:
    project: Project
    scopes: List[TargetScope]
    executions: List[ToolExecution]
    findings: List[Finding]
    evidence: List[Evidence]
    metrics: ReportSummaryMetrics
    generated_at: str = field(default_factory=_utc_now_iso)


class ReportBuilder:
    """Aggregates project assessment data and generates professional reports."""

    def __init__(self, db: Database):
        self.db = db

    def build_report_data(self, project_id: int) -> AssessmentReportData:
        """Pulls and aggregates all project security records from SQLite."""
        project = self.db.get_project(project_id)
        if not project:
            raise ValueError(f"Project with ID {project_id} does not exist.")

        scopes = self.db.list_scopes(project_id)
        executions = self.db.list_executions(project_id)
        findings = self.db.list_findings(project_id)
        evidence = self.db.list_evidence(project_id)

        # Compute summary metrics
        metrics = ReportSummaryMetrics(
            total_findings=len(findings),
            total_targets=len(scopes),
            total_executions=len(executions),
            total_evidence_files=len(evidence),
        )

        for f in findings:
            if f.severity == FindingSeverity.CRITICAL:
                metrics.critical_count += 1
            elif f.severity == FindingSeverity.HIGH:
                metrics.high_count += 1
            elif f.severity == FindingSeverity.MEDIUM:
                metrics.medium_count += 1
            elif f.severity == FindingSeverity.LOW:
                metrics.low_count += 1
            else:
                metrics.info_count += 1

            if f.cvss_score and f.cvss_score > metrics.max_cvss:
                metrics.max_cvss = f.cvss_score

            if f.validation_status.value == "confirmed":
                metrics.confirmed_findings += 1

        return AssessmentReportData(
            project=project,
            scopes=scopes,
            executions=executions,
            findings=findings,
            evidence=evidence,
            metrics=metrics,
        )

    # -------------------------------------------------------------
    # 1. JSON Report Generation
    # -------------------------------------------------------------
    def generate_json(self, project_id: int, output_path: Optional[Path] = None) -> str:
        """Generates a structured machine-readable JSON report."""
        data = self.build_report_data(project_id)

        report_dict = {
            "report_version": "1.0",
            "generator": "CyberSecuritySuite Assessment Engine",
            "generated_at": data.generated_at,
            "project": {
                "id": data.project.id,
                "name": data.project.name,
                "client_name": data.project.client_name,
                "description": data.project.description,
                "status": data.project.status.value,
                "created_at": data.project.created_at,
            },
            "metrics": asdict(data.metrics),
            "scopes": [
                {
                    "target": s.target,
                    "target_type": s.target_type.value,
                    "is_authorized": s.is_authorized,
                    "notes": s.notes,
                }
                for s in data.scopes
            ],
            "executions": [
                {
                    "id": ex.id,
                    "tool_name": ex.tool_name,
                    "command": ex.command,
                    "status": ex.status.value,
                    "exit_code": ex.exit_code,
                    "started_at": ex.started_at,
                    "finished_at": ex.finished_at,
                    "duration_seconds": ex.duration_seconds,
                    "raw_output_path": ex.raw_output_path,
                }
                for ex in data.executions
            ],
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "cvss_score": f.cvss_score,
                    "cvss_vector": f.cvss_vector,
                    "affected_asset": f.affected_asset,
                    "affected_port_service": f.affected_port_service,
                    "description": f.description,
                    "reproduction_steps": f.reproduction_steps,
                    "remediation": f.remediation,
                    "validation_status": f.validation_status.value,
                    "source_tool": f.source_tool,
                    "execution_id": f.execution_id,
                    "created_at": f.created_at,
                }
                for f in data.findings
            ],
            "evidence": [
                {
                    "id": ev.id,
                    "file_path": ev.file_path,
                    "sha256_hash": ev.sha256_hash,
                    "finding_id": ev.finding_id,
                    "execution_id": ev.execution_id,
                    "description": ev.description,
                    "mime_type": ev.mime_type,
                    "created_at": ev.created_at,
                }
                for ev in data.evidence
            ],
        }

        json_text = json.dumps(report_dict, indent=2)
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json_text, encoding="utf-8")

        return json_text

    # -------------------------------------------------------------
    # 2. Markdown Report Generation
    # -------------------------------------------------------------
    def generate_markdown(self, project_id: int, output_path: Optional[Path] = None) -> str:
        """Generates a comprehensive, portable technical Markdown report."""
        data = self.build_report_data(project_id)
        p = data.project
        m = data.metrics

        lines: List[str] = [
            f"# Security Assessment & Penetration Testing Report",
            f"**Project:** {p.name}  ",
            f"**Client Organization:** {p.client_name or 'N/A'}  ",
            f"**Assessment Date:** {data.generated_at[:10]}  ",
            f"**Report Classification:** CONFIDENTIAL  ",
            f"**Platform:** CyberSecuritySuite Workstation  ",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            p.description or "This report documents the security assessment and vulnerability findings identified during the authorized penetration test.",
            "",
            "### Risk Posture & Metrics Overview",
            "",
            "| Metric | Count / Value |",
            "| :--- | :--- |",
            f"| **Total Security Findings** | **{m.total_findings}** |",
            f"| Critical Severity | {m.critical_count} |",
            f"| High Severity | {m.high_count} |",
            f"| Medium Severity | {m.medium_count} |",
            f"| Low Severity | {m.low_count} |",
            f"| Informational | {m.info_count} |",
            f"| Maximum CVSS Score | {m.max_cvss:.1f} / 10.0 |",
            f"| Confirmed Vulnerabilities | {m.confirmed_findings} |",
            f"| Authorized Targets In Scope | {m.total_targets} |",
            f"| Security Tools Executed | {m.total_executions} |",
            f"| Cryptographic Evidence Records | {m.total_evidence_files} |",
            "",
            "---",
            "",
            "## 2. Assessment Scope & Rules of Engagement",
            "",
            "Testing was conducted strictly within the authorized targets defined below:",
            "",
            "| Target Identifier | Type | Authorization Status | Notes |",
            "| :--- | :--- | :--- | :--- |",
        ]

        if data.scopes:
            for s in data.scopes:
                auth_str = "Authorized ✓" if s.is_authorized else "Excluded / Blocked ✗"
                lines.append(f"| `{s.target}` | {s.target_type.value} | {auth_str} | {s.notes or 'N/A'} |")
        else:
            lines.append("| *No specific target scopes registered* | - | - | - |")

        lines.extend([
            "",
            "---",
            "",
            "## 3. Methodology & Standards",
            "",
            "The assessment followed the EC-Council CPENT (Certified Penetration Testing Professional) and PTES methodologies:",
            "1. **Reconnaissance & Passive OSINT:** DNS inspection, certificate analysis, HTTP header enumeration, and passive route mapping.",
            "2. **Host & Service Discovery:** Non-intrusive network port scanning and service fingerprinting via Nmap.",
            "3. **Web & API Security Inspection:** Security header validation, CORS misconfiguration analysis, and JavaScript secret scanning.",
            "4. **Vulnerability Verification:** Evidence collection with SHA-256 cryptographic integrity hashes.",
            "",
            "---",
            "",
            "## 4. Findings Summary Matrix",
            "",
            "| ID | Severity | CVSS | Finding Title | Affected Asset | Status |",
            "| :---: | :---: | :---: | :--- | :--- | :---: |",
        ])

        if data.findings:
            for f in data.findings:
                cvss_str = f"{f.cvss_score:.1f}" if f.cvss_score else "N/A"
                lines.append(
                    f"| #{f.id} | **{f.severity.value.upper()}** | {cvss_str} | {f.title} | `{f.affected_asset}` | {f.validation_status.value} |"
                )
        else:
            lines.append("| - | - | - | *No security vulnerabilities identified* | - | - |")

        lines.extend([
            "",
            "---",
            "",
            "## 5. Detailed Technical Findings & Remediation",
            "",
        ])

        if data.findings:
            for f in data.findings:
                lines.extend([
                    f"### Finding #{f.id}: {f.title}",
                    "",
                    f"- **Severity:** `{f.severity.value.upper()}`",
                    f"- **CVSS Score:** `{f.cvss_score or 'N/A'}`",
                    f"- **CVSS Vector:** `{f.cvss_vector or 'N/A'}`",
                    f"- **Affected Asset:** `{f.affected_asset}`",
                    f"- **Service / Port:** `{f.affected_port_service or 'N/A'}`",
                    f"- **Source Tool:** `{f.source_tool or 'N/A'}`",
                    f"- **Validation Status:** `{f.validation_status.value}`",
                    "",
                    "#### Vulnerability Description & Explanation",
                    f"{f.description or 'No description provided.'}",
                    "",
                    "#### Actionable Remediation Guidance",
                    f"{f.remediation or 'Review application configuration and apply vendor hardening guidelines.'}",
                    "",
                ])
                if f.reproduction_steps:
                    lines.extend([
                        "#### Reproduction Steps",
                        f"```text\n{f.reproduction_steps}\n```",
                        "",
                    ])
        else:
            lines.append("No technical findings to display.")

        lines.extend([
            "",
            "---",
            "",
            "## 6. Cryptographic Evidence Vault",
            "",
            "All assessment artifacts, tool outputs, and captured evidence are cryptographically verified:",
            "",
            "| ID | File Name | MIME Type | SHA-256 Hash | Description |",
            "| :---: | :--- | :---: | :--- | :--- |",
        ])

        if data.evidence:
            for ev in data.evidence:
                fname = Path(ev.file_path).name
                lines.append(
                    f"| #{ev.id} | `{fname}` | {ev.mime_type} | `{ev.sha256_hash}` | {ev.description} |"
                )
        else:
            lines.append("| - | *No evidence files registered* | - | - | - |")

        lines.extend([
            "",
            "---",
            "",
            "## 7. Disclaimer & Rules of Engagement",
            "",
            "This report contains sensitive security intelligence intended solely for the authorized client organization.",
            "Testing was executed in compliance with agreed Rules of Engagement. Antigravity / CyberSecuritySuite makes",
            "no guarantee that all vulnerabilities have been discovered beyond the specified testing timeframe and scope.",
            "",
            f"*Generated by CyberSecuritySuite on {data.generated_at} UTC*",
        ])

        md_text = "\n".join(lines)
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(md_text, encoding="utf-8")

        return md_text

    # -------------------------------------------------------------
    # 3. HTML Report Generation
    # -------------------------------------------------------------
    def generate_html(self, project_id: int, output_path: Optional[Path] = None) -> str:
        """Generates a professional, self-contained, responsive HTML report with embedded CSS."""
        data = self.build_report_data(project_id)
        p = data.project
        m = data.metrics

        # Severity Badge CSS classes and colors
        sev_color_map = {
            "critical": ("#ef4444", "#450a0a"),
            "high": ("#f97316", "#431407"),
            "medium": ("#eab308", "#422006"),
            "low": ("#38bdf8", "#082f49"),
            "informational": ("#94a3b8", "#0f172a"),
        }

        # Build Scope Rows HTML
        scope_rows = ""
        for s in data.scopes:
            auth_badge = (
                '<span class="badge badge-success">Authorized</span>'
                if s.is_authorized
                else '<span class="badge badge-danger">Blocked</span>'
            )
            scope_rows += f"""
            <tr>
              <td><code>{s.target}</code></td>
              <td>{s.target_type.value}</td>
              <td>{auth_badge}</td>
              <td>{s.notes or '—'}</td>
            </tr>"""

        # Build Findings Matrix HTML
        findings_matrix_rows = ""
        for f in data.findings:
            sev_fg, sev_bg = sev_color_map.get(f.severity.value, ("#94a3b8", "#0f172a"))
            cvss_val = f"{f.cvss_score:.1f}" if f.cvss_score else "—"
            findings_matrix_rows += f"""
            <tr>
              <td>#{f.id}</td>
              <td><span class="badge" style="background-color: {sev_bg}; color: {sev_fg}; border: 1px solid {sev_fg};">{f.severity.value.upper()}</span></td>
              <td><strong>{cvss_val}</strong></td>
              <td><a href="#finding-{f.id}" class="finding-link">{f.title}</a></td>
              <td><code>{f.affected_asset}</code></td>
              <td><span class="status-tag">{f.validation_status.value}</span></td>
            </tr>"""

        # Build Detailed Findings Cards HTML
        findings_cards = ""
        for f in data.findings:
            sev_fg, sev_bg = sev_color_map.get(f.severity.value, ("#94a3b8", "#0f172a"))
            repro_html = ""
            if f.reproduction_steps:
                repro_html = f"""
                <div class="card-section">
                  <h4>Reproduction Steps</h4>
                  <pre class="code-block">{f.reproduction_steps}</pre>
                </div>"""

            findings_cards += f"""
            <div class="finding-card" id="finding-{f.id}">
              <div class="finding-header">
                <span class="badge" style="background-color: {sev_bg}; color: {sev_fg}; border: 1px solid {sev_fg};">{f.severity.value.upper()}</span>
                <h3 class="finding-title">#{f.id} — {f.title}</h3>
                <span class="cvss-tag">CVSS {f.cvss_score or 'N/A'}</span>
              </div>
              <div class="finding-meta-grid">
                <div><strong>Affected Asset:</strong> <code>{f.affected_asset}</code></div>
                <div><strong>Port / Service:</strong> {f.affected_port_service or 'N/A'}</div>
                <div><strong>Validation:</strong> {f.validation_status.value}</div>
                <div><strong>Source Tool:</strong> {f.source_tool or 'c0desec/nmap'}</div>
              </div>
              <div class="card-section">
                <h4>Vulnerability Explanation</h4>
                <p>{f.description or 'No technical description recorded.'}</p>
              </div>
              <div class="card-section remediation-box">
                <h4>Recommended Remediation</h4>
                <p>{f.remediation or 'Review application configuration and harden server per industry baselines.'}</p>
              </div>
              {repro_html}
            </div>"""

        # Build Evidence Rows HTML
        evidence_rows = ""
        for ev in data.evidence:
            fname = Path(ev.file_path).name
            evidence_rows += f"""
            <tr>
              <td>#{ev.id}</td>
              <td><strong>{fname}</strong></td>
              <td><span class="badge badge-info">{ev.mime_type}</span></td>
              <td><code class="hash-code">{ev.sha256_hash}</code></td>
              <td>{ev.description}</td>
            </tr>"""

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Assessment Report — {p.name}</title>
  <style>
    :root {{
      --bg-primary: #0b0d13;
      --bg-surface: #121620;
      --bg-card: #171d2b;
      --border-color: #242d40;
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --accent-blue: #0284c7;
      --accent-cyan: #38bdf8;
      --color-critical: #ef4444;
      --color-high: #f97316;
      --color-medium: #eab308;
      --color-low: #38bdf8;
      --color-info: #94a3b8;
    }}

    * {{ box-sizing: border-box; margin: 0; padding: 0; }}

    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background-color: var(--bg-primary);
      color: var(--text-primary);
      line-height: 1.6;
      padding: 32px 16px;
    }}

    .container {{
      max-width: 1100px;
      margin: 0 auto;
    }}

    /* Header Banner */
    .report-header {{
      background: linear-gradient(135deg, #0e1526 0%, #17223b 100%);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 32px;
      margin-bottom: 24px;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    }}

    .header-top {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
    }}

    .brand-title {{
      font-size: 14px;
      font-weight: 700;
      letter-spacing: 1.5px;
      text-transform: uppercase;
      color: var(--accent-cyan);
    }}

    .confidential-tag {{
      background-color: #ef444422;
      color: #ef4444;
      border: 1px solid #ef444466;
      padding: 4px 12px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }}

    .report-title {{
      font-size: 28px;
      font-weight: 800;
      color: #ffffff;
      margin-bottom: 8px;
    }}

    .report-meta-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-top: 20px;
      padding-top: 20px;
      border-top: 1px solid var(--border-color);
      font-size: 13px;
      color: var(--text-secondary);
    }}

    .report-meta-grid strong {{ color: var(--text-primary); }}

    /* Metrics Overview Grid */
    .metrics-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 16px;
      margin-bottom: 32px;
    }}

    .metric-card {{
      background-color: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 16px;
      text-align: center;
    }}

    .metric-value {{
      font-size: 32px;
      font-weight: 800;
      line-height: 1.2;
      margin-bottom: 4px;
    }}

    .metric-label {{
      font-size: 12px;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}

    /* Severity Breakdown Bar */
    .severity-bar-container {{
      background-color: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 32px;
    }}

    .section-title {{
      font-size: 20px;
      font-weight: 700;
      color: #ffffff;
      margin-bottom: 16px;
      display: flex;
      align-items: center;
      gap: 8px;
    }}

    /* Tables */
    .table-container {{
      background-color: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      overflow-x: auto;
      margin-bottom: 32px;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      text-align: left;
    }}

    th {{
      background-color: #0f1420;
      color: var(--text-secondary);
      padding: 12px 16px;
      font-weight: 600;
      border-bottom: 1px solid var(--border-color);
    }}

    td {{
      padding: 12px 16px;
      border-bottom: 1px solid var(--border-color);
      color: var(--text-primary);
    }}

    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background-color: rgba(255, 255, 255, 0.02); }}

    code {{
      font-family: "JetBrains Mono", Consolas, monospace;
      font-size: 12px;
      background-color: #1e2638;
      padding: 2px 6px;
      border-radius: 4px;
      color: var(--accent-cyan);
    }}

    .hash-code {{
      font-size: 11px;
      word-break: break-all;
    }}

    /* Badges */
    .badge {{
      display: inline-block;
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}

    .badge-success {{ background-color: #064e3b; color: #34d399; border: 1px solid #059669; }}
    .badge-danger {{ background-color: #450a0a; color: #f87171; border: 1px solid #dc2626; }}
    .badge-info {{ background-color: #0c4a6e; color: #38bdf8; border: 1px solid #0284c7; }}

    .status-tag {{
      background-color: #1e293b;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 11px;
      color: var(--text-secondary);
    }}

    .finding-link {{
      color: #ffffff;
      text-decoration: none;
      font-weight: 600;
    }}

    .finding-link:hover {{
      color: var(--accent-cyan);
      text-decoration: underline;
    }}

    /* Finding Detail Cards */
    .finding-card {{
      background-color: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 24px;
      margin-bottom: 20px;
    }}

    .finding-header {{
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 16px;
    }}

    .finding-title {{
      font-size: 18px;
      font-weight: 700;
      color: #ffffff;
      flex: 1;
    }}

    .cvss-tag {{
      background-color: #1e293b;
      border: 1px solid #334155;
      padding: 4px 10px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 700;
      color: #e2e8f0;
    }}

    .finding-meta-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 12px;
      padding: 12px;
      background-color: #0f1420;
      border-radius: 6px;
      margin-bottom: 16px;
      font-size: 12px;
      color: var(--text-secondary);
    }}

    .card-section {{ margin-bottom: 16px; }}
    .card-section h4 {{
      font-size: 13px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--accent-cyan);
      margin-bottom: 6px;
    }}

    .card-section p {{ font-size: 13px; color: #cbd5e1; }}

    .remediation-box {{
      background-color: rgba(2, 132, 199, 0.08);
      border-left: 3px solid var(--accent-cyan);
      padding: 12px;
      border-radius: 0 6px 6px 0;
    }}

    .code-block {{
      background-color: #090c12;
      border: 1px solid #1e2433;
      padding: 12px;
      border-radius: 6px;
      font-family: "JetBrains Mono", Consolas, monospace;
      font-size: 12px;
      color: #38bdf8;
      overflow-x: auto;
    }}

    /* Footer */
    .report-footer {{
      margin-top: 48px;
      padding-top: 24px;
      border-top: 1px solid var(--border-color);
      text-align: center;
      font-size: 12px;
      color: var(--text-muted);
    }}

    @media print {{
      body {{ background-color: #ffffff; color: #000000; padding: 0; }}
      .container {{ max-width: 100%; }}
      .report-header {{ background: #f1f5f9; border-color: #cbd5e1; color: #000; }}
      .report-title {{ color: #000000; }}
      .metric-card, .finding-card, .table-container, .severity-bar-container {{
        background: #ffffff;
        border-color: #cbd5e1;
        color: #000;
      }}
      th {{ background: #f8fafc; color: #334155; }}
      td {{ color: #0f172a; border-color: #e2e8f0; }}
      .card-section p, .finding-title {{ color: #0f172a; }}
    }}
  </style>
</head>
<body>
  <div class="container">

    <!-- Header Banner -->
    <header class="report-header">
      <div class="header-top">
        <span class="brand-title">CyberSecuritySuite — Security Workstation</span>
        <span class="confidential-tag">Confidential Assessment</span>
      </div>
      <h1 class="report-title">{p.name}</h1>
      <p style="color: var(--text-secondary); font-size: 14px;">Professional Penetration Testing & Vulnerability Assessment Report</p>

      <div class="report-meta-grid">
        <div><strong>Client:</strong> {p.client_name or 'N/A'}</div>
        <div><strong>Assessment Date:</strong> {data.generated_at[:10]}</div>
        <div><strong>Project Status:</strong> {p.status.value.upper()}</div>
        <div><strong>Methodology:</strong> EC-Council CPENT / PTES</div>
      </div>
    </header>

    <!-- Metrics Cards -->
    <div class="metrics-grid">
      <div class="metric-card">
        <div class="metric-value" style="color: var(--accent-cyan);">{m.total_findings}</div>
        <div class="metric-label">Total Findings</div>
      </div>
      <div class="metric-card">
        <div class="metric-value" style="color: var(--color-critical);">{m.critical_count}</div>
        <div class="metric-label">Critical</div>
      </div>
      <div class="metric-card">
        <div class="metric-value" style="color: var(--color-high);">{m.high_count}</div>
        <div class="metric-label">High</div>
      </div>
      <div class="metric-card">
        <div class="metric-value" style="color: var(--color-medium);">{m.medium_count}</div>
        <div class="metric-label">Medium</div>
      </div>
      <div class="metric-card">
        <div class="metric-value" style="color: var(--color-low);">{m.low_count}</div>
        <div class="metric-label">Low / Info</div>
      </div>
      <div class="metric-card">
        <div class="metric-value" style="color: #ffffff;">{m.max_cvss:.1f}</div>
        <div class="metric-label">Max CVSS</div>
      </div>
    </div>

    <!-- Executive Summary Section -->
    <div class="severity-bar-container">
      <h2 class="section-title">📊 Executive Summary</h2>
      <p style="color: var(--text-secondary); margin-bottom: 12px;">
        {p.description or 'A comprehensive security evaluation was executed to discover exploitable vulnerabilities and configuration deficiencies.'}
      </p>
      <div style="font-size: 13px; color: var(--text-secondary);">
        A total of <strong>{m.total_findings}</strong> security findings were identified across <strong>{m.total_targets}</strong> target assets.
        <strong>{m.confirmed_findings}</strong> vulnerabilities were confirmed with evidence.
      </div>
    </div>

    <!-- Scope Table -->
    <h2 class="section-title">🎯 Assessment Scope & Rules of Engagement</h2>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Target Locus</th>
            <th>Type</th>
            <th>Authorization Status</th>
            <th>Operational Notes</th>
          </tr>
        </thead>
        <tbody>
          {scope_rows or '<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No target scopes registered</td></tr>'}
        </tbody>
      </table>
    </div>

    <!-- Findings Matrix Table -->
    <h2 class="section-title">🛡️ Security Findings Summary Matrix</h2>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Severity</th>
            <th>CVSS</th>
            <th>Finding Title</th>
            <th>Affected Asset</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {findings_matrix_rows or '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No security findings discovered</td></tr>'}
        </tbody>
      </table>
    </div>

    <!-- Detailed Findings Cards -->
    <h2 class="section-title">🔍 Technical Findings & Remediation Guidance</h2>
    {findings_cards or '<div class="finding-card"><p style="color: var(--text-secondary);">No findings to display.</p></div>'}

    <!-- Evidence Vault Table -->
    <h2 class="section-title">🔒 Cryptographic Evidence Vault (SHA-256)</h2>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Artifact File</th>
            <th>MIME Type</th>
            <th>Cryptographic Hash (SHA-256)</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          {evidence_rows or '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No evidence records vaulted</td></tr>'}
        </tbody>
      </table>
    </div>

    <!-- Footer -->
    <footer class="report-footer">
      <p>Report generated by <strong>CyberSecuritySuite Workstation</strong> — EC-Council CPENT Preparedness Platform</p>
      <p>Generated at {data.generated_at} UTC • Cryptographically Signed Record</p>
    </footer>

  </div>
</body>
</html>"""

        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(html_content, encoding="utf-8")

        return html_content

    # -------------------------------------------------------------
    # 4. Generate All Formats Utility
    # -------------------------------------------------------------
    def generate_all(self, project_id: int, output_dir: Path) -> Dict[str, Path]:
        """Generates HTML, Markdown, and JSON reports in output_dir."""
        data = self.build_report_data(project_id)
        output_dir.mkdir(parents=True, exist_ok=True)

        clean_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in data.project.name.lower())
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        html_path = output_dir / f"{clean_name}_report_{stamp}.html"
        md_path = output_dir / f"{clean_name}_report_{stamp}.md"
        json_path = output_dir / f"{clean_name}_report_{stamp}.json"

        self.generate_html(project_id, output_path=html_path)
        self.generate_markdown(project_id, output_path=md_path)
        self.generate_json(project_id, output_path=json_path)

        return {
            "html": html_path,
            "markdown": md_path,
            "json": json_path,
        }

