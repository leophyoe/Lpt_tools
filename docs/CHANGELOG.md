# Changelog

All notable changes to the CyberSecuritySuite platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased] - 2026-10-20

### Added
- **Core Architecture & Storage (Phase 1)**:
  - SQLite persistent database manager in `storage/db.py` featuring Write-Ahead Logging (WAL) and foreign key cascades.
  - Domain models in `storage/models.py` for Projects, Target Scopes, Tool Executions, Security Findings, and Evidence records.
  - Pre-execution target scope authorization service in `core/scope.py` supporting IP addresses, CIDR subnet containment, and hostname/domain matching.
- **Process Execution & Tool Registry (Phase 2)**:
  - System tool registry in `core/registry.py` detecting host binaries (`nmap`, `zap.sh`, `tshark`, `nuclei`) and checking versions.
  - Asynchronous streaming process runner in `terminal/runner.py` with real-time stdout/stderr callback streaming, execution duration tracking, timeouts, and process-group cancellation (`SIGTERM`/`SIGKILL`).
- **Network Security Workflow (Phase 4)**:
  - `NmapParser` in `modules/network/nmap_parser.py` extracting host states, open ports, service banners, and translating them into structured findings with severity levels and remediation guidance.
  - `NmapAdapter` in `modules/network/nmap_adapter.py` validating target scope, constructing safe argument arrays, executing scans via `ProcessRunner`, saving raw XML evidence with SHA-256 hashes, and storing findings.
- **Desktop Workstation UI (Phase 3 & Action 3)**:
  - PySide6 desktop application in `desktop/` styled with a dark cybersecurity workstation theme (`desktop/theme.py`).
  - Integrated terminal console widget (`desktop/widgets/terminal_view.py`) supporting real-time streaming, color-coded streams, and clipboard copy.
  - Projects & Scope management view (`desktop/views/projects_view.py`).
  - Network discovery scan view (`desktop/views/network_scan_view.py`) with background execution thread and scope guard modal alerts.
  - Findings and Evidence triage view (`desktop/views/findings_view.py`) with severity badges and markdown remediation panel.
  - CPENT learning & practical labs roadmap view (`desktop/views/cpent_labs_view.py`).
- **CPENT Learning Platform & Practical Methodologies (Phase 9)**:
  - Structured CPENT test models in `labs/cpent/curriculum.py` covering OSINT, Social Engineering, and Network Pentesting.
  - Complete 30-Day CPENT AI Study Plan in `labs/cpent/study_plan.py` spanning 4 weeks of structured theory, practical tasks, and tool recommendations.
  - Interactive multi-tab CPENT Desktop View in `desktop/views/cpent_labs_view.py`:
    - Tab 1: 🗓️ 30-Day Study Roadmap with daily tasks and progress tracking.
    - Tab 2: 🛡️ Assessment Methodologies explorer with live search and markdown guidance.
    - Tab 3: ⚡ Practical Command & One-Liner Cheat Sheet (Nmap, NetExec, Pivoting, Chisel, SMB, Metasploit).
  - Reference materials collected in `labs/cpent/references/`: Vitaly Ford CPENT notes, CPENT-Crash-Course, CPENT-Learning, and CPENTv1StudyGuide.
  - Integration of `c0desec-pentest` in `source/web/c0desec-pentest` for web/API security testing.
- **Web & API Security Integration (Phase 4 / c0desec Adapter)**:
  - `WebSecurityAdapter` in `modules/web/c0desec_adapter.py` providing safe, passive web application & API reconnaissance with strict scope enforcement.
  - Integration with `source/web/c0desec-pentest` constants and secret detection regex patterns (`SECRET_PATTERNS`).
  - Automated sensitive-value redaction via `redact_secret_value()` ensuring credentials/tokens are never exposed in logs or findings.
  - HTTP security header inspection (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Server version disclosures).
  - Insecure CORS misconfiguration detection (reflective origins with credentials).
  - Web route & endpoint extraction from HTML anchors, scripts, and forms.
  - Raw JSON evidence vault archiving with SHA-256 cryptographic integrity hash.
  - Desktop `WebScanView` in `desktop/views/web_scan_view.py` with multi-tab results display (Discovered Routes, JS Secret Candidates, Response Headers), background worker thread, cancel capability, and real-time terminal streaming.
  - Integration into `MainWindow` navigation bar and project-switching signal pipeline.
- **Comprehensive Test Suite**:
  - 41 automated tests across all domain models, scope authorization, process runner, Nmap adapter/parser, curriculum, 30-day study plan, c0desec adapter, and PySide6 UI. All 41 tests passing.
