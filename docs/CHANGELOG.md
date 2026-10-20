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
- **Comprehensive Test Suite**:
  - 30 automated tests across `test_environment`, `test_storage`, `test_scope`, `test_registry`, `test_runner`, `test_nmap_parser`, `test_nmap_adapter`, and `test_ui` (via `pytest-qt`). All 30 tests passing.
