# Changelog

All notable changes to the CyberSecuritySuite platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased] - 2026-10-20

### Added
- Canonical directory skeleton (`core/`, `modules/`, `desktop/`, `terminal/`, `ai/`, `storage/`, `reports/`, `labs/`, `source/`, `docs/`, `licenses/`, `third_party/`, `tests/`, `scripts/`).
- Initialized local Git repository (`main` branch) with comprehensive `.gitignore`.
- Python 3.12 virtual environment (`.venv`) with `PySide6 6.12.0`, `pytest 9.1.1`, `pytest-qt 4.5.0`, and `pytest-cov 7.1.0`.
- Foundational documentation suite:
  - `README.md`: Project overview, capabilities, setup guide, and ethical disclaimer.
  - `docs/PROJECT_MASTER_BRIEF.md`: Core requirements, philosophy, and learning objectives.
  - `docs/ARCHITECTURE.md`: High-level multi-layer architecture and component interactions.
  - `docs/ROADMAP.md`: Phased milestone tracking from Phase 0 to Phase 8.
  - `docs/SOURCE_INVENTORY.md`: Tracking matrix of candidate upstream security tools and licenses.
  - `docs/SECURITY_MODEL.md`: Scope guard, process safety, AI redaction, and evidence integrity rules.
  - `docs/DECISIONS.md`: Architecture Decision Records (ADRs 001 - 005).
  - `docs/CHANGELOG.md`: Chronological log of changes.
