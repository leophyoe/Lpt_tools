"""Database management and SQLite repository for CyberSecuritySuite.

Enforces SQLite WAL mode, foreign key integrity, and provides atomic
operations for Projects, Scopes, Executions, Findings, and Evidence.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, List, Optional

from storage.models import (
    Evidence,
    ExecutionStatus,
    Finding,
    FindingSeverity,
    Project,
    ProjectStatus,
    TargetScope,
    TargetType,
    ToolExecution,
    ValidationStatus,
)

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    client_name TEXT DEFAULT '',
    description TEXT DEFAULT '',
    status TEXT DEFAULT 'active',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS target_scopes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    target TEXT NOT NULL,
    target_type TEXT DEFAULT 'ip_address',
    is_authorized INTEGER DEFAULT 1,
    notes TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tool_executions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    tool_name TEXT NOT NULL,
    command TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    exit_code INTEGER,
    started_at TEXT,
    finished_at TEXT,
    duration_seconds REAL,
    raw_output_path TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    severity TEXT DEFAULT 'informational',
    cvss_score REAL,
    cvss_vector TEXT,
    affected_asset TEXT DEFAULT '',
    affected_port_service TEXT DEFAULT '',
    description TEXT DEFAULT '',
    reproduction_steps TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    validation_status TEXT DEFAULT 'unverified',
    source_tool TEXT DEFAULT '',
    execution_id INTEGER,
    created_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (execution_id) REFERENCES tool_executions(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    sha256_hash TEXT NOT NULL,
    finding_id INTEGER,
    execution_id INTEGER,
    description TEXT DEFAULT '',
    mime_type TEXT DEFAULT 'text/plain',
    created_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE SET NULL,
    FOREIGN KEY (execution_id) REFERENCES tool_executions(id) ON DELETE SET NULL
);
"""


class Database:
    """Manages SQLite connections, migrations, and repository operations."""

    def __init__(self, db_path: str | Path = ":memory:"):
        self.db_path = str(db_path)
        self._mem_conn: Optional[sqlite3.Connection] = None
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        else:
            self._mem_conn = sqlite3.connect(":memory:")
            self._mem_conn.row_factory = sqlite3.Row
            self._mem_conn.execute("PRAGMA foreign_keys = ON;")
        self._init_db()

    def get_connection(self) -> sqlite3.Connection:
        if self._mem_conn is not None:
            return self._mem_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        return conn

    def close(self) -> None:
        if self._mem_conn is not None:
            self._mem_conn.close()
            self._mem_conn = None

    @contextmanager
    def session(self) -> Generator[sqlite3.Connection, None, None]:
        """Provides an atomic transactional connection context."""
        conn = self.get_connection()
        try:
            with conn:
                yield conn
        finally:
            if self._mem_conn is None:
                conn.close()

    def _init_db(self) -> None:
        with self.session() as conn:
            conn.executescript(SCHEMA_SQL)

    # ---------------------------------------------------------
    # Project Operations
    # ---------------------------------------------------------
    def create_project(self, project: Project) -> Project:
        query = """
            INSERT INTO projects (name, client_name, description, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """
        with self.session() as conn:
            cursor = conn.execute(
                query,
                (
                    project.name,
                    project.client_name,
                    project.description,
                    project.status.value,
                    project.created_at,
                    project.updated_at,
                ),
            )
            project.id = cursor.lastrowid
            return project

    def get_project(self, project_id: int) -> Optional[Project]:
        query = "SELECT * FROM projects WHERE id = ?"
        with self.session() as conn:
            row = conn.execute(query, (project_id,)).fetchone()
            if not row:
                return None
            return Project(
                id=row["id"],
                name=row["name"],
                client_name=row["client_name"],
                description=row["description"],
                status=ProjectStatus(row["status"]),
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )

    def list_projects(self) -> List[Project]:
        query = "SELECT * FROM projects ORDER BY created_at DESC"
        with self.session() as conn:
            rows = conn.execute(query).fetchall()
            return [
                Project(
                    id=row["id"],
                    name=row["name"],
                    client_name=row["client_name"],
                    description=row["description"],
                    status=ProjectStatus(row["status"]),
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                )
                for row in rows
            ]

    def delete_project(self, project_id: int) -> bool:
        query = "DELETE FROM projects WHERE id = ?"
        with self.session() as conn:
            cursor = conn.execute(query, (project_id,))
            return cursor.rowcount > 0

    # ---------------------------------------------------------
    # Target Scope Operations
    # ---------------------------------------------------------
    def add_scope(self, scope: TargetScope) -> TargetScope:
        query = """
            INSERT INTO target_scopes (project_id, target, target_type, is_authorized, notes, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """
        with self.session() as conn:
            cursor = conn.execute(
                query,
                (
                    scope.project_id,
                    scope.target,
                    scope.target_type.value,
                    1 if scope.is_authorized else 0,
                    scope.notes,
                    scope.created_at,
                ),
            )
            scope.id = cursor.lastrowid
            return scope

    def list_scopes(self, project_id: int) -> List[TargetScope]:
        query = "SELECT * FROM target_scopes WHERE project_id = ? ORDER BY id ASC"
        with self.session() as conn:
            rows = conn.execute(query, (project_id,)).fetchall()
            return [
                TargetScope(
                    id=row["id"],
                    project_id=row["project_id"],
                    target=row["target"],
                    target_type=TargetType(row["target_type"]),
                    is_authorized=bool(row["is_authorized"]),
                    notes=row["notes"],
                    created_at=row["created_at"],
                )
                for row in rows
            ]

    # ---------------------------------------------------------
    # Tool Execution Operations
    # ---------------------------------------------------------
    def create_execution(self, execution: ToolExecution) -> ToolExecution:
        query = """
            INSERT INTO tool_executions (project_id, tool_name, command, status, exit_code, started_at, finished_at, duration_seconds, raw_output_path, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self.session() as conn:
            cursor = conn.execute(
                query,
                (
                    execution.project_id,
                    execution.tool_name,
                    execution.command,
                    execution.status.value,
                    execution.exit_code,
                    execution.started_at,
                    execution.finished_at,
                    execution.duration_seconds,
                    execution.raw_output_path,
                    execution.created_at,
                ),
            )
            execution.id = cursor.lastrowid
            return execution

    def update_execution(self, execution: ToolExecution) -> None:
        query = """
            UPDATE tool_executions
            SET status = ?, exit_code = ?, started_at = ?, finished_at = ?, duration_seconds = ?, raw_output_path = ?
            WHERE id = ?
        """
        with self.session() as conn:
            conn.execute(
                query,
                (
                    execution.status.value,
                    execution.exit_code,
                    execution.started_at,
                    execution.finished_at,
                    execution.duration_seconds,
                    execution.raw_output_path,
                    execution.id,
                ),
            )

    def list_executions(self, project_id: int) -> List[ToolExecution]:
        query = "SELECT * FROM tool_executions WHERE project_id = ? ORDER BY id DESC"
        with self.session() as conn:
            rows = conn.execute(query, (project_id,)).fetchall()
            return [
                ToolExecution(
                    id=row["id"],
                    project_id=row["project_id"],
                    tool_name=row["tool_name"],
                    command=row["command"],
                    status=ExecutionStatus(row["status"]),
                    exit_code=row["exit_code"],
                    started_at=row["started_at"],
                    finished_at=row["finished_at"],
                    duration_seconds=row["duration_seconds"],
                    raw_output_path=row["raw_output_path"],
                    created_at=row["created_at"],
                )
                for row in rows
            ]

    # ---------------------------------------------------------
    # Finding Operations
    # ---------------------------------------------------------
    def create_finding(self, finding: Finding) -> Finding:
        query = """
            INSERT INTO findings (project_id, title, severity, cvss_score, cvss_vector, affected_asset,
                                 affected_port_service, description, reproduction_steps, remediation,
                                 validation_status, source_tool, execution_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self.session() as conn:
            cursor = conn.execute(
                query,
                (
                    finding.project_id,
                    finding.title,
                    finding.severity.value,
                    finding.cvss_score,
                    finding.cvss_vector,
                    finding.affected_asset,
                    finding.affected_port_service,
                    finding.description,
                    finding.reproduction_steps,
                    finding.remediation,
                    finding.validation_status.value,
                    finding.source_tool,
                    finding.execution_id,
                    finding.created_at,
                ),
            )
            finding.id = cursor.lastrowid
            return finding

    def list_findings(self, project_id: int) -> List[Finding]:
        query = "SELECT * FROM findings WHERE project_id = ? ORDER BY id DESC"
        with self.session() as conn:
            rows = conn.execute(query, (project_id,)).fetchall()
            return [
                Finding(
                    id=row["id"],
                    project_id=row["project_id"],
                    title=row["title"],
                    severity=FindingSeverity(row["severity"]),
                    cvss_score=row["cvss_score"],
                    cvss_vector=row["cvss_vector"],
                    affected_asset=row["affected_asset"],
                    affected_port_service=row["affected_port_service"],
                    description=row["description"],
                    reproduction_steps=row["reproduction_steps"],
                    remediation=row["remediation"],
                    validation_status=ValidationStatus(row["validation_status"]),
                    source_tool=row["source_tool"],
                    execution_id=row["execution_id"],
                    created_at=row["created_at"],
                )
                for row in rows
            ]

    # ---------------------------------------------------------
    # Evidence Operations
    # ---------------------------------------------------------
    def add_evidence(self, evidence: Evidence) -> Evidence:
        query = """
            INSERT INTO evidence (project_id, file_path, sha256_hash, finding_id, execution_id, description, mime_type, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self.session() as conn:
            cursor = conn.execute(
                query,
                (
                    evidence.project_id,
                    evidence.file_path,
                    evidence.sha256_hash,
                    evidence.finding_id,
                    evidence.execution_id,
                    evidence.description,
                    evidence.mime_type,
                    evidence.created_at,
                ),
            )
            evidence.id = cursor.lastrowid
            return evidence

    def list_evidence(self, project_id: int) -> List[Evidence]:
        query = "SELECT * FROM evidence WHERE project_id = ? ORDER BY id DESC"
        with self.session() as conn:
            rows = conn.execute(query, (project_id,)).fetchall()
            return [
                Evidence(
                    id=row["id"],
                    project_id=row["project_id"],
                    file_path=row["file_path"],
                    sha256_hash=row["sha256_hash"],
                    finding_id=row["finding_id"],
                    execution_id=row["execution_id"],
                    description=row["description"],
                    mime_type=row["mime_type"],
                    created_at=row["created_at"],
                )
                for row in rows
            ]

    # Backward compatibility aliases
    create_evidence = add_evidence
    create_target_scope = add_scope
    create_tool_execution = create_execution
