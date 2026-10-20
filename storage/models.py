"""Core domain models for CyberSecuritySuite.

Defines dataclasses for Projects, Target Scopes, Tool Executions,
Security Findings, and Evidence records.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ProjectStatus(str, Enum):
    ACTIVE = "active"
    ARCHIVED = "archived"
    COMPLETED = "completed"


class TargetType(str, Enum):
    IP_ADDRESS = "ip_address"
    CIDR_RANGE = "cidr_range"
    HOSTNAME = "hostname"
    URL = "url"


class ExecutionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ValidationStatus(str, Enum):
    UNVERIFIED = "unverified"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    REMEDIATED = "remediated"


@dataclass
class Project:
    name: str
    id: Optional[int] = None
    client_name: str = ""
    description: str = ""
    status: ProjectStatus = ProjectStatus.ACTIVE
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)


@dataclass
class TargetScope:
    project_id: int
    target: str
    id: Optional[int] = None
    target_type: TargetType = TargetType.IP_ADDRESS
    is_authorized: bool = True
    notes: str = ""
    created_at: str = field(default_factory=_utc_now_iso)


@dataclass
class ToolExecution:
    project_id: int
    tool_name: str
    command: str
    id: Optional[int] = None
    status: ExecutionStatus = ExecutionStatus.PENDING
    exit_code: Optional[int] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    raw_output_path: Optional[str] = None
    created_at: str = field(default_factory=_utc_now_iso)


@dataclass
class Finding:
    project_id: int
    title: str
    id: Optional[int] = None
    severity: FindingSeverity = FindingSeverity.INFORMATIONAL
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    affected_asset: str = ""
    affected_port_service: str = ""
    description: str = ""
    reproduction_steps: str = ""
    remediation: str = ""
    validation_status: ValidationStatus = ValidationStatus.UNVERIFIED
    source_tool: str = ""
    execution_id: Optional[int] = None
    created_at: str = field(default_factory=_utc_now_iso)


@dataclass
class Evidence:
    project_id: int
    file_path: str
    sha256_hash: str = ""
    id: Optional[int] = None
    finding_id: Optional[int] = None
    execution_id: Optional[int] = None
    description: str = ""
    mime_type: str = "text/plain"
    file_hash: Optional[str] = None
    created_at: str = field(default_factory=_utc_now_iso)

    def __post_init__(self):
        if not self.sha256_hash and self.file_hash:
            self.sha256_hash = self.file_hash
        elif not self.file_hash and self.sha256_hash:
            self.file_hash = self.sha256_hash
