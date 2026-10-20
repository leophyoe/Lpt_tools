"""Nmap tool execution adapter.

Constructs validated Nmap scan commands, verifies target scope,
executes via ProcessRunner, parses XML output, and persists findings.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, List, Optional

from core.registry import ToolRegistry
from core.scope import ScopeAuthorizationService, ScopeCheckResult
from modules.network.nmap_parser import NmapParser, NmapScanResult
from storage.db import Database
from storage.models import (
    Evidence,
    ExecutionStatus,
    Finding,
    TargetScope,
    ToolExecution,
)
from terminal.runner import ProcessRunner


class ScanProfile(str, Enum):
    PING_DISCOVERY = "ping_discovery"
    TOP_PORTS = "top_ports"
    SERVICE_VERSION = "service_version"
    CUSTOM = "custom"


@dataclass
class NmapScanOptions:
    target: str
    profile: ScanProfile = ScanProfile.TOP_PORTS
    ports: Optional[str] = None
    extra_args: Optional[List[str]] = None
    timeout: float = 300.0


@dataclass
class NmapExecutionResult:
    is_authorized: bool
    scope_reason: str
    execution: Optional[ToolExecution] = None
    scan_result: Optional[NmapScanResult] = None
    findings: List[Finding] = None

    def __post_init__(self):
        if self.findings is None:
            self.findings = []


class NmapAdapter:
    """Orchestrates authorized Nmap scanning, execution, and finding creation."""

    def __init__(self, db: Database, registry: Optional[ToolRegistry] = None):
        self.db = db
        self.registry = registry or ToolRegistry()
        self.runner = ProcessRunner()

    def build_command(self, options: NmapScanOptions) -> List[str]:
        """Construct a safe argument list for Nmap execution."""
        nmap_meta = self.registry.get_tool("nmap")
        binary = nmap_meta.binary_path if (nmap_meta and nmap_meta.binary_path) else "nmap"

        cmd = [binary]

        if options.profile == ScanProfile.PING_DISCOVERY:
            cmd.extend(["-sn"])
        elif options.profile == ScanProfile.TOP_PORTS:
            cmd.extend(["-F", "-T4"])
        elif options.profile == ScanProfile.SERVICE_VERSION:
            cmd.extend(["-sV", "-T4"])
        elif options.profile == ScanProfile.CUSTOM and options.ports:
            cmd.extend(["-p", options.ports])

        if options.ports and options.profile != ScanProfile.CUSTOM:
            cmd.extend(["-p", options.ports])

        if options.extra_args:
            # Prevent injection of destructive flags or redirection
            forbidden = {"--script=exploit", "-oN", "-oX", "-oG", "-oS"}
            for arg in options.extra_args:
                if not any(arg.startswith(f) for f in forbidden):
                    cmd.append(arg)

        # Force XML output to stdout for programmatic parsing
        cmd.extend(["-oX", "-"])
        cmd.append(options.target)

        return cmd

    def execute_scan(
        self,
        project_id: int,
        options: NmapScanOptions,
        scopes: List[TargetScope],
        on_output: Optional[Callable[[str, str], None]] = None,
        evidence_dir: Optional[Path] = None,
    ) -> NmapExecutionResult:
        """Validate scope, run Nmap, parse results, and record findings."""
        # 1. Scope check
        scope_check: ScopeCheckResult = ScopeAuthorizationService.is_target_authorized(
            options.target, scopes
        )
        if not scope_check.is_allowed:
            return NmapExecutionResult(
                is_authorized=False,
                scope_reason=scope_check.reason,
            )

        # 2. Build command
        command = self.build_command(options)
        cmd_str = " ".join(command)

        # 3. Create execution record in DB
        execution = ToolExecution(
            project_id=project_id,
            tool_name="nmap",
            command=cmd_str,
            status=ExecutionStatus.RUNNING,
        )
        execution = self.db.create_execution(execution)

        # 4. Execute process
        result = self.runner.run(
            command=command,
            timeout=options.timeout,
            on_output=on_output,
        )

        # 5. Update execution record
        execution.status = result.status
        execution.exit_code = result.exit_code
        execution.started_at = result.started_at
        execution.finished_at = result.finished_at
        execution.duration_seconds = result.duration_seconds

        # Save raw XML evidence if output exists
        raw_xml = result.stdout
        if raw_xml.strip() and evidence_dir:
            evidence_dir.mkdir(parents=True, exist_ok=True)
            ev_file = evidence_dir / f"nmap_exec_{execution.id}.xml"
            ev_file.write_text(raw_xml, encoding="utf-8")
            execution.raw_output_path = str(ev_file)

            sha256 = hashlib.sha256(raw_xml.encode("utf-8")).hexdigest()
            self.db.add_evidence(
                Evidence(
                    project_id=project_id,
                    execution_id=execution.id,
                    file_path=str(ev_file),
                    sha256_hash=sha256,
                    description=f"Raw Nmap XML output for execution #{execution.id}",
                    mime_type="application/xml",
                )
            )

        self.db.update_execution(execution)

        # 6. Parse structured findings
        scan_result = None
        findings: List[Finding] = []
        if result.status == ExecutionStatus.COMPLETED and raw_xml.strip():
            try:
                scan_result = NmapParser.parse_xml(raw_xml)
                findings = NmapParser.to_findings(
                    scan_result, project_id=project_id, execution_id=execution.id
                )
                for f in findings:
                    self.db.create_finding(f)
            except ValueError:
                pass

        return NmapExecutionResult(
            is_authorized=True,
            scope_reason=scope_check.reason,
            execution=execution,
            scan_result=scan_result,
            findings=findings,
        )
