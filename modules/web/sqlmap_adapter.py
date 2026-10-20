"""SQLMap Execution and Vulnerability Detection Adapter.

Safely invokes the open-source SQLMap engine (from source/web/sqlmap/sqlmap.py
or host PATH), enforces pre-execution target scope authorization, streams output
without freezing the GUI, and persists discovered SQL injection vulnerabilities
as structured findings and cryptographic evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Tuple
from urllib.parse import urlparse

from core.registry import ToolRegistry
from core.scope import ScopeAuthorizationService, ScopeCheckResult
from storage.db import Database
from storage.models import (
    Evidence,
    ExecutionStatus,
    Finding,
    FindingSeverity,
    TargetScope,
    ToolExecution,
    ValidationStatus,
)
from terminal.runner import ProcessExecutionResult, ProcessRunner


@dataclass
class SQLMapOptions:
    target_url: str
    risk: int = 1         # 1: Low risk, 2: Medium, 3: High
    level: int = 1        # 1: Basic tests, 2: Cookie, 3: User-Agent, 5: Host
    crawl_depth: int = 0  # 0: Just target URL
    batch_mode: bool = True
    timeout: float = 30.0


@dataclass
class SQLMapFindingItem:
    parameter: str
    param_type: str
    injection_type: str
    title: str
    payload: str
    dbms: str


class SQLMapAdapter:
    """Orchestrates authorized SQLMap security testing within scope."""

    def __init__(self, db: Database, registry: Optional[ToolRegistry] = None):
        self.db = db
        self.registry = registry or ToolRegistry()
        self.runner = ProcessRunner()

    def build_command(self, options: SQLMapOptions) -> List[str]:
        """Constructs safe argument array for SQLMap."""
        base_cmd = self.registry.resolve_command("sqlmap", [])

        args = list(base_cmd)
        args.extend(["-u", options.target_url])
        args.extend(["--risk", str(options.risk)])
        args.extend(["--level", str(options.level)])

        if options.batch_mode:
            args.append("--batch")

        if options.crawl_depth > 0:
            args.extend(["--crawl", str(options.crawl_depth)])

        # Safety options: disable color codes for clean regex parsing
        args.append("--disable-coloring")
        return args

    def cancel(self) -> bool:
        return self.runner.cancel()

    def execute_scan(
        self,
        project_id: int,
        options: SQLMapOptions,
        scopes: List[TargetScope],
        on_output: Optional[Callable[[str, str], None]] = None,
        evidence_dir: Optional[Path] = None,
    ) -> Tuple[bool, str, List[Finding], Optional[ToolExecution]]:
        """Validates scope, runs SQLMap in background subprocess, and parses findings."""
        target_url = options.target_url.strip()
        parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
        host = parsed.hostname or target_url

        # 1. Enforce Scope Authorization
        scope_check: ScopeCheckResult = ScopeAuthorizationService.is_target_authorized(host, scopes)
        if not scope_check.is_allowed:
            if on_output:
                on_output(f"[-] SQLMap execution blocked by Scope Guard: {scope_check.reason}\n", "stderr")
            return False, scope_check.reason, [], None

        # 2. Build Safe Command
        try:
            cmd = self.build_command(options)
        except FileNotFoundError as e:
            if on_output:
                on_output(f"[-] Tool not available: {e}\n", "stderr")
            return False, str(e), [], None

        # 3. Create Execution Record
        cmd_str = " ".join(cmd)
        execution = ToolExecution(
            project_id=project_id,
            tool_name="sqlmap",
            command=cmd_str,
            status=ExecutionStatus.RUNNING,
        )
        execution = self.db.create_execution(execution)

        def emit(msg: str, stream: str = "stdout"):
            if on_output:
                on_output(msg, stream)

        emit(f"[*] Starting SQLMap injection check against: {target_url}\n", "system")
        emit(f"[*] Scope validated: {scope_check.reason}\n", "stdout")

        # 4. Execute Command
        result: ProcessExecutionResult = self.runner.run(
            cmd,
            timeout=options.timeout,
            on_output=on_output,
        )

        execution.status = result.status
        execution.exit_code = result.exit_code
        execution.duration_seconds = result.duration_seconds

        # 5. Parse Findings from Output
        findings = self.parse_sqlmap_output(
            stdout_text=result.stdout,
            target_url=target_url,
            project_id=project_id,
            execution_id=execution.id,
        )

        # 6. Save Findings in DB
        for f in findings:
            self.db.create_finding(f)

        # 7. Vault Evidence
        if evidence_dir and result.stdout:
            evidence_dir.mkdir(parents=True, exist_ok=True)
            ev_file = evidence_dir / f"sqlmap_exec_{execution.id}.log"
            ev_file.write_text(result.stdout, encoding="utf-8")
            sha256 = hashlib.sha256(result.stdout.encode("utf-8")).hexdigest()

            execution.raw_output_path = str(ev_file)
            self.db.add_evidence(
                Evidence(
                    project_id=project_id,
                    execution_id=execution.id,
                    file_path=str(ev_file),
                    sha256_hash=sha256,
                    description=f"SQLMap raw execution output for {target_url}",
                    mime_type="text/plain",
                )
            )

        self.db.update_execution(execution)
        emit(f"[+] SQLMap completed with status: {result.status.value}. {len(findings)} findings recorded.\n", "success")

        return True, "Success", findings, execution

    @staticmethod
    def parse_sqlmap_output(
        stdout_text: str,
        target_url: str,
        project_id: int,
        execution_id: Optional[int] = None,
    ) -> List[Finding]:
        """Parses injection details and DBMS info from SQLMap stdout text."""
        findings: List[Finding] = []

        # Check for confirmed injection
        # Look for pattern:
        # Parameter: id (GET)
        #    Type: boolean-based blind
        #    Title: AND boolean-based blind - WHERE or HAVING clause
        #    Payload: id=1 AND 5258=5258
        param_blocks = re.findall(
            r"Parameter:\s+(\w+)\s+\(([^)]+)\)\s+Type:\s+([^\n]+)\s+Title:\s+([^\n]+)\s+Payload:\s+([^\n]+)",
            stdout_text,
            re.MULTILINE,
        )

        for param, p_type, inj_type, title, payload in param_blocks:
            findings.append(
                Finding(
                    project_id=project_id,
                    title=f"SQL Injection in parameter '{param}' ({p_type}): {title.strip()}",
                    severity=FindingSeverity.CRITICAL,
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    affected_asset=urlparse(target_url).hostname or target_url,
                    affected_port_service="Web / Database",
                    description=(
                        f"SQLMap confirmed an exploitable SQL injection vulnerability in parameter '{param}' "
                        f"via {p_type}. Injection type: {inj_type.strip()}."
                    ),
                    reproduction_steps=f"Target URL: {target_url}\nParameter: {param}\nPayload: {payload.strip()}",
                    remediation=(
                        "Implement parameterized queries (Prepared Statements) or use an Object-Relational "
                        "Mapper (ORM) with automated escaping. Never concatenate untrusted user input directly into SQL strings."
                    ),
                    validation_status=ValidationStatus.CONFIRMED,
                    source_tool="sqlmap",
                    execution_id=execution_id,
                )
            )

        # Fallback heuristic: check if sqlmap identified DBMS
        dbms_match = re.search(r"the back-end DBMS is\s+([^\n]+)", stdout_text, re.IGNORECASE)
        if dbms_match and not findings:
            dbms_name = dbms_match.group(1).strip()
            findings.append(
                Finding(
                    project_id=project_id,
                    title=f"Back-End DBMS Fingerprinted: {dbms_name}",
                    severity=FindingSeverity.LOW,
                    cvss_score=3.1,
                    affected_asset=urlparse(target_url).hostname or target_url,
                    affected_port_service="Web / Database",
                    description=f"SQLMap successfully fingerprinted the back-end database management system as: {dbms_name}.",
                    remediation="Suppress verbose database error messages and remove server identification banners.",
                    validation_status=ValidationStatus.CONFIRMED,
                    source_tool="sqlmap",
                    execution_id=execution_id,
                )
            )

        return findings

