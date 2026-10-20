"""Gobuster Directory and Endpoint Brute-Forcing Adapter.

Safely invokes the open-source Gobuster engine (host binary /usr/bin/gobuster),
enforces pre-execution target scope authorization, streams discovered paths in real time,
and persists valid endpoints and sensitive paths as structured findings in SQLite.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
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
class GobusterOptions:
    target_url: str
    wordlist_path: Optional[str] = None
    threads: int = 10
    timeout: float = 60.0
    extensions: Optional[str] = None


@dataclass
class DiscoveredEndpoint:
    path: str
    status_code: int
    size: Optional[int] = None
    redirect_url: Optional[str] = None


class GobusterAdapter:
    """Orchestrates authorized Gobuster endpoint enumeration with scope guard and persistence."""

    DEFAULT_FALLBACK_WORDS = [
        "admin", "login", "api", "dashboard", "robots.txt",
        ".git", "backup", "config", "test", "v1", "v2",
        "portal", "console", "server-status", "health",
        "swagger", "openapi.json", "env", ".env", "uploads",
    ]

    def __init__(self, db: Database, registry: Optional[ToolRegistry] = None):
        self.db = db
        self.registry = registry or ToolRegistry()
        self.runner = ProcessRunner()

    def resolve_wordlist(self, user_path: Optional[str] = None) -> Tuple[str, bool]:
        """Resolves an existing wordlist on the host or generates a safe temporary one.
        
        Returns (resolved_path, is_temporary).
        """
        if user_path and Path(user_path).is_file():
            return user_path, False

        # Known standard wordlists on Linux/Debian/Ubuntu
        candidates = [
            "/usr/share/dirb/wordlists/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
        ]
        for c in candidates:
            if Path(c).is_file():
                return c, False

        # Create temporary fallback wordlist
        tmp = tempfile.NamedTemporaryFile("w+", suffix=".txt", delete=False)
        tmp.write("\n".join(self.DEFAULT_FALLBACK_WORDS) + "\n")
        tmp.flush()
        tmp.close()
        return tmp.name, True

    def build_command(self, options: GobusterOptions, wordlist_file: str) -> List[str]:
        """Constructs safe argument list for Gobuster directory scan."""
        base_cmd = self.registry.resolve_command("gobuster", [])
        cmd = list(base_cmd)
        cmd.extend([
            "dir",
            "-u", options.target_url,
            "-w", wordlist_file,
            "-q",
            "--no-color",
            "-t", str(max(1, min(options.threads, 50))),
        ])
        if options.extensions:
            cmd.extend(["-x", options.extensions])
        return cmd

    def cancel(self) -> bool:
        return self.runner.cancel()

    def parse_output(self, output: str) -> List[DiscoveredEndpoint]:
        """Parses Gobuster standard output lines into structured endpoints."""
        endpoints: List[DiscoveredEndpoint] = []
        clean_text = re.sub(r"\x1b\[[0-9;]*m", "", output)

        for line in clean_text.splitlines():
            line = line.strip()
            if not line or line.startswith("=") or line.startswith("[+]"):
                continue

            # Example: "/admin (Status: 301) [Size: 178] [--> http://127.0.0.1/admin/]"
            # Or: "/login (Status: 200) [Size: 4523]"
            match = re.search(
                r"^([^\s]+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?(?:\s+\[-->\s*([^\s\]]+)\])?",
                line,
            )
            if match:
                path = match.group(1).strip()
                status_code = int(match.group(2))
                size = int(match.group(3)) if match.group(3) else None
                redirect_url = match.group(4).strip() if match.group(4) else None
                endpoints.append(
                    DiscoveredEndpoint(
                        path=path,
                        status_code=status_code,
                        size=size,
                        redirect_url=redirect_url,
                    )
                )

        return endpoints

    def execute_scan(
        self,
        project_id: int,
        options: GobusterOptions,
        scopes: List[TargetScope],
        on_output: Optional[Callable[[str, str], None]] = None,
        evidence_dir: Optional[Path] = None,
    ) -> Tuple[bool, str, List[Finding], Optional[ToolExecution]]:
        """Validates scope, runs Gobuster in background subprocess, and parses findings."""
        target_url = options.target_url.strip()
        parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
        host = parsed.hostname or target_url

        # 1. Scope Authorization Check
        scope_check: ScopeCheckResult = ScopeAuthorizationService.is_target_authorized(host, scopes)
        if not scope_check.is_allowed:
            if on_output:
                on_output(f"[SCOPE REJECTED] Target '{host}' is outside authorized scope: {scope_check.reason}\n", "stderr")
            return False, f"Target out of scope: {scope_check.reason}", [], None

        # 2. Resolve Wordlist
        wordlist_path, is_temp = self.resolve_wordlist(options.wordlist_path)

        try:
            command = self.build_command(options, wordlist_path)
        except Exception as exc:
            if is_temp and os.path.exists(wordlist_path):
                os.unlink(wordlist_path)
            return False, f"Command resolution failed: {exc}", [], None

        # 3. Create ToolExecution record in SQLite
        tool_exec = ToolExecution(
            project_id=project_id,
            tool_name="gobuster",
            command=" ".join(command),
            status=ExecutionStatus.RUNNING,
        )
        saved_exec = self.db.create_tool_execution(tool_exec)

        # 4. Execute via ProcessRunner
        try:
            proc_result: ProcessExecutionResult = self.runner.run(
                command=command,
                timeout=options.timeout,
                on_output=on_output,
            )
        finally:
            if is_temp and os.path.exists(wordlist_path):
                try:
                    os.unlink(wordlist_path)
                except OSError:
                    pass

        saved_exec.finished_at = proc_result.finished_at
        saved_exec.status = proc_result.status
        saved_exec.exit_code = proc_result.exit_code
        self.db.update_tool_execution(saved_exec)

        full_output = proc_result.stdout + "\n" + proc_result.stderr

        # 5. Save cryptographic raw evidence file
        if evidence_dir:
            evidence_dir.mkdir(parents=True, exist_ok=True)
            ev_file = evidence_dir / f"gobuster_exec_{saved_exec.id}.log"
            ev_file.write_text(full_output, encoding="utf-8")
            sha256 = hashlib.sha256(full_output.encode("utf-8")).hexdigest()

            evidence = Evidence(
                project_id=project_id,
                execution_id=saved_exec.id,
                file_path=str(ev_file),
                file_hash=sha256,
                description=f"Gobuster directory fuzzing output for {target_url}",
            )
            self.db.create_evidence(evidence)

        # 6. Parse discovered endpoints and persist findings
        endpoints = self.parse_output(proc_result.stdout)
        findings: List[Finding] = []

        sensitive_patterns = [r"\.git", r"\.env", r"backup", r"config", r"swagger", r"admin"]

        for ep in endpoints:
            is_sensitive = any(re.search(pat, ep.path, re.IGNORECASE) for pat in sensitive_patterns)
            severity = FindingSeverity.MEDIUM if (is_sensitive and ep.status_code == 200) else FindingSeverity.INFORMATIONAL

            title = f"Discovered Endpoint: {ep.path} (HTTP {ep.status_code})"
            description = (
                f"Web content enumeration identified endpoint '{ep.path}' with HTTP status {ep.status_code} "
                f"on target '{target_url}' (Response size: {ep.size or 'N/A'} bytes)."
            )
            if ep.redirect_url:
                description += f" Redirects to: {ep.redirect_url}"

            remediation = (
                "Ensure that access control mechanisms are enforced on administrative or sensitive endpoints. "
                "Disable directory listings and remove unnecessary backup or configuration files."
            )

            finding = Finding(
                project_id=project_id,
                execution_id=saved_exec.id,
                title=title,
                description=description,
                severity=severity,
                affected_target=f"{target_url.rstrip('/')}{ep.path}",
                remediation=remediation,
                validation_status=ValidationStatus.CONFIRMED,
            )
            created = self.db.create_finding(finding)
            findings.append(created)

        is_success = proc_result.status == ExecutionStatus.COMPLETED and proc_result.exit_code == 0
        return is_success, f"Scan finished ({len(endpoints)} endpoints discovered)", findings, saved_exec
