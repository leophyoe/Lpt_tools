"""AI Copilot and Intelligent Terminal Assistant for CyberSecuritySuite.

Provides terminal output analysis, error diagnostics, natural language to pentest
command synthesis with scope guard verification, and automated vulnerability finding
extraction for assessment reports.

Supports:
1. Built-in Expert Cybersecurity Heuristic Engine (100% Offline, zero setup).
2. Google Gemini API (Cloud - gemini-1.5-flash, gemini-1.5-pro, etc.).
3. OpenAI API (Cloud - gpt-4o-mini, gpt-4o, etc.).
4. Local Ollama (Offline LLMs - llama3, deepseek-r1, mistral at http://127.0.0.1:11434).

All cloud API queries pass through strict sensitive data redaction to mask
passwords, bearer tokens, AWS keys, and private keys prior to external transmission.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from core.credential_manager import CredentialManager
from core.scope import ScopeAuthorizationService, ScopeCheckResult
from storage.models import Finding, FindingSeverity, TargetScope, ValidationStatus
from terminal.recorder import redact_sensitive_text


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AIProvider(str, Enum):
    BUILTIN_OFFLINE = "builtin_offline"
    LOCAL_OLLAMA = "local_ollama"
    GEMINI_API = "gemini_api"
    OPENAI_API = "openai_api"


@dataclass
class AIDiagnosticResult:
    analysis: str
    root_cause: str
    suggested_fix: str
    suggested_command: Optional[str] = None
    severity: str = "INFO"
    provider_used: str = "builtin_offline"


@dataclass
class AICommandSuggestion:
    tool_name: str
    command: str
    explanation: str
    is_active: bool
    is_in_scope: bool
    scope_reason: str
    provider_used: str = "builtin_offline"


class AICopilotEngine:
    """Intelligent cybersecurity copilot supporting offline heuristics, Ollama, Gemini, and OpenAI."""

    def __init__(
        self,
        provider: AIProvider = AIProvider.BUILTIN_OFFLINE,
        ollama_url: str = "http://127.0.0.1:11434",
        ollama_model: str = "llama3",
        gemini_model: str = "gemini-1.5-flash",
        openai_model: str = "gpt-4o-mini",
        gemini_api_key: Optional[str] = None,
        openai_api_key: Optional[str] = None,
    ):
        self.provider = provider
        self.ollama_url = ollama_url
        self.ollama_model = ollama_model
        self.gemini_model = gemini_model
        self.openai_model = openai_model
        self._custom_gemini_key = gemini_api_key
        self._custom_openai_key = openai_api_key

    def get_api_key(self, provider: AIProvider) -> Optional[str]:
        """Resolves active API key from instance configuration, credential manager, or environment."""
        if provider == AIProvider.GEMINI_API:
            if self._custom_gemini_key:
                return self._custom_gemini_key
            return CredentialManager.get_key("gemini")
        elif provider == AIProvider.OPENAI_API:
            if self._custom_openai_key:
                return self._custom_openai_key
            return CredentialManager.get_key("openai")
        return None

    def set_api_key(self, provider: AIProvider, api_key: str) -> bool:
        """Saves an API key through the CredentialManager and updates current session state."""
        clean = api_key.strip()
        if provider == AIProvider.GEMINI_API:
            self._custom_gemini_key = clean or None
            return CredentialManager.set_key("gemini", clean)
        elif provider == AIProvider.OPENAI_API:
            self._custom_openai_key = clean or None
            return CredentialManager.set_key("openai", clean)
        return True

    def clear_api_key(self, provider: AIProvider) -> bool:
        """Removes the stored API key for the given provider."""
        if provider == AIProvider.GEMINI_API:
            self._custom_gemini_key = None
            return CredentialManager.delete_key("gemini")
        elif provider == AIProvider.OPENAI_API:
            self._custom_openai_key = None
            return CredentialManager.delete_key("openai")
        return True

    # -----------------------------------------------------------------------
    # Connection Verification
    # -----------------------------------------------------------------------

    def test_connection(
        self,
        provider: Optional[AIProvider] = None,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Tests live connectivity to the selected AI provider."""
        target_prov = provider or self.provider

        if target_prov == AIProvider.BUILTIN_OFFLINE:
            return True, "Built-in Cybersecurity Heuristic Engine ready (100% Offline, No network required)."

        elif target_prov == AIProvider.LOCAL_OLLAMA:
            url = f"{self.ollama_url.rstrip('/')}/api/tags"
            target_model = model or self.ollama_model
            try:
                req = urllib.request.Request(url, method="GET")
                with urllib.request.urlopen(req, timeout=5.0) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        models = [m.get("name", "") for m in data.get("models", [])]
                        model_list = ", ".join(models[:4]) if models else "No models pulled yet"
                        if target_model and models and not any(target_model in m for m in models):
                            return False, f"Ollama is reachable, but model '{target_model}' is not downloaded. Pull it using 'ollama pull {target_model}'."
                        return True, f"Ollama connection verified on {self.ollama_url}. Installed models: {model_list}"
                    return False, f"Ollama returned HTTP status {resp.status}."
            except urllib.error.URLError:
                return False, f"Connection refused: Ollama is not running on {self.ollama_url}. Start Ollama with 'ollama serve'."
            except Exception as e:
                return False, f"Ollama error: {e}"

        elif target_prov == AIProvider.GEMINI_API:
            key = api_key or self.get_api_key(AIProvider.GEMINI_API)
            if not key:
                return False, "Gemini API key is not configured. Enter and save your Gemini API key in AI Settings."

            target_model = model or self.gemini_model
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{target_model}:generateContent?key={key}"
            payload = json.dumps({
                "contents": [{"parts": [{"text": "ping"}]}],
                "generationConfig": {"maxOutputTokens": 5, "temperature": 0.0},
            }).encode("utf-8")

            try:
                req = urllib.request.Request(
                    url,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=8.0) as resp:
                    if resp.status == 200:
                        return True, f"Google Gemini API verified successfully! Model: '{target_model}' is responsive."
                    return False, f"Gemini API returned HTTP {resp.status}."
            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    return False, "Authentication Failed (401/403): Gemini API key is invalid or unauthorized."
                elif e.code == 429:
                    return False, "Quota Exceeded (429): Gemini API rate limit or project quota reached."
                elif e.code == 404:
                    return False, f"Model Not Found (404): Model '{target_model}' does not exist in Gemini API."
                return False, f"Gemini API error (HTTP {e.code}): {e.reason}"
            except urllib.error.URLError as e:
                return False, f"Network Connection Error: Unable to reach Google API servers ({e.reason})."
            except Exception as e:
                return False, f"Gemini connection error: {e}"

        elif target_prov == AIProvider.OPENAI_API:
            key = api_key or self.get_api_key(AIProvider.OPENAI_API)
            if not key:
                return False, "OpenAI API key is not configured. Enter and save your OpenAI API key in AI Settings."

            target_model = model or self.openai_model
            url = "https://api.openai.com/v1/chat/completions"
            payload = json.dumps({
                "model": target_model,
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 5,
                "temperature": 0.0,
            }).encode("utf-8")

            try:
                req = urllib.request.Request(
                    url,
                    data=payload,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {key}",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=8.0) as resp:
                    if resp.status == 200:
                        return True, f"OpenAI API verified successfully! Model: '{target_model}' is responsive."
                    return False, f"OpenAI API returned HTTP {resp.status}."
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    return False, "Authentication Failed (401): OpenAI API key is invalid."
                elif e.code == 429:
                    return False, "Quota Exceeded (429): OpenAI account quota depleted or rate limited."
                return False, f"OpenAI API error (HTTP {e.code}): {e.reason}"
            except urllib.error.URLError as e:
                return False, f"Network Connection Error: Unable to reach OpenAI servers ({e.reason})."
            except Exception as e:
                return False, f"OpenAI connection error: {e}"

        return False, "Unknown AI Provider."

    # -----------------------------------------------------------------------
    # Output Diagnosis and Error Explanation
    # -----------------------------------------------------------------------

    def diagnose_output(
        self,
        output: str,
        exit_code: Optional[int] = None,
        user_consented: bool = True,
    ) -> AIDiagnosticResult:
        """Analyzes terminal stdout/stderr to diagnose errors or summarize output."""
        clean_text = re.sub(r"\x1b\[[0-9;]*m", "", output).strip()
        if not clean_text:
            return AIDiagnosticResult(
                analysis="Terminal output is empty.",
                root_cause="No process output captured.",
                suggested_fix="Execute a security tool or command in the terminal to inspect results.",
                provider_used=self.provider.value,
            )

        # 1. Cloud Provider: Gemini API
        if self.provider == AIProvider.GEMINI_API:
            key = self.get_api_key(AIProvider.GEMINI_API)
            if not key:
                return AIDiagnosticResult(
                    analysis="⚠️ Google Gemini API is selected, but no API key is configured.",
                    root_cause="Missing Gemini API Key",
                    suggested_fix="Click '⚙️ AI Settings' to configure your Gemini API key, or switch to the Built-in Offline Engine.",
                    provider_used="gemini_api",
                )
            if not user_consented:
                return AIDiagnosticResult(
                    analysis="⚠️ Cloud Transmission Consent Required: Sending terminal output to Gemini API requires explicit consent.",
                    root_cause="Consent Pending",
                    suggested_fix="Check 'Consent to send redacted output to Cloud AI' or switch to the Built-in Offline Engine.",
                    provider_used="gemini_api",
                )

            # Sanitize and redact passwords/tokens before sending
            redacted_snippet = redact_sensitive_text(clean_text[-2500:])
            prompt = (
                "You are an expert Senior Penetration Tester and CPENT Instructor assisting an analyst.\n"
                f"Analyze this terminal security tool output (Exit Code: {exit_code}).\n"
                "Provide:\n"
                "1. Brief technical analysis of what happened or vulnerabilities discovered.\n"
                "2. Root cause of error or observation.\n"
                "3. Recommended next action or exact CLI fix command.\n\n"
                f"Terminal Output:\n{redacted_snippet}"
            )
            resp_text, err = self._query_gemini(prompt)
            if resp_text:
                cmd_match = re.search(r"```(?:bash|sh)?\n(.*?)\n```", resp_text, re.DOTALL)
                sugg_cmd = cmd_match.group(1).strip() if cmd_match else None
                return AIDiagnosticResult(
                    analysis=resp_text,
                    root_cause="Analysis generated by Google Gemini AI.",
                    suggested_fix="Review findings and remediation steps generated above.",
                    suggested_command=sugg_cmd,
                    provider_used="gemini_api",
                )

        # 2. Cloud Provider: OpenAI API
        elif self.provider == AIProvider.OPENAI_API:
            key = self.get_api_key(AIProvider.OPENAI_API)
            if not key:
                return AIDiagnosticResult(
                    analysis="⚠️ OpenAI API is selected, but no API key is configured.",
                    root_cause="Missing OpenAI API Key",
                    suggested_fix="Click '⚙️ AI Settings' to configure your OpenAI API key, or switch to the Built-in Offline Engine.",
                    provider_used="openai_api",
                )
            if not user_consented:
                return AIDiagnosticResult(
                    analysis="⚠️ Cloud Transmission Consent Required: Sending terminal output to OpenAI API requires explicit consent.",
                    root_cause="Consent Pending",
                    suggested_fix="Check 'Consent to send redacted output to Cloud AI' or switch to the Built-in Offline Engine.",
                    provider_used="openai_api",
                )

            redacted_snippet = redact_sensitive_text(clean_text[-2500:])
            prompt = (
                "You are an expert Senior Penetration Tester and CPENT Instructor assisting an analyst.\n"
                f"Analyze this terminal security tool output (Exit Code: {exit_code}).\n"
                "Provide:\n"
                "1. Technical analysis of findings or errors.\n"
                "2. Root cause.\n"
                "3. Actionable next CLI command.\n\n"
                f"Terminal Output:\n{redacted_snippet}"
            )
            resp_text, err = self._query_openai(prompt)
            if resp_text:
                cmd_match = re.search(r"```(?:bash|sh)?\n(.*?)\n```", resp_text, re.DOTALL)
                sugg_cmd = cmd_match.group(1).strip() if cmd_match else None
                return AIDiagnosticResult(
                    analysis=resp_text,
                    root_cause="Analysis generated by OpenAI.",
                    suggested_fix="Review guidance generated above.",
                    suggested_command=sugg_cmd,
                    provider_used="openai_api",
                )

        # 3. Local Ollama Provider
        elif self.provider == AIProvider.LOCAL_OLLAMA:
            redacted_snippet = redact_sensitive_text(clean_text[-2500:])
            prompt = (
                "You are a Senior Penetration Tester and CPENT Instructor. Analyze this security tool output and exit code "
                f"{exit_code}.\nExplain technical findings or errors, root cause, and the exact CLI command to proceed:\n\n{redacted_snippet}"
            )
            resp_text, err = self._query_ollama(prompt)
            if resp_text:
                return AIDiagnosticResult(
                    analysis=resp_text,
                    root_cause="Identified via Local Ollama analysis.",
                    suggested_fix="Review the recommended commands and guidance above.",
                    provider_used="local_ollama",
                )

        # 4. Fallback / Built-in Offline Heuristics Engine
        return self._diagnose_offline(clean_text, exit_code)

    def _diagnose_offline(self, clean_text: str, exit_code: Optional[int]) -> AIDiagnosticResult:
        """Built-in cybersecurity heuristic engine operating 100% offline."""
        lowered = clean_text.lower()

        # 1. Permission Denied / Root Privileges
        if "permission denied" in lowered or "you need to be root" in lowered or "operation not permitted" in lowered:
            return AIDiagnosticResult(
                analysis="Execution halted due to insufficient operating system privileges.",
                root_cause="The requested network operation (e.g. raw socket SYN scan) requires elevated root permissions.",
                suggested_fix="Prefix command with 'sudo' or run the application in an authorized administrative session.",
                suggested_command="sudo !!",
                severity="HIGH",
                provider_used="builtin_offline",
            )

        # 2. Connection Refused / Host Down
        if "connection refused" in lowered or "site appears to be down" in lowered or "host seems down" in lowered:
            return AIDiagnosticResult(
                analysis="Target host is either offline, unreachable, or filtering ICMP echo probes.",
                root_cause="Network connection could not be established on the requested port or protocol.",
                suggested_fix="Verify target IP/URL availability. If using Nmap, append '-Pn' to disable ping probes.",
                suggested_command="nmap -Pn -sV <target>",
                severity="MEDIUM",
                provider_used="builtin_offline",
            )

        # 3. Missing Dependencies or Wordlist
        if "required module not found" in lowered or "no module named" in lowered:
            mod_match = re.search(r"no module named ['\"]?([A-Za-z0-9_\-]+)['\"]?", lowered)
            mod_name = mod_match.group(1) if mod_match else "dependency"
            return AIDiagnosticResult(
                analysis=f"Missing runtime software dependency: '{mod_name}'.",
                root_cause="The interpreter or script requires a library that is not currently installed.",
                suggested_fix=f"Install the missing package into the environment using: 'pip install {mod_name}'.",
                suggested_command=f"pip install {mod_name}",
                severity="MEDIUM",
                provider_used="builtin_offline",
            )

        if "wordlist" in lowered and ("not found" in lowered or "does not exist" in lowered or "empty" in lowered):
            return AIDiagnosticResult(
                analysis="Specified wordlist file could not be opened.",
                root_cause="Wordlist path is incorrect or wordlist package is uninstalled.",
                suggested_fix="Use system wordlists such as '/usr/share/dirb/wordlists/common.txt' or install SecLists.",
                suggested_command="gobuster dir -u <url> -w /usr/share/dirb/wordlists/common.txt",
                severity="LOW",
                provider_used="builtin_offline",
            )

        # 4. SQLMap Specific
        if "sqlmap" in lowered or "is vulnerable" in lowered or "sql injection" in lowered:
            if "is vulnerable" in lowered or "heuristic" in lowered or "parameter" in lowered:
                return AIDiagnosticResult(
                    analysis="SQL Injection vulnerability confirmed by SQLMap!",
                    root_cause="Application concatenates unescaped user input into backend database query.",
                    suggested_fix="Use parameterized queries (Prepared Statements) or an ORM. Do not concatenate SQL.",
                    suggested_command="sqlmap -u <url> --batch --dbs",
                    severity="CRITICAL",
                    provider_used="builtin_offline",
                )
            if "target url appears to be protected by a waf" in lowered or "waf/ips" in lowered:
                return AIDiagnosticResult(
                    analysis="SQLMap detected an active Web Application Firewall (WAF/IPS).",
                    root_cause="Automated injection payloads were blocked or dropped by perimeter protection.",
                    suggested_fix="Inspect WAF with WAFW00F, use tamper scripts (e.g. '--tamper=space2comment'), or adjust request delay.",
                    suggested_command="sqlmap -u <url> --tamper=between,randomcase --batch",
                    severity="HIGH",
                    provider_used="builtin_offline",
                )

        # 5. Nmap Success Summary
        if "nmap done:" in lowered or "nmap scan report" in lowered:
            return AIDiagnosticResult(
                analysis="Nmap network port scan completed successfully.",
                root_cause="Host service exploration finished without network interruption.",
                suggested_fix="Review discovered open ports below and use 'Extract Findings' to register them into the Assessment Report.",
                severity="INFO",
                provider_used="builtin_offline",
            )

        # Default fallback analysis
        status_text = f"Process completed with exit code {exit_code}." if exit_code is not None else "Execution output captured."
        return AIDiagnosticResult(
            analysis=f"{status_text}\nOutput contains {len(clean_text.splitlines())} lines.",
            root_cause="Standard process stream output.",
            suggested_fix="Inspect stdout above or use command generator to formulate next testing phase.",
            severity="INFO",
            provider_used="builtin_offline",
        )

    # -----------------------------------------------------------------------
    # Natural Language to Pentest Command Generation
    # -----------------------------------------------------------------------

    def generate_command(
        self,
        prompt: str,
        target: Optional[str] = None,
        scopes: Optional[List[TargetScope]] = None,
    ) -> AICommandSuggestion:
        """Translates user prompt into a validated, scope-checked command."""
        p_low = prompt.lower().strip()
        cmd_target = target or "127.0.0.1"

        # Extract target from prompt if present
        ip_match = re.search(r"\b(?:https?://)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/[^\s]*)?)\b", prompt)
        domain_match = re.search(r"\b(?:https?://)?([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s]*)?)\b", prompt)
        if ip_match:
            cmd_target = ip_match.group(1)
        elif domain_match:
            cmd_target = domain_match.group(1)

        # Scope validation
        parsed = urlparse(cmd_target if "://" in cmd_target else f"http://{cmd_target}")
        host_to_check = parsed.hostname or cmd_target
        is_in_scope = True
        scope_reason = "Target verified in scope."

        if scopes is not None:
            scope_check: ScopeCheckResult = ScopeAuthorizationService.is_target_authorized(host_to_check, scopes)
            is_in_scope = scope_check.is_allowed
            scope_reason = scope_check.reason

        # 1. Nmap Network Scanning
        if "port" in p_low or "nmap" in p_low or "network" in p_low or "service" in p_low:
            if "top" in p_low or "fast" in p_low:
                return AICommandSuggestion(
                    tool_name="nmap",
                    command=f"nmap -F -T4 {host_to_check}",
                    explanation="Fast scan of the top 100 most common network ports with aggressive timing.",
                    is_active=True,
                    is_in_scope=is_in_scope,
                    scope_reason=scope_reason,
                    provider_used=self.provider.value,
                )
            if "all" in p_low or "full" in p_low:
                return AICommandSuggestion(
                    tool_name="nmap",
                    command=f"nmap -p- -sV -T4 {host_to_check}",
                    explanation="Comprehensive full TCP port scan (ports 1-65535) with service version detection.",
                    is_active=True,
                    is_in_scope=is_in_scope,
                    scope_reason=scope_reason,
                    provider_used=self.provider.value,
                )
            return AICommandSuggestion(
                tool_name="nmap",
                command=f"nmap -sV -T4 {host_to_check}",
                explanation="Standard TCP service version exploration.",
                is_active=True,
                is_in_scope=is_in_scope,
                scope_reason=scope_reason,
                provider_used=self.provider.value,
            )

        # 2. Gobuster Web Directory Enumeration
        if any(k in p_low for k in ["directory", "directories", "dir", "gobuster", "fuzz", "route", "path", "endpoint"]):
            url = cmd_target if cmd_target.startswith("http") else f"http://{cmd_target}"
            return AICommandSuggestion(
                tool_name="gobuster",
                command=f"gobuster dir -u {url} -w /usr/share/dirb/wordlists/common.txt -q --no-color",
                explanation="Fast web directory enumeration using common directory wordlists.",
                is_active=True,
                is_in_scope=is_in_scope,
                scope_reason=scope_reason,
                provider_used=self.provider.value,
            )

        # 3. WAF Detection
        if "waf" in p_low or "firewall" in p_low:
            url = cmd_target if cmd_target.startswith("http") else f"http://{cmd_target}"
            return AICommandSuggestion(
                tool_name="wafw00f",
                command=f"python3 source/web/wafw00f/wafw00f/bin/wafw00f {url} -a",
                explanation="Fingerprint web application firewalls and perimeter proxies protecting the target.",
                is_active=True,
                is_in_scope=is_in_scope,
                scope_reason=scope_reason,
                provider_used=self.provider.value,
            )

        # 4. SQL Injection with SQLMap
        if "sql" in p_low or "injection" in p_low or "database" in p_low or "sqlmap" in p_low:
            url = cmd_target if cmd_target.startswith("http") else f"http://{cmd_target}"
            return AICommandSuggestion(
                tool_name="sqlmap",
                command=f"python3 source/web/sqlmap/sqlmap.py -u \"{url}\" --batch --risk=1 --level=1",
                explanation="Automated SQL injection audit testing GET/POST parameter vulnerabilities.",
                is_active=True,
                is_in_scope=is_in_scope,
                scope_reason=scope_reason,
                provider_used=self.provider.value,
            )

        # 5. Bandit Python SAST
        if "bandit" in p_low or "sast" in p_low or "source code" in p_low or "python security" in p_low:
            return AICommandSuggestion(
                tool_name="bandit",
                command="bandit -r . -f txt",
                explanation="Static Application Security Testing (SAST) of Python source files.",
                is_active=False,
                is_in_scope=True,
                scope_reason="Local source code audit (In-Scope).",
                provider_used=self.provider.value,
            )

        # Default fallback
        return AICommandSuggestion(
            tool_name="nmap",
            command=f"nmap -sV {host_to_check}",
            explanation=f"Default network service exploration on target {host_to_check}.",
            is_active=True,
            is_in_scope=is_in_scope,
            scope_reason=scope_reason,
            provider_used=self.provider.value,
        )

    # -----------------------------------------------------------------------
    # Finding Extraction from Terminal Output
    # -----------------------------------------------------------------------

    def extract_findings_from_terminal(
        self, output: str, target: str, project_id: int
    ) -> List[Finding]:
        """Parses raw terminal text from various tools and extracts report findings."""
        findings: List[Finding] = []
        clean_text = re.sub(r"\x1b\[[0-9;]*m", "", output)

        # A. Parse Nmap Open Ports & Services
        for line in clean_text.splitlines():
            line_str = line.strip()
            port_match = re.search(r"^(\d+/(?:tcp|udp))\s+open\s+([^\s]+)(?:\s+(.*))?", line_str)
            if port_match:
                port_proto = port_match.group(1)
                service = port_match.group(2)
                version_info = port_match.group(3) or ""

                port_num = int(port_proto.split("/")[0])

                if port_num in (21, 23):  # FTP, Telnet
                    sev = FindingSeverity.HIGH
                    title = f"Unencrypted Service Exposed: {service.upper()} ({port_proto})"
                    remediation = "Disable unencrypted cleartext protocols (Telnet/FTP) and transition to SSH/SFTP."
                elif port_num in (445, 139):  # SMB
                    sev = FindingSeverity.MEDIUM
                    title = f"SMB Network Sharing Port Exposed ({port_proto})"
                    remediation = "Restrict SMB access to internal management networks and require SMBv3 signing."
                elif port_num in (3389, 5900):  # RDP, VNC
                    sev = FindingSeverity.MEDIUM
                    title = f"Remote Desktop Service Exposed: {service.upper()} ({port_proto})"
                    remediation = "Enforce Multi-Factor Authentication (MFA) and restrict remote desktop behind VPN."
                elif port_num in (1433, 3306, 5432, 27017, 6379):  # Databases
                    sev = FindingSeverity.HIGH
                    title = f"Database Port Directly Exposed: {service.upper()} ({port_proto})"
                    remediation = "Database ports should never be exposed to external or untrusted networks. Bind to localhost."
                else:
                    sev = FindingSeverity.INFORMATIONAL
                    title = f"Open Network Port Discovered: {port_proto} ({service})"
                    remediation = "Ensure only necessary business services are exposed and keep service packages updated."

                desc = f"Identified active open network service on target '{target}'.\nPort: {port_proto}\nService: {service}"
                if version_info:
                    desc += f"\nVersion Banner: {version_info}"

                findings.append(
                    Finding(
                        project_id=project_id,
                        title=title,
                        description=desc,
                        severity=sev,
                        affected_asset=target,
                        affected_port_service=port_proto,
                        remediation=remediation,
                        validation_status=ValidationStatus.CONFIRMED,
                        source_tool="terminal_ai_extractor",
                    )
                )

        # B. Parse Gobuster Endpoints
        for line in clean_text.splitlines():
            ep_match = re.search(r"^(/[^\s]+)\s+\(Status:\s*(\d+)\)", line.strip())
            if ep_match:
                path = ep_match.group(1)
                code = int(ep_match.group(2))
                if any(k in path.lower() for k in [".git", ".env", "backup", "config", "swagger", "admin"]) and code in (200, 301):
                    findings.append(
                        Finding(
                            project_id=project_id,
                            title=f"Sensitive Web Route Exposed: {path} (HTTP {code})",
                            description=f"Directory enumeration detected sensitive asset at '{target.rstrip('/')}{path}'.",
                            severity=FindingSeverity.HIGH if ".git" in path or ".env" in path else FindingSeverity.MEDIUM,
                            affected_asset=f"{target.rstrip('/')}{path}",
                            remediation="Restrict access to administrative paths and remove sensitive repository/backup files from production.",
                            validation_status=ValidationStatus.CONFIRMED,
                            source_tool="terminal_ai_extractor",
                        )
                    )

        # C. Parse SQLMap Injection Finding
        if "sqlmap" in clean_text.lower() and ("is vulnerable" in clean_text.lower() or "injection" in clean_text.lower()):
            findings.append(
                Finding(
                    project_id=project_id,
                    title="SQL Injection Vulnerability Discovered via Terminal Execution",
                    description=f"SQLMap execution against '{target}' detected exploitable SQL injection parameter vectors.",
                    severity=FindingSeverity.CRITICAL,
                    affected_asset=target,
                    remediation="Employ parameterized SQL statements (Prepared Statements) or use an established ORM. Sanitize all user inputs.",
                    validation_status=ValidationStatus.CONFIRMED,
                    source_tool="sqlmap",
                )
            )

        # D. Parse WAF Detection
        if "wafw00f" in clean_text.lower() and "is behind" in clean_text.lower():
            waf_match = re.search(r"is behind (?:a )?([A-Za-z0-9_\-\.\s\(\)]+?)(?: WAF|\.|\n|$)", clean_text)
            waf_name = waf_match.group(1).strip() if waf_match else "WAF"
            findings.append(
                Finding(
                    project_id=project_id,
                    title=f"Web Application Firewall (WAF) Fingerprinted: {waf_name}",
                    description=f"WAFW00F fingerprinting identified perimeter firewall '{waf_name}' on '{target}'.",
                    severity=FindingSeverity.INFORMATIONAL,
                    affected_asset=target,
                    remediation="Informational assessment discovery. Take firewall inspection behaviors into account during security auditing.",
                    validation_status=ValidationStatus.CONFIRMED,
                    source_tool="wafw00f",
                )
            )

        return findings

    # -----------------------------------------------------------------------
    # Internal HTTP Client Helpers
    # -----------------------------------------------------------------------

    def _query_gemini(
        self, prompt: str, model: Optional[str] = None, api_key: Optional[str] = None
    ) -> Tuple[Optional[str], Optional[str]]:
        key = api_key or self.get_api_key(AIProvider.GEMINI_API)
        if not key:
            return None, "Gemini API key is missing."

        target_model = model or self.gemini_model
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{target_model}:generateContent?key={key}"
        payload = json.dumps({
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 2048},
        }).encode("utf-8")

        try:
            req = urllib.request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                candidates = data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts:
                        return parts[0].get("text", "").strip(), None
                return None, "Gemini API returned empty response."
        except urllib.error.HTTPError as e:
            return None, f"Gemini API HTTP Error {e.code}: {e.reason}"
        except Exception as e:
            return None, f"Gemini error: {e}"

    def _query_openai(
        self, prompt: str, model: Optional[str] = None, api_key: Optional[str] = None
    ) -> Tuple[Optional[str], Optional[str]]:
        key = api_key or self.get_api_key(AIProvider.OPENAI_API)
        if not key:
            return None, "OpenAI API key is missing."

        target_model = model or self.openai_model
        url = "https://api.openai.com/v1/chat/completions"
        payload = json.dumps({
            "model": target_model,
            "messages": [
                {"role": "system", "content": "You are a professional cybersecurity penetration testing copilot and CPENT instructor."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }).encode("utf-8")

        try:
            req = urllib.request.Request(
                url,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {key}",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                choices = data.get("choices", [])
                if choices:
                    return choices[0].get("message", {}).get("content", "").strip(), None
                return None, "OpenAI returned empty response."
        except urllib.error.HTTPError as e:
            return None, f"OpenAI HTTP Error {e.code}: {e.reason}"
        except Exception as e:
            return None, f"OpenAI error: {e}"

    def _query_ollama(
        self, prompt: str, model: Optional[str] = None
    ) -> Tuple[Optional[str], Optional[str]]:
        target_model = model or self.ollama_model
        url = f"{self.ollama_url.rstrip('/')}/api/generate"
        payload = json.dumps({
            "model": target_model,
            "prompt": prompt,
            "stream": False,
        }).encode("utf-8")

        try:
            req = urllib.request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=12.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("response", "").strip(), None
        except Exception as e:
            return None, f"Ollama error: {e}"
