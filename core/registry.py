"""Tool registry and system environment discovery.

Maintains metadata, installed status, and version identification
for supported assessment tools across system PATH and local source repositories.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class ToolMetadata:
    name: str
    display_name: str
    binary_name: str
    category: str
    version_flag: str = "--version"
    description: str = ""
    fallback_source_path: Optional[str] = None
    is_python_script: bool = False
    binary_path: Optional[str] = None
    version: Optional[str] = None
    is_installed: bool = False


class ToolRegistry:
    """Discovers, inventories, and verifies security tools on the host system."""

    DEFAULT_TOOLS: List[ToolMetadata] = [
        ToolMetadata(
            name="nmap",
            display_name="Nmap Network Scanner",
            binary_name="nmap",
            category="network",
            version_flag="--version",
            description="Network exploration and security auditing tool.",
        ),
        ToolMetadata(
            name="sqlmap",
            display_name="SQLMap Injection Engine",
            binary_name="sqlmap",
            category="web",
            version_flag="--version",
            fallback_source_path="source/web/sqlmap/sqlmap.py",
            is_python_script=True,
            description="Automatic SQL injection and database takeover tool.",
        ),
        ToolMetadata(
            name="gobuster",
            display_name="Gobuster Directory/DNS Scanner",
            binary_name="gobuster",
            category="web",
            version_flag="version",
            description="Fast directory, file, DNS, and vhost busting tool written in Go.",
        ),
        ToolMetadata(
            name="hydra",
            display_name="THC-Hydra Network Logon Cracker",
            binary_name="hydra",
            category="system",
            version_flag="-h",
            description="Fast network authentication brute-forcing tool supporting numerous protocols.",
        ),
        ToolMetadata(
            name="hashcat",
            display_name="Hashcat Password Recovery",
            binary_name="hashcat",
            category="system",
            version_flag="--version",
            description="Advanced password recovery and hash cracking utility.",
        ),
        ToolMetadata(
            name="binwalk",
            display_name="Binwalk Firmware Analyzer",
            binary_name="binwalk",
            category="system",
            version_flag="--help",
            description="Firmware analysis and extraction utility.",
        ),
        ToolMetadata(
            name="john",
            display_name="John the Ripper",
            binary_name="john",
            category="system",
            version_flag="--help",
            description="Rapid password cracking tool.",
        ),
        ToolMetadata(
            name="volatility3",
            display_name="Volatility 3 Memory Forensics",
            binary_name="vol.py",
            category="system",
            version_flag="--help",
            fallback_source_path="source/system/volatility3/vol.py",
            is_python_script=True,
            description="Memory forensics analysis framework.",
        ),
        ToolMetadata(
            name="zaproxy",
            display_name="OWASP ZAP",
            binary_name="zap.sh",
            category="web",
            version_flag="-version",
            description="Integrated penetration testing tool for web applications.",
        ),
        ToolMetadata(
            name="nuclei",
            display_name="Nuclei Vulnerability Scanner",
            binary_name="nuclei",
            category="vulnerability",
            version_flag="-version",
            description="Fast and customizable vulnerability scanner based on simple YAML templates.",
        ),
        ToolMetadata(
            name="ffuf",
            display_name="ffuf Fast Web Fuzzer",
            binary_name="ffuf",
            category="web",
            version_flag="-V",
            description="Fast web fuzzer written in Go.",
        ),
        ToolMetadata(
            name="gitleaks",
            display_name="Gitleaks Secret Scanner",
            binary_name="gitleaks",
            category="code_security",
            version_flag="version",
            description="Secret scanner for git repositories and files.",
        ),
        ToolMetadata(
            name="trivy",
            display_name="Trivy Vulnerability Scanner",
            binary_name="trivy",
            category="code_security",
            version_flag="--version",
            description="Vulnerability and misconfiguration scanner for containers and repos.",
        ),
        ToolMetadata(
            name="tshark",
            display_name="TShark Network Packet Analyzer",
            binary_name="tshark",
            category="network",
            version_flag="--version",
            description="Network protocol analyzer and terminal version of Wireshark.",
        ),
    ]

    def __init__(self, tools: Optional[List[ToolMetadata]] = None):
        self._tools: Dict[str, ToolMetadata] = {
            t.name: t for t in (tools or self.DEFAULT_TOOLS)
        }
        self.refresh()

    def refresh(self) -> None:
        """Scan system PATH and local fallback source paths to discover tools and versions."""
        for tool in self._tools.values():
            found_path = shutil.which(tool.binary_name)
            if found_path:
                tool.binary_path = found_path
                tool.is_installed = True
                tool.version = self._detect_version(found_path, tool.version_flag)
            elif tool.fallback_source_path and Path(tool.fallback_source_path).is_file():
                resolved = str(Path(tool.fallback_source_path).resolve())
                tool.binary_path = resolved
                tool.is_installed = True
                if tool.is_python_script:
                    tool.version = self._detect_python_script_version(resolved, tool.version_flag)
                else:
                    tool.version = self._detect_version(resolved, tool.version_flag)
            else:
                tool.binary_path = None
                tool.is_installed = False
                tool.version = None

    @staticmethod
    def _detect_version(binary_path: str, version_flag: str) -> Optional[str]:
        try:
            res = subprocess.run(
                [binary_path, version_flag],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            output = res.stdout.strip() or res.stderr.strip()
            if output:
                return output.splitlines()[0]
        except (subprocess.SubprocessError, OSError):
            pass
        return None

    @staticmethod
    def _detect_python_script_version(script_path: str, version_flag: str) -> Optional[str]:
        try:
            res = subprocess.run(
                [sys.executable, script_path, version_flag],
                capture_output=True,
                text=True,
                timeout=4,
                check=False,
            )
            output = res.stdout.strip() or res.stderr.strip()
            if output:
                return output.splitlines()[0]
        except (subprocess.SubprocessError, OSError):
            pass
        return None

    def get_tool(self, name: str) -> Optional[ToolMetadata]:
        return self._tools.get(name)

    def is_available(self, name: str) -> bool:
        tool = self.get_tool(name)
        return tool.is_installed if tool else False

    def list_tools(self) -> List[ToolMetadata]:
        return list(self._tools.values())

    def list_installed_tools(self) -> List[ToolMetadata]:
        return [t for t in self._tools.values() if t.is_installed]

    def resolve_command(self, tool_name: str, args: List[str]) -> List[str]:
        """Resolves tool executable into a safe argument list with shell=False."""
        tool = self.get_tool(tool_name)
        if not tool or not tool.is_installed or not tool.binary_path:
            raise FileNotFoundError(f"Security tool '{tool_name}' is not installed or available.")

        if tool.is_python_script:
            return [sys.executable, tool.binary_path] + args
        return [tool.binary_path] + args
