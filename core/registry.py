"""Tool registry and system environment discovery.

Maintains metadata, installed status, and version identification
for supported assessment tools.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class ToolMetadata:
    name: str
    display_name: str
    binary_name: str
    category: str
    version_flag: str = "--version"
    description: str = ""
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
        """Scan system PATH and discover binaries and versions."""
        for tool in self._tools.values():
            found_path = shutil.which(tool.binary_name)
            if found_path:
                tool.binary_path = found_path
                tool.is_installed = True
                tool.version = self._detect_version(found_path, tool.version_flag)
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
            # Return first line of version output
            if output:
                return output.splitlines()[0]
        except (subprocess.SubprocessError, OSError):
            pass
        return None

    def get_tool(self, name: str) -> Optional[ToolMetadata]:
        return self._tools.get(name)

    def list_tools(self) -> List[ToolMetadata]:
        return list(self._tools.values())

    def is_available(self, name: str) -> bool:
        tool = self.get_tool(name)
        return bool(tool and tool.is_installed)
