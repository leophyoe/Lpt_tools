"""Nmap XML and raw output parser.

Converts Nmap XML scan outputs into structured Python models
and security findings.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import List, Optional

from storage.models import Finding, FindingSeverity, ValidationStatus


@dataclass
class PortResult:
    port_id: int
    protocol: str
    state: str
    service_name: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""

    @property
    def service_summary(self) -> str:
        parts = [self.service_name]
        if self.product:
            parts.append(self.product)
        if self.version:
            parts.append(self.version)
        return " ".join(filter(None, parts))


@dataclass
class HostResult:
    ip: str
    status: str
    hostname: Optional[str] = None
    ports: List[PortResult] = field(default_factory=list)


@dataclass
class NmapScanResult:
    command_args: str
    hosts: List[HostResult] = field(default_factory=list)
    raw_xml: str = ""


class NmapParser:
    """Parses standard Nmap XML (-oX) into structured data."""

    @classmethod
    def parse_xml(cls, xml_content: str) -> NmapScanResult:
        """Parse Nmap XML string into NmapScanResult."""
        if not xml_content or not xml_content.strip():
            return NmapScanResult(command_args="", raw_xml="")

        try:
            root = ET.fromstring(xml_content.strip())
        except ET.ParseError as e:
            raise ValueError(f"Invalid Nmap XML output: {e}") from e

        command_args = root.attrib.get("args", "")
        hosts: List[HostResult] = []

        for host_elem in root.findall("host"):
            # Check host status
            status_elem = host_elem.find("status")
            status = status_elem.attrib.get("state", "unknown") if status_elem is not None else "unknown"

            # Extract IP address
            ip = ""
            for addr in host_elem.findall("address"):
                if addr.attrib.get("addrtype") in ("ipv4", "ipv6"):
                    ip = addr.attrib.get("addr", "")
                    break

            if not ip:
                continue

            # Extract Hostname if available
            hostname = None
            hostnames_elem = host_elem.find("hostnames")
            if hostnames_elem is not None:
                first_hn = hostnames_elem.find("hostname")
                if first_hn is not None:
                    hostname = first_hn.attrib.get("name")

            # Extract Ports
            ports: List[PortResult] = []
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    try:
                        port_id = int(port_elem.attrib.get("portid", 0))
                    except ValueError:
                        continue
                    protocol = port_elem.attrib.get("protocol", "tcp")

                    state_elem = port_elem.find("state")
                    state = state_elem.attrib.get("state", "unknown") if state_elem is not None else "unknown"

                    service_name = ""
                    product = ""
                    version = ""
                    extra_info = ""

                    service_elem = port_elem.find("service")
                    if service_elem is not None:
                        service_name = service_elem.attrib.get("name", "")
                        product = service_elem.attrib.get("product", "")
                        version = service_elem.attrib.get("version", "")
                        extra_info = service_elem.attrib.get("extrainfo", "")

                    ports.append(
                        PortResult(
                            port_id=port_id,
                            protocol=protocol,
                            state=state,
                            service_name=service_name,
                            product=product,
                            version=version,
                            extra_info=extra_info,
                        )
                    )

            hosts.append(
                HostResult(
                    ip=ip,
                    status=status,
                    hostname=hostname,
                    ports=ports,
                )
            )

        return NmapScanResult(
            command_args=command_args,
            hosts=hosts,
            raw_xml=xml_content,
        )

    @classmethod
    def to_findings(cls, scan_result: NmapScanResult, project_id: int, execution_id: Optional[int] = None) -> List[Finding]:
        """Convert discovered open ports and services into structured findings."""
        findings: List[Finding] = []

        for host in scan_result.hosts:
            if host.status != "up":
                continue

            for port in host.ports:
                if port.state != "open":
                    continue

                service_desc = port.service_summary or "Unknown service"
                title = f"Discovered Service: {service_desc} on {host.ip}:{port.port_id}/{port.protocol}"
                
                # Check for known insecure or sensitive services to adjust severity
                severity = FindingSeverity.INFORMATIONAL
                remediation = "Verify whether this port/service is required for business purposes; restrict access via firewall if unnecessary."
                
                insecure_services = {
                    "telnet": (FindingSeverity.HIGH, "Replace Telnet with encrypted SSH."),
                    "ftp": (FindingSeverity.LOW, "Ensure FTP requires encryption (FTPS/SFTP) and disallows anonymous login."),
                    "http": (FindingSeverity.INFORMATIONAL, "Ensure HTTP traffic redirects to secure HTTPS."),
                    "smb": (FindingSeverity.MEDIUM, "Ensure SMB signing is required and SMBv1 is disabled."),
                    "ms-wbt-server": (FindingSeverity.MEDIUM, "Restrict RDP access with NLA and MFA."),
                }

                svc_lower = port.service_name.lower()
                for key, (sev, rem) in insecure_services.items():
                    if key in svc_lower:
                        severity = sev
                        remediation = rem
                        break

                description = (
                    f"Port {port.port_id}/{port.protocol} was identified as open on host {host.ip} "
                    f"({host.hostname or 'no reverse DNS'}). Service identified: {service_desc}."
                )

                findings.append(
                    Finding(
                        project_id=project_id,
                        title=title,
                        severity=severity,
                        affected_asset=host.ip,
                        affected_port_service=f"{port.port_id}/{port.protocol}",
                        description=description,
                        remediation=remediation,
                        validation_status=ValidationStatus.CONFIRMED,
                        source_tool="nmap",
                        execution_id=execution_id,
                    )
                )

        return findings
