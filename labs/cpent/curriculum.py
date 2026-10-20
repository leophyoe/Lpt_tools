"""CPENT practical methodologies, learning objectives, and lab test definitions.

Structures official penetration testing methodologies (OSINT, Social Engineering,
and Network Penetration Testing) into actionable educational and testing models.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class CPENTTestItem:
    test_id: str
    title: str
    methodology: str  # "OSINT", "Social Engineering", "Network Pentest"
    category: str
    suggested_tools: List[str]
    command_template: Optional[str] = None
    description: str = ""
    learning_points: List[str] = field(default_factory=list)


@dataclass
class CPENTTrack:
    name: str
    methodology: str
    description: str
    tests: List[CPENTTestItem] = field(default_factory=list)


# --------------------------------------------------------------------------
# 1. OSINT Methodology Modules
# --------------------------------------------------------------------------
OSINT_TESTS: List[CPENTTestItem] = [
    CPENTTestItem(
        test_id="OSINT-1.1",
        title="Find Domain and Sub-domains of Target",
        methodology="OSINT",
        category="OSINT through the WWW",
        suggested_tools=["sublist3r", "amass", "findomain", "dnsrecon"],
        command_template="subfinder -d {domain} -silent",
        description="Enumerate domain names and sub-domains to identify expanding organization attack surfaces.",
        learning_points=["Passive DNS gathering", "Certificate Transparency logs", "Search engine indexing"],
    ),
    CPENTTestItem(
        test_id="OSINT-1.3",
        title="Refine Web Searches using Google Advanced Operators & GHDB",
        methodology="OSINT",
        category="OSINT through the WWW",
        suggested_tools=["Google Dorks", "GHDB"],
        command_template="site:{domain} filetype:pdf OR filetype:xls OR intitle:\"index of\"",
        description="Filter and locate exposed confidential documents, server directories, and credentials.",
        learning_points=["Boolean search operators", "Google Hacking Database (GHDB) categories", "Information leakage vectors"],
    ),
    CPENTTestItem(
        test_id="OSINT-1.4",
        title="Footprint the Target using Shodan & Censys",
        methodology="OSINT",
        category="OSINT through the WWW",
        suggested_tools=["shodan", "censys"],
        command_template="shodan search org:\"{organization}\"",
        description="Identify internet-facing edge routers, firewalls, IoT devices, webcams, and open administration ports.",
        learning_points=["Banner indexing engines", "Exposed device fingerprinting", "Zero-interaction external reconnaissance"],
    ),
    CPENTTestItem(
        test_id="OSINT-1.8",
        title="Enumerate Leaked Credentials from Pastebin & HaveIBeenPwned",
        methodology="OSINT",
        category="OSINT through the WWW",
        suggested_tools=["hibp", "dehashed", "pastebin scraper"],
        description="Discover credential dumps, API keys, and employee hashes leaked in third-party data breaches.",
        learning_points=["Breach data analysis", "Credential stuffing risk modeling", "Password hygiene evaluation"],
    ),
    CPENTTestItem(
        test_id="OSINT-3.1",
        title="Perform Regional Whois Lookups",
        methodology="OSINT",
        category="OSINT through DNS Interrogation",
        suggested_tools=["whois"],
        command_template="whois {domain_or_ip}",
        description="Query regional internet registries (ARIN, RIPE, APNIC, LACNIC, AfriNIC) for ownership and IP ranges.",
        learning_points=["RIR allocation boundaries", "Technical/Administrative contact identification", "Autonomous System Numbers (ASN)"],
    ),
    CPENTTestItem(
        test_id="OSINT-3.5",
        title="Perform DNS Zone Transfer (AXFR)",
        methodology="OSINT",
        category="OSINT through DNS Interrogation",
        suggested_tools=["dig", "nslookup", "dnsrecon"],
        command_template="dig axfr @{nameserver} {domain}",
        description="Attempt full DNS database replication to reveal all internal hostnames, mail servers, and IP records.",
        learning_points=["DNS AXFR protocol operation", "Misconfigured secondary nameservers", "Internal network topology revelation"],
    ),
]


# --------------------------------------------------------------------------
# 2. Social Engineering Methodology Modules
# --------------------------------------------------------------------------
SOCIAL_ENGINEERING_TESTS: List[CPENTTestItem] = [
    CPENTTestItem(
        test_id="SE-1.2",
        title="Authorized Phishing Campaign Execution",
        methodology="Social Engineering",
        category="Email Attack Vector",
        suggested_tools=["GoPhish", "Social Engineering Toolkit (SET)"],
        description="Simulate realistic phishing scenarios against consenting organizations to assess security awareness.",
        learning_points=["Email spoofing mechanisms (SPF, DKIM, DMARC)", "Urgency and pretext crafting", "Click-rate metrics and remedial training"],
    ),
    CPENTTestItem(
        test_id="SE-2.1",
        title="Voice Phishing (Vishing) Simulation",
        methodology="Social Engineering",
        category="Telephone Attack Vector",
        suggested_tools=["VoIP softphones", "Call scenario matrix"],
        description="Simulate technical support impersonation to test employee compliance and verbal verification protocols.",
        learning_points=["Elicitation techniques", "Authority and helpfulness cognitive biases", "Verification escalation protocols"],
    ),
    CPENTTestItem(
        test_id="SE-3.4",
        title="Piggybacking & Tailgating Physical Access Test",
        methodology="Social Engineering",
        category="Physical Attack Vector",
        suggested_tools=["Authorized Badge Access Audit"],
        description="Evaluate physical perimeter security, turnstile controls, and employee badge challenge rates.",
        learning_points=["Mantraps and physical access controls", "Social politeness vs security protocol", "Escort policy enforcement"],
    ),
    CPENTTestItem(
        test_id="SE-3.9",
        title="Removable Media Dropping (USB Baiting)",
        methodology="Social Engineering",
        category="Physical Attack Vector",
        suggested_tools=["Synthetic Beacon USBs"],
        description="Place benign, trackable storage devices in public/communal areas to evaluate endpoint device control policies.",
        learning_points=["AutoRun/AutoPlay risks", "Endpoint USB whitelisting", "User curiosity vs policy adherence"],
    ),
]


# --------------------------------------------------------------------------
# 3. Network Penetration Testing Methodology Modules
# --------------------------------------------------------------------------
NETWORK_PENTEST_TESTS: List[CPENTTestItem] = [
    CPENTTestItem(
        test_id="NET-1.1",
        title="Scan Network to Discover Live Hosts",
        methodology="Network Pentest",
        category="Port Scanning & Host Discovery",
        suggested_tools=["nmap"],
        command_template="nmap -sn -PE -PP -PS21,22,80,443 {target_subnet}",
        description="Discover active systems across single or multiple subnets using multi-probe ICMP and TCP SYN pings.",
        learning_points=["Firewall ping blocking bypasses", "ARP discovery in local subnets", "ICMP timestamp & address mask requests"],
    ),
    CPENTTestItem(
        test_id="NET-1.5",
        title="SYN Scan (Half-open Scan) on Target",
        methodology="Network Pentest",
        category="Port Scanning & Host Discovery",
        suggested_tools=["nmap"],
        command_template="nmap -sS -T4 -p- {target}",
        description="Send SYN packets and inspect SYN/ACK vs RST responses without completing the 3-way TCP handshake.",
        learning_points=["Stealth scanning mechanics", "Raw socket capability requirements", "IDS/IPS signature evasion"],
    ),
    CPENTTestItem(
        test_id="NET-1.8",
        title="UDP Port Scanning",
        methodology="Network Pentest",
        category="Port Scanning & Host Discovery",
        suggested_tools=["nmap"],
        command_template="nmap -sU --top-ports 100 -T3 {target}",
        description="Identify vulnerable UDP services (DNS, SNMP, TFTP, NTP, DHCP) by analyzing ICMP port unreachable responses.",
        learning_points=["ICMP rate limiting impact", "Stateless protocol probing", "Open|filtered ambiguity resolution"],
    ),
    CPENTTestItem(
        test_id="NET-3.1",
        title="Operating System Fingerprinting",
        methodology="Network Pentest",
        category="OS and Service Fingerprinting",
        suggested_tools=["nmap"],
        command_template="nmap -O --osscan-guess {target}",
        description="Analyze TCP/IP stack implementation nuances (window sizes, TCP options, IP ID sequences) to determine remote OS.",
        learning_points=["TCP/IP stack fingerprinting databases", "Active vs passive fingerprinting", "Reliability factors with packet filters"],
    ),
    CPENTTestItem(
        test_id="NET-3.3",
        title="Manual Banner Grabbing",
        methodology="Network Pentest",
        category="OS and Service Fingerprinting",
        suggested_tools=["nc", "telnet"],
        command_template="nc -nv -w 2 {target} {port}",
        description="Establish raw socket connections to open ports and read initial service greeting banners.",
        learning_points=["Service identification without heavy scanning", "Custom banner deceptions", "Protocol handshake initiation"],
    ),
    CPENTTestItem(
        test_id="NET-4.2",
        title="NetBIOS & SMB Enumeration",
        methodology="Network Pentest",
        category="Enumeration",
        suggested_tools=["nbtscan", "NetExec", "smbclient"],
        command_template="netexec smb {target} --shares",
        description="Extract computer names, workgroups, domain controllers, and open SMB file shares.",
        learning_points=["NetBIOS Name Service (137/UDP)", "SMB null sessions and guest access", "IPC$ share enumeration"],
    ),
    CPENTTestItem(
        test_id="NET-4.3",
        title="SNMP Community String Enumeration",
        methodology="Network Pentest",
        category="Enumeration",
        suggested_tools=["snmpwalk", "onesixtyone"],
        command_template="snmpwalk -v2c -c public {target}",
        description="Query SNMP agents using default/weak community strings (public, private) to extract network configs, routes, and processes.",
        learning_points=["Management Information Bases (MIB)", "SNMPv1/v2c plaintext community risks", "SNMPv3 authentication and privacy"],
    ),
    CPENTTestItem(
        test_id="NET-4.18",
        title="Traffic Capture & Credential Sniffing",
        methodology="Network Pentest",
        category="Enumeration",
        suggested_tools=["tcpdump", "tshark", "wireshark"],
        command_template="tcpdump -i any -nn -s0 -w capture.pcap",
        description="Capture cleartext protocol traffic (FTP, HTTP, Telnet, POP3, IMAP) traversing network interfaces.",
        learning_points=["Promiscuous mode packet capture", "PCAP filter expressions", "Cleartext authentication identification"],
    ),
    CPENTTestItem(
        test_id="NET-5.3",
        title="Nmap Scripting Engine (NSE) Vulnerability Scanning",
        methodology="Network Pentest",
        category="Vulnerability Assessment",
        suggested_tools=["nmap"],
        command_template="nmap --script vuln -sV {target}",
        description="Execute targeted Lua vulnerability detection scripts to identify unpatched flaws and known CVEs.",
        learning_points=["NSE script categories (safe, vuln, intrusive)", "Service banner to CVE correlation", "False positive reduction"],
    ),
    CPENTTestItem(
        test_id="NET-6.1",
        title="Windows Remote Password Authentication Testing",
        methodology="Network Pentest",
        category="Windows Exploitation",
        suggested_tools=["NetExec", "hydra"],
        command_template="netexec smb {target} -u users.txt -p passwords.txt",
        description="Audit password strength across Windows services (SMB, RDP, WinRM) while avoiding account lockout.",
        learning_points=["Account lockout threshold monitoring", "Password spraying vs brute-forcing", "Kerberos pre-authentication"],
    ),
    CPENTTestItem(
        test_id="NET-8.2",
        title="ARP Poisoning & Man-in-the-Middle Inspection",
        methodology="Network Pentest",
        category="Internal Exploitation Techniques",
        suggested_tools=["bettercap", "arpspoof"],
        description="Simulate address resolution cache poisoning in controlled network lab segments to verify dynamic ARP inspection.",
        learning_points=["Gratuitous ARP exploitation", "Layer 2 security controls (DAI, DHCP snooping)", "SSL/TLS inspection risks"],
    ),
    CPENTTestItem(
        test_id="NET-10.7",
        title="Post-Exploitation Cleanup & State Restoration",
        methodology="Network Pentest",
        category="Post Exploitation",
        suggested_tools=["System Audit Scripts"],
        description="Remove test artifacts, helper scripts, testing user accounts, and restore system state following assessment.",
        learning_points=["Assessment footprint elimination", "Operational integrity preservation", "Ethical penetration testing rules of engagement"],
    ),
]


def get_all_cpent_tests() -> List[CPENTTestItem]:
    """Retrieve all structured tests across all methodologies."""
    return OSINT_TESTS + SOCIAL_ENGINEERING_TESTS + NETWORK_PENTEST_TESTS


def get_tests_by_methodology(methodology: str) -> List[CPENTTestItem]:
    return [t for t in get_all_cpent_tests() if t.methodology.lower() == methodology.lower()]
