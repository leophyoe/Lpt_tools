# CyberSecuritySuite — Tool Integration Status Matrix

**Verification Date:** 2026-10-20  
**Host Environment:** Ubuntu Linux (x86_64), Python 3.12.3 (.venv active), OpenJDK 21  
**Verification Method:** Direct execution of version commands, PATH inspection, and source repository audit.

---

## 1. Executive Summary

- **Total Planned & Cloned Tools:** 24 tools
- **Ready & Verified Functional:** 8 tools (Nmap, c0desec, SQLMap, Gobuster, Hydra, Hashcat, Volatility3, WAFW00F)
- **Currently Integrated with GUI:** 2 tools (Nmap in `NetworkScanView`, c0desec in `WebScanView`)
- **Ready for Immediate Adapter / Execution:** SQLMap, Gobuster, Hydra, WAFW00F, Volatility3, Binwalk
- **Blocked by Missing Compiler / Binary:** 4 Go tools (`nuclei`, `ffuf`, `gitleaks`, `trivy`) — `go` compiler not installed.
- **Blocked by Missing Dependencies:** 4 tools (`bandit` missing `stevedore`, `NetExec` missing `sqlalchemy`, `nikto` missing Perl `XML::Writer`, `ScoutSuite`/`prowler` missing virtualenv dependencies).
- **Source-Only Unbuilt Java/C Tools:** 6 tools (`zaproxy`, `radare2`, `wireshark`/`tshark`, `jadx`, `apktool`, `frida`).

---

## 2. Comprehensive Tool Status Matrix

| Tool Name | Category | Installed / Detected Version | Execution Mode | Adapter Implemented | GUI Connected | Safe Local Test | Current Blocker / Status |
| :--- | :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| **Nmap** | Network | `/usr/bin/nmap` (7.94SVN) | Host CLI Binary | Yes (`nmap_adapter.py`) | Yes (`NetworkScanView`) | Passed (`localhost`) | **Ready & Fully Integrated** |
| **c0desec** | Web / Recon | `source/web/c0desec-pentest` | Python Adapter | Yes (`c0desec_adapter.py`) | Yes (`WebScanView`) | Passed (Synthetic) | **Ready & Fully Integrated** |
| **SQLMap** | Web / Database | `source/web/sqlmap/sqlmap.py` (v1.10.10#dev) | Python CLI Script | In Progress | Connectable via Shell / Adapter | Passed (`--version`) | **Functional in source** — needs dedicated GUI view or terminal command |
| **Gobuster** | Web / Brute | `/usr/bin/gobuster` (v3.6) | Host CLI Binary | No | Terminal / Runner | Passed (`version`) | **Installed on host** — executable via integrated terminal |
| **Hydra** | Network / Auth | `/usr/bin/hydra` (v9.5) | Host CLI Binary | No | Terminal / Runner | Passed (`-h`) | **Installed on host** — executable via integrated terminal |
| **Hashcat** | Password | `/usr/bin/hashcat` (v6.2.6) | Host CLI Binary | No | Terminal / Runner | Passed (`--version`) | **Installed on host** — executable via integrated terminal |
| **John the Ripper** | Password | `/usr/sbin/john` | Host CLI Binary | No | Terminal / Runner | Passed (`--help`) | **Installed on host** |
| **Binwalk** | Firmware / Reverse | `/usr/bin/binwalk` | Host CLI Binary | No | Terminal / Runner | Passed (`--help`) | **Installed on host** |
| **WAFW00F** | Web / Recon | `source/web/wafw00f` (v2.4.2) | Python Module (`-m wafw00f.main`) | No | Connectable | Passed (`--version`) | **Functional in source** |
| **Volatility 3** | Forensics / Memory | `source/system/volatility3/vol.py` (v2.28.3) | Python CLI Script | No | Connectable | Passed (`--help`) | **Functional in source** |
| **Impacket** | Network / AD | `source/network/impacket` (v0.11.0) | Python Library | No | Connectable | Passed (`version.BANNER`) | **Library available in source** |
| **Nuclei** | Vulnerability | Source repo only | Go Binary | No | No | Failed (No binary) | **Blocker:** Go compiler (`go`) not installed on host |
| **ffuf** | Web / Fuzzing | Source repo only | Go Binary | No | No | Failed (No binary) | **Blocker:** Go compiler (`go`) not installed on host |
| **Gitleaks** | Code Security | Source repo only | Go Binary | No | No | Failed (No binary) | **Blocker:** Go compiler (`go`) not installed on host |
| **Trivy** | Vulnerability / Supply Chain | Source repo only | Go Binary | No | No | Failed (No binary) | **Blocker:** Go compiler (`go`) not installed on host |
| **Bandit** | Code Security | `source/code_security/bandit` | Python Package | No | No | Failed | **Blocker:** Missing `stevedore` in Python `.venv` |
| **NetExec** | Network / AD | `source/network/NetExec` | Python Script | No | No | Failed | **Blocker:** Missing `sqlalchemy` in Python `.venv` |
| **Nikto** | Web / Vuln | `source/web/nikto` | Perl Script | No | No | Failed | **Blocker:** Missing Perl module `XML::Writer` |
| **OWASP ZAP** | Web / Proxy | `source/web/zaproxy` | Java Application | No | No | Failed (Source only) | **Blocker:** Unbuilt Gradle project; `zap.sh` binary not installed in PATH |
| **Wireshark / TShark** | Network | Source repo only | C Binary | No | No | Failed (Not in PATH) | **Blocker:** Host binaries not installed (`tshark` not in `/usr/bin`) |
| **Radare2** | Reverse Eng | `source/reverse_engineering/radare2` | C Binary | No | No | Failed (Source only) | **Blocker:** Uncompiled C source tree |
| **Jadx** | Mobile / Reverse | `source/mobile/jadx` | Java Application | No | No | Failed (Source only) | **Blocker:** Unbuilt Gradle project |
| **Apktool** | Mobile | `source/mobile/Apktool` | Java Application | No | No | Failed (Source only) | **Blocker:** Unbuilt Gradle project |
| **ScoutSuite / Prowler** | Cloud | `source/cloud/*` | Python CLI | No | No | Failed | **Blocker:** Heavy cloud SDK requirements not installed |

---

## 3. Tool Architecture & Resolution Strategy

To make tools authentically usable in `CyberSecuritySuite`, we resolve tools via a dual discovery mechanism in `core/registry.py`:
1. **System Host Binaries (`shutil.which`):** For tools installed system-wide on Ubuntu (`nmap`, `gobuster`, `hydra`, `hashcat`, `binwalk`, `john`).
2. **Project Source Wrappers (`source/**`):** For Python-based tools cloned in the repository (`sqlmap`, `c0desec`, `wafw00f`, `volatility3`). The platform resolves their Python entrypoints directly without requiring global installation.

