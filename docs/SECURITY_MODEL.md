# Security, Privacy & Safety Model

## 1. Scope & Authorization Architecture

The platform enforces a strict pre-execution authorization check for any security operation.

```text
User Request / Scan Trigger
          │
          ▼
┌───────────────────────────────────────────────┐
│           Scope Authorization Guard           │
│  - Is target IP / Host in authorized scope?   │
│  - Is target explicitly excluded?             │
│  - Does the project have signed authorization?│
└───────────────────────┬───────────────────────┘
                        │
          ┌─────────────┴─────────────┐
          │ Passes                    │ Fails
          ▼                           ▼
┌──────────────────────────┐   ┌──────────────────────────┐
│ Operation Classification │   │ Execution Blocked        │
│ - PASSIVE (Auto-allowed) │   │ (Logged in Audit Log)    │
│ - ACTIVE (Prompt user)   │   └──────────────────────────┘
│ - INTRUSIVE (Explicit OK)│
└──────────────────────────┘
```

### Authorization Levels
1. **Passive**: Information retrieval that sends no probe packets directly to the target (DNS queries, WHOIS, local source code analysis).
2. **Active**: Probes, port scans, HTTP directory fuzzing. Requires the target to match the authorized project scope and requires user confirmation.
3. **Intrusive**: Vulnerability verification, exploit modules, high-frequency brute forcing. Requires explicit confirmation and confirmation that the target is a controlled lab or authorized system.

---

## 2. Process Execution Safety

1. **No `shell=True` Execution**: Commands are never executed as arbitrary concatenated shell strings. All executions pass structured argument arrays (`list[str]`) directly to `subprocess.Popen` / `QProcess`.
2. **Timeout & Resource Limits**: Every process execution is assigned a strict timeout (configurable, default 15 minutes). Hanging processes are terminated cleanly via SIGTERM, followed by SIGKILL if unresponsive.
3. **Cancellation Mechanism**: Users can abort running tasks at any time from the UI with immediate process group termination.
4. **Privilege Demarcation**: The application does not run as `root`. Tools requiring raw socket privileges (such as SYN scans in Nmap) utilize standard Linux capabilities (`setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip`) or prompt via `pkexec` with full command transparency.

---

## 3. Data Privacy & AI Redaction

1. **Local-First Processing**: All scanning results, outputs, database records, and evidence files reside strictly on the local machine.
2. **Pre-AI Redaction**: Before sending any context (terminal output, scan results, or code snippets) to external AI models:
   - Target credentials, passwords, tokens, API keys, and hashes are automatically replaced with `[REDACTED_SECRET]`.
   - Internal IP ranges and customer names can be anonymized based on user privacy settings.
3. **Transparent Provider Selection**: Users are clearly notified whether an AI query is processed locally (e.g. Ollama) or transmitted to an external API (e.g. Gemini, OpenAI).

---

## 4. Evidence Integrity

- Every raw output, PCAP file, or artifact captured by an execution adapter is immediately hashed using **SHA-256**.
- The hash is stored in the database alongside the timestamp and execution metadata to ensure non-repudiation and evidence provenance for audit reports.
