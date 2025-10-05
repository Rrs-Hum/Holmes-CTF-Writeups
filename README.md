## 🏅 Holmes CTF 2025 — Participation
<p align="center">  <img src="attachments/Certificate-RrsHum.png" alt="Holmes CTF 2025 Certificate — Rares Lascau (Null Raider)" width="650">
</p>

A small, focused portfolio of my Blue Team work from **Holmes CTF 2025**.  
My goal is to show how I think, investigate, and communicate as a **SOC analyst / DFIR responder** 

---

## 👋 Why this repo exists

- **Real analyst habits.** I start with a question, gather evidence, and keep a tidy chain-of-custody in the write-up (timestamps, event IDs, hashes, registry paths).
- **Detect-first mindset.** Every finding becomes a rule, query, or checklist item you can operationalize.
- **Clear reporting.** Each challenge has a short **timeline**, and **Lessons Learned**.

---

## 🔎 Highlights

- **Detection Engineering:** KQL/Sigma-style ideas, log source mapping (4688, 4720, 4698, 4104, TaskScheduler/Operational).
- **Host & Network Triage:** Event log parsing, registry hive inspection, `netsh portproxy`, scheduled tasks, host file tampering.
- **Threat-Led Investigations:** IOCs → CTI pivots → infra context (open ports, banners, ownership).
- **Communication:** Concise answers, evidence blocks, and “Quick Wins” for detection & hardening.

**Tooling I’m comfortable with:** Bash/grep/awk, Sysmon/Security.evtx, Reg hives (`reglookup`, `regipy`), PowerShell, Wireshark, Volatility, Impacket, Hashcat, Splunk/Elastic.

---

## 📚 Challenges

| #  | Name                     | Focus (SOC Skills)                     | Difficulty | Write-up |
|----|--------------------------|----------------------------------------|------------|---------|
| 01 | The Card                 | Indicator pivoting, web/WAF logs, CTI  | Easy       | [Read](01_The_Card.md) |
| 02 | The Enduring Echo        | Host triage, persistence, lateral move | Easy       | [Read](02_The_Enduring_Echo.md) |
| 03 | The Watchman’s Residue   | AI helpdesk leak, RMM abuse, DFIR timeline | Medium | [Read](03_The_Watchmans_Residue.md) |
| 04 | The Payload              | Malware behavior & propagation         | Hard       | Only Partially Completed the Challenge |
| 05 | The Tunnel Without Walls | Memory forensics, covert channels      | Hard       | Only Partially Completed the Challenge |

---

## 🧭 What “good” looks like in these write-ups

- **How I worked:** the exact commands/queries I ran (copy/paste ready).
- **Evidence:** trimmed log/XML/registry snippets with the relevant fields highlighted.
- **Lessons Learned:** 5–8 bullets you can turn into controls or a playbook.

---

## 🧩 Quick teasers

### 01 — *The Card* (Web logs → CTI → Infra)
- 🧠 **Scenario:** A suspicious web request chain hints at a web shell and data access on a public app. The trail runs through WAF/proxy logs into a small piece of attacker infra.
- 🛠️ **What I did:** Pivoted on markers in **HTTP logs** (UA, paths, parameters), enriched with **CTI** (domain/IP reputation, ASN), and validated exposure via banner checks. Built a compact incident narrative (initial probe → web shell → data pull).
- 🎯 **Focus (SOC Skills):** Indicator pivoting, CTI enrichment, log triage, infra scoping.
- ✅ **Outcome:** Mapped the campaign touchpoints and highlighted weak controls (upload filtering, stale creds, noisy beacons).
- 💡 **Quick Wins:** 
  - Alert on web-shell upload patterns and odd `POST` destinations.
  - Hunt for **sudden spikes** in 4xx→2xx transitions on admin routes.
  - Block/monitor infra tied to the campaign ASN/banners.
- 🔎 **Tools:** Proxy/WAF logs, `curl`/banner checks, basic CTI lookups.

> **Value:** shows indicator pivoting discipline, CTI enrichment, and clear reporting.

### 02 — *The Enduring Echo* (Windows triage → persistence → lateral move)
- 🧠 **Scenario:** A Windows host shows suspicious process chains and repeated script execution. Evidence points to a stealthy persistence + lateral movement attempt.
- 🛠️ **What I did:** Rebuilt execution flow from **4688** (process creation), correlated with **scheduled tasks** and **PowerShell 4104** logs. Confirmed lateral helper via `netsh portproxy` and captured registry evidence. Produced a timestamped, source-attributed timeline.
- 🎯 **Focus (SOC Skills):** Host log analysis, persistence discovery, registry forensics, practical detections.
- ✅ **Outcome:** Identified the task-based persistence, recovered relevant hashes, and documented the exact registry paths for the port-proxy pivot.
- 💡 **Quick Wins:** 
  - Alert: `WmiPrvSE.exe` spawning `cmd.exe`/`powershell.exe` with `\\127.0.0.1\ADMIN$`.
  - Monitor: `HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp` for new entries.
  - Hunt: SYSTEM tasks executing from `%USERPROFILE%\AppData\Local\*.ps1`.
- 🔎 **Tools:** Event Viewer/EVTX exports, PowerShell logs (4104), registry inspection (`reg.exe`, reg parsers).

> **Value:** demonstrates event-driven reasoning, registry analysis, and practical detections you can deploy.

### 03 — *The Watchman’s Residue* (AI helpdesk → RMM → DFIR timeline)
- 🧠 **Scenario:** An AI helpdesk bot at an MSP is socially engineered into leaking **RMM access**. From there, the attacker (👀 “JM”) lands on a Windows workstation, sets up **persistence** (Winlogon/Userinit), runs **credential tools** (e.g., mimikatz), and **exfiltrates** sensitive files.
- 🛠️ **What I did:** Correlated **PCAP** chat traffic (`/api/messages`) with **TeamViewer logs** (sessions + file transfers) and **host artifacts** (USN `$J`, Prefetch, LNK, UserAssist, Winlogon) to build a **minute-level incident timeline**. Mapped persistence to **MITRE T1547.004**.
- 🎯 **Focus (SOC Skills):** Timeline reconstruction, RMM abuse detection, Windows triage, evidence normalization (UTC vs local), and ATT&CK mapping.
- ✅ **Outcome:** Answered **12/19** during the event window; used the **post-event 3-day grace** (no score impact) to finish analysis, verify UserAssist runtime, and tighten IOCs/timestamps.
- 💡 **Quick Wins:** 
  - Alert on **TeamViewer**/RMM file sends from temp dirs (e.g., `C:\Windows\Temp\*\`).
  - Hunt for **Winlogon\Userinit** modifications adding extra binaries (persistence).
  - Watch for creation of **`MIMIKATZ.EXE-*.pf`** and suspicious tools in `%Temp%`/`%ProgramData%`.
- 🔎 **Tools:** Wireshark/tshark, Eric Zimmerman (MFTECmd, Registry Explorer), `lnkparse`, John the Ripper/`keepass2john`.

> **Value:** Shows AI-adjacent risk handling, cross-artifact correlation (network ↔ RMM ↔ host), and clear, recruiter-friendly storytelling with concrete detections.

---

## 🛡️ Ready-to-use “Quick Wins”

These come straight from the investigations and are easy to operationalize in a SOC:

### 🚨 Alerts
- **RMM / TeamViewer exfil:** Alert on **TeamViewer “Send file”** events or RMM file transfers to/temp from  
  `C:\Windows\Temp\*` or `C:\ProgramData\*`.
- **Winlogon persistence:** Alert when `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`  
  contains **additional binaries** (e.g., `Userinit.exe, JM.exe`).
- **Credential dumping indicators:** Creation of **`MIMIKATZ.EXE-*.pf`** or execution of `mimikatz.exe` / common clones.
- **Suspicious process chains:** `WmiPrvSE.exe` → `cmd.exe`/`powershell.exe`, especially with `\\127.0.0.1\ADMIN$` in the command line.
- **AI helpdesk leakage:** Alert on outbound messages containing **credential patterns** (e.g., `ID: \d{3} \d{3} \d{3}`, `Password:`) from bot integrations.

### 🕵️ Hunts
- **Temp staging:** New executables/archives dropped under `C:\Windows\Temp\` or `%TEMP%` followed by quick execution.
- **Exfil patterns:** Long-lived TLS or bursty HTTP `POST` right after file staging in temp dirs.
- **Lateral prep:** Discovery of `dump.txt`-style outputs (tool logs) accessed right before RMM transfers (LNK “Accessed” timestamps).
- **RMM script runner abuse:** Spikes in script execution events or unusual operators/ASNs initiating sessions.

### 🔍 Monitors
- **Port proxy pivot:** `HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp` for new values (silent pivot).
- **Scheduled tasks:** SYSTEM or at-logon tasks launching scripts from `%USERPROFILE%\AppData\Local\*.ps1` or `%ProgramData%\*.exe`.
- **TeamViewer sessions:** Start/End + **file transfer** telemetry tied to sensitive hosts (workstations handling HR/R&D data).

### 🧱 Guardrails
- **RMM hardening:** Enforce **MFA**, IP allow-list/VPN, device certs; restrict admin access to management planes.
- **AI helpdesk safety:** Add **prompt/response filters** for secrets, redact patterns (IDs/passwords), and log bot interactions for review.
- **Egress control:** Allow-list known SaaS/RMM endpoints; flag new **long-lived TLS** with unknown SNI.
- **Local lockdowns:** Block/alert `netsh advfirewall set allprofiles state off` and **hosts file** edits adding non-corporate domains.

### 🧾 Logging baseline
- Enable **4688 with CommandLine**, **PowerShell 4104**, **Task Scheduler/Operational**, **Defender** detections, and **Sysmon** (process, network, file create).
- Centralize **RMM/TeamViewer** logs and **DNS** logs; preserve **USN `$J`** and **Prefetch** in triage imaging.

### 🚫 Blocklists / IOCs (operationalize quickly)
- Paths: `C:\Windows\Temp\safe\*`, `C:\Windows\Temp\flyover\*`, `%ProgramData%\*\*.exe`
- Filenames: `mimikatz.exe`, `JM.exe`, `webbrowserpassview.exe`, `credhistview.zip`
- Artifacts: `MIMIKATZ.EXE-*.pf`, LNK targets referencing `dump.txt` in temp dirs

---

## 🗂️ Repo Structure

```text
Holmes-CTF-Writeups/
├─ attachments/            # screenshots / figures referenced in write-ups
├─ 01_The_Card.md
├─ 02_The_Enduring_Echo.md
├─ 03_The_Watchmans_Residue.md
├─ README.md
