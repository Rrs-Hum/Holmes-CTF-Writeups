# Challenge 02 – The Enduring Echo  

## 📖 Challenge Description  
LeStrade provided a Windows disk image containing forensic artifacts. Watson noticed abnormal CPU activity and anomalies in process logs, suggesting malicious persistence and lateral movement.  
Our goal: analyze the logs and registry to reconstruct the attacker’s actions and answer the investigative questions.  

---

## 🛠️ Approach  

1. **Prepared the environment**  
   - Copied all `.evtx` files into a working directory on Kali.  
   - Converted selected logs (`Security.evtx`, `System.evtx`, `Windows PowerShell.evtx`, and `Microsoft-Windows-PowerShell%4Operational.evtx`) into `.xml` for easier parsing.  
   - Tools used: `evtxexport`, `xmlstarlet`, `grep`, `awk`, and Python.  

   ![screenshot of converted XML directory](path/to/xml_directory.png)

2. **Initial log analysis**  
   - Focused on high-value Event IDs:  
     - **4688** → New Process Creation  
     - **4720** → User Account Created  
     - **4698** → Scheduled Task Created  
     - **4104/4105** → PowerShell ScriptBlock Logging  
   - Extracted suspicious `CommandLine` entries from the logs.  

   ![screenshot of grep/xmlstarlet filtering](path/to/eventid_filter.png)

3. **Suspicious processes**  
   - Found repeated invocations of:  
     ```powershell
     powershell.exe -File C:\Users\Werni\AppData\Local\JM.ps1
     ```  
   - Observed attacker exploration with commands like `cd`, `dir`, `type`, `ipconfig`, `systeminfo`, and host file modifications.  

   ![screenshot of Security.xml showing JM.ps1 execution](path/to/jmps1_execution.png)

4. **Persistence & execution tool**  
   - Detected remote execution via **psexec.exe**.  
   - Identified persistence: a scheduled task named **SysHelper Update** running `JM.ps1` every 2 minutes as SYSTEM.  

   ![screenshot of scheduled task creation event](path/to/schtasks_event.png)

5. **Registry & hive analysis**  
   - Extracted `SYSTEM` and `SAM` hives.  
   - Recovered NTLM hash of attacker-created account `svc_netupd`.  
   - Cracked the hash using `hashcat` with a custom mask derived from the script’s timestamp-based password generation.  

   ![screenshot of hashcat cracking password](path/to/hashcat_crack.png)

---

## 🔍 Analysis & Answers  

- **First non-`cd` command executed:**  
