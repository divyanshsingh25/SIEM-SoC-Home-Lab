# 🔐 Persistence Threat Hunting Playbook

## Overview

Persistence mechanisms allow attackers to maintain access across system reboots and session terminations. This playbook helps identify unauthorized persistence installation, modification, and execution.

---

## 🎯 MITRE ATT&CK Persistence Techniques

| Technique | ID | Windows Artifact |
|-----------|-----|-----------------|
| Scheduled Task | T1053.005 | Sysmon EventCode 1, Task Scheduler |
| Registry Run Keys | T1547.001 | Sysmon EventCode 12, 13, 14 |
| Startup Folder | T1547.005 | File creation in Startup directory |
| Windows Service | T1543.003 | Sysmon EventCode 1, Service creation |
| Boot/Logon Script | T1547.001 | Registry modifications for scripts |
| Rootkit | T1014 | Kernel mode operations, Driver loading |
| Web Shell | T1505.003 | IIS/Apache file creation |
| Scheduled Task via AT | T1053.002 | Legacy scheduled task creation |

---

## 🚨 Common Persistence Locations

| Persistence Type | Registry/File Path |
|------------------|------------------|
| Run Keys | `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` |
| RunOnce Keys | `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce` |
| Startup Folder | `C:\Users\[User]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` |
| User Init | `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Userinit` |
| Shell | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders` |
| Services | `HKLM\System\CurrentControlSet\Services\[ServiceName]` |
| Logon Scripts | `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` |
| Scheduled Tasks | `C:\Windows\System32\Tasks\` |

---

## 📊 Hunting Queries

### 1. Suspicious Registry Run Keys

**Objective:** Detect unauthorized startup programs via registry modifications

**SPL Query - Registry Run Key Modifications:**
```spl
index=main EventCode IN (12, 13, 14) 
| search TargetObject IN ("*CurrentVersion\\Run*", "*CurrentVersion\\RunOnce*", "*Userinit*")
| search TargetObject NOT IN ("*Windows\\*", "*Microsoft\\*", "*System32\\*")
| stats count by Computer, User, TargetObject, Details
| where count >= 1
```

**SPL Query - User vs System Run Keys:**
```spl
index=main EventCode=13 
| search TargetObject="*CurrentVersion\\Run"
| regex TargetObject="HKEY_(?<hive>\w+)" 
| search hive="LOCAL_MACHINE"
| stats count by Computer, User, TargetObject, Details
| where count > 0
```

**SPL Query - Run Key Value Pointing to Temp/AppData:**
```spl
index=main EventCode=13 TargetObject="*Run"
| search Details IN ("*AppData\\*", "*Temp\\*", "*ProgramData\\*", "*.vbs*", "*.js*", "*.bat*")
| stats count by Computer, User, Details
```

**What to Look For:**
- ✅ Registry modifications by non-admin users
- ✅ Adding values pointing to temporary locations
- ✅ Values with encoded/obfuscated content
- ✅ Multiple run key modifications by same process
- ✅ Adding references to scripts (.vbs, .ps1, .js)
- ✅ Execution during system startup

**Severity:** 🟠 HIGH

---

### 2. Scheduled Task Creation

**Objective:** Detect suspicious scheduled task installation for persistence

**SPL Query - Task Scheduler XML Creation:**
```spl
index=main EventCode=11 
| search TargetFilename="C:\\Windows\\System32\\Tasks\\*"
| search TargetFilename NOT IN ("*Microsoft\\*", "*Windows\\*", "*Sysmain*")
| stats count by Computer, User, TargetFilename, _time
```

**SPL Query - Unusual Task Creation Time:**
```spl
index=main EventCode=1 Image="*schtasks.exe" CommandLine="*/create*"
| eval hour=strftime(_time, "%H"), day=strftime(_time, "%A")
| where (hour < 6 OR hour > 20) OR day IN ("Saturday", "Sunday")
| stats count by Computer, User, CommandLine
```

**SPL Query - Task Execution After Creation:**
```spl
index=main EventCode=1 Image="*schtasks.exe" CommandLine="*/create*"
| transaction Computer startswith="Image=*schtasks.exe" endswith="EventCode=1"
| stats count by Computer, User
| join Computer [search index=main EventCode=1 TargetImage="C:\\Windows\\System32\\Tasks\\*"]
| stats count by Computer
```

**SPL Query - Task with High Privilege:**
```spl
index=main EventCode=1 Image="*schtasks.exe" CommandLine="*/create*"
| search CommandLine IN ("*/RU SYSTEM*", "*/RU \"NT AUTHORITY\\\\SYSTEM\"*", "*/RL HIGHEST*")
| stats count by Computer, User, CommandLine
```

**What to Look For:**
- ✅ Tasks created outside business hours
- ✅ Tasks scheduled to run at startup
- ✅ Tasks running as SYSTEM account
- ✅ Task names matching legitimate services (Defender, Windows Update)
- ✅ Multiple tasks created by same user
- ✅ Tasks executing scripts from temp locations

**Severity:** 🟠 HIGH

---

### 3. Windows Service Installation

**Objective:** Detect unauthorized service creation for persistence

**SPL Query - Service Creation Events:**
```spl
index=main EventCode=1 Image="*sc.exe" CommandLine="*create*"
| search CommandLine NOT IN ("*Windows\\*", "*Microsoft\\*")
| stats count by Computer, User, CommandLine
```

**SPL Query - Service Registry Modifications:**
```spl
index=main EventCode=13 TargetObject="*Services\\*"
| search TargetObject NOT IN ("*Windows\\*", "*Microsoft\\*", "*Sysmain*")
| stats count by Computer, User, TargetObject, Details
```

**SPL Query - Service File Creation:**
```spl
index=main EventCode=11 TargetFilename="C:\\Windows\\System32\\drivers\\*"
| search TargetFilename="*.sys"
| search TargetFilename NOT IN ("*Windows\\*", "*Microsoft\\*")
| stats count by Computer, User, TargetFilename
```

**SPL Query - Service Network Activity:**
```spl
index=main EventCode=1 Image="*sc.exe" CommandLine="*create*"
| join Computer [search index=main EventCode=3 SourceImage NOT IN ("*Windows\\*", "*Microsoft\\*") Initiated=true 
                                    DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*")]
| stats count by Computer, User
```

**What to Look For:**
- ✅ Service creation by non-admin accounts
- ✅ Services pointing to unusual executable locations
- ✅ Services with random/obfuscated names
- ✅ Services created and immediately started
- ✅ Service executable from temp/appdata
- ✅ Services running as SYSTEM with network access

**Severity:** 🔴 CRITICAL

---

### 4. Startup Folder Persistence

**Objective:** Detect files dropped into startup directories

**SPL Query - Startup Folder File Creation:**
```spl
index=main EventCode=11 
| search TargetFilename="*AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*"
| search TargetFilename NOT IN ("*.lnk", "*.txt")
| stats count by Computer, User, TargetFilename
```

**SPL Query - Startup Folder Executable Creation:**
```spl
index=main EventCode=11 
| search TargetFilename="*Startup\\*"
| search TargetFilename IN ("*.exe", "*.dll", "*.vbs", "*.ps1", "*.bat", "*.cmd", "*.js")
| stats count by Computer, User, TargetFilename
```

**SPL Query - Public vs User Startup:**
```spl
index=main EventCode=11 
| regex TargetFilename="(AppData.*Startup|ProgramData.*Startup)"
| stats count by Computer, User, TargetFilename
```

**What to Look For:**
- ✅ Executable files in startup folder
- ✅ Files created by non-user processes
- ✅ Script files (.vbs, .ps1, .bat)
- ✅ Multiple files created simultaneously
- ✅ Hidden file attributes

**Severity:** 🟠 HIGH

---

### 5. Boot/Logon Script Injection

**Objective:** Detect manipulation of logon scripts for persistence

**SPL Query - Logon Script Registry Modification:**
```spl
index=main EventCode=13 
| search TargetObject IN ("*Userinit*", "*Shell*", "*UserInitMprLogonScript*")
| search Details NOT IN ("*System32\\*", "*userinit.exe*", "*explorer.exe*")
| stats count by Computer, User, TargetObject, Details
```

**SPL Query - Logon Script Execution:**
```spl
index=main EventCode=1 ParentImage="*logon.scr*"
| stats count by Computer, User, Image, CommandLine
```

**SPL Query - Group Policy Script Injection:**
```spl
index=main EventCode=11 TargetFilename="*sysvol\\*"
| search TargetFilename IN ("*.vbs", "*.ps1", "*.bat", "*.cmd", "*.js")
| stats count by Computer, User, TargetFilename
```

**What to Look For:**
- ✅ Changes to Userinit value pointing to scripts
- ✅ Scripts in Group Policy directories
- ✅ Execution of modified logon scripts
- ✅ Scripts running at unexpected times
- ✅ Scripts with encoded content

**Severity:** 🔴 CRITICAL

---

### 6. Web Shell Installation

**Objective:** Detect unauthorized web application persistence

**SPL Query - Web Shell File Creation (IIS):**
```spl
index=main EventCode=11 
| search TargetFilename="*inetpub\\wwwroot\\*"
| search TargetFilename IN ("*.aspx", "*.asp", "*.php", "*.jsp", "*.jspx", "*.war")
| search TargetFilename NOT IN ("*\\bin\\*", "*\\App_*\\*")
| stats count by Computer, User, TargetFilename
```

**SPL Query - Web Shell File Modification:**
```spl
index=main EventCode=2 TargetFilename="*inetpub\\wwwroot\\*"
| search TargetFilename IN ("*.aspx", "*.php", "*.jsp")
| stats count by Computer, User, TargetFilename
```

**SPL Query - Suspicious IIS Process Execution:**
```spl
index=main EventCode=1 ParentImage="*w3wp.exe*"
| search Image NOT IN ("*System32\\*", "*Program Files\\*")
| stats count by Computer, User, Image
```

**What to Look For:**
- ✅ Web application files created/modified
- ✅ IIS process spawning unusual child processes
- ✅ Scripts with encoded payloads
- ✅ Web access logs showing parameter passing
- ✅ Creation of backup/alternate naming schemes

**Severity:** 🔴 CRITICAL

---

### 7. DLL Side-Loading

**Objective:** Detect DLL hijacking for persistence

**SPL Query - Suspicious DLL in System Locations:**
```spl
index=main EventCode=11 TargetFilename="C:\\Windows\\System32\\*.dll"
| search TargetFilename NOT IN ("*Windows\\System32\\*.dll*")
| stats count by Computer, User, TargetFilename
```

**SPL Query - DLL with Unsigned Code Signature:**
```spl
index=main EventCode=1 Image="*.dll"
| search Signature="*(Not Signed)*" OR Signature=""
| stats count by Computer, User, Image
```

**SPL Query - DLL Loaded from Suspicious Path:**
```spl
index=main EventCode=7 ImageLoaded IN ("*AppData\\*", "*Temp\\*", "*ProgramData\\*")
| search ImageLoaded="*.dll"
| stats count by Computer, User, Image, ImageLoaded
```

**What to Look For:**
- ✅ DLL files in system directories from non-admin users
- ✅ Unsigned DLLs in protected directories
- ✅ DLLs loaded from temporary locations
- ✅ Search order hijacking patterns

**Severity:** 🟠 HIGH

---

### 8. Image File Execution Options Injection

**Objective:** Detect debugger injection for persistence

**SPL Query - IFEO Registry Modification:**
```spl
index=main EventCode=13 
| search TargetObject="*Image File Execution Options*"
| search TargetObject NOT IN ("*Windows\\*", "*Microsoft\\*")
| stats count by Computer, User, TargetObject, Details
```

**SPL Query - IFEO Debugger Value:**
```spl
index=main EventCode=13 
| search TargetObject="*Image File Execution Options*" Details="*Debugger*"
| stats count by Computer, User, TargetObject, Details
```

**What to Look For:**
- ✅ Adding Debugger key for legitimate executables
- ✅ Debugger pointing to attacker-controlled binary
- ✅ IFEO modifications for accessibility tools

**Severity:** 🟠 HIGH

---

## 🔗 Persistence Chain Analysis

**SPL Query - Indicator Convergence (Registry + File + Execution):**
```spl
index=main (EventCode=13 TargetObject="*Run" Details="*.exe") 
          OR (EventCode=11 TargetFilename="*Startup\\*.exe") 
          OR (EventCode=1 Image="*schtasks.exe" CommandLine="*/create*")
| stats count by Computer, User, _time
| where count >= 2
| stats count by Computer, User
| where count >= 2
```

**SPL Query - Persistence Setup + Communication Pattern:**
```spl
[search index=main EventCode=13 TargetObject="*Run" OR EventCode=1 Image="*schtasks.exe"]
| join Computer [search index=main EventCode=3 Initiated=true 
                                DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*")]
| stats count by Computer, User
| where count >= 2
```

---

## 🎓 Investigation Workflow

```
1. IDENTIFY PERSISTENCE INDICATOR
   └─ Registry modification alert
   └─ File creation alert
   └─ Service creation alert

2. VALIDATE PERSISTENCE TYPE
   └─ Is it Registry Run key?
   └─ Is it Scheduled Task?
   └─ Is it Windows Service?
   └─ Is it Startup folder?

3. DETERMINE SOURCE
   └─ Which process made the change?
   └─ Which user account?
   └─ When was it created? (First seen date)

4. ASSESS LEGITIMACY
   └─ Is process whitelisted?
   └─ Is location expected?
   └─ Is file signed/legitimate?
   └─ Is execution pattern expected?

5. CORRELATE WITH OTHER EVENTS
   └─ File creation events?
   └─ Network connections?
   └─ Credential access?

6. DETERMINE SCOPE
   └─ Single system?
   └─ Multiple systems?
   └─ Any successful execution?

7. ESCALATE & RESPOND
   └─ Isolate system
   └─ Preserve forensic evidence
   └─ Remove persistence
   └─ Re-image if necessary
```

---

## 📋 Persistence Verification Checklist

- [ ] Is file/registry change from known/trusted process?
- [ ] Does location match legitimate software?
- [ ] Is file digitally signed by trusted vendor?
- [ ] Is creation time aligned with normal activity?
- [ ] Are file permissions suspicious?
- [ ] Does persistence successfully execute on reboot?
- [ ] Is there supporting command-line evidence?
- [ ] Are there indicators of privilege escalation?
- [ ] Is there evidence of data exfiltration?
- [ ] Multiple persistence mechanisms present?

---

## 🛡️ Defense Strategies

**Detection:**
- Monitor all registry run keys for changes
- Alert on service creation with non-standard names
- Track scheduled task modifications
- Monitor startup folders

**Prevention:**
- Disable unused scheduled tasks
- Restrict service creation permissions
- Implement endpoint protection (HIPS)
- File integrity monitoring (FIM)

**Response:**
- Remove identified persistence
- Check for secondary persistence
- Rebuild if trust cannot be assured
- Review network for lateral movement

---

## 📚 Resources

- [MITRE ATT&CK Persistence](https://attack.mitre.org/tactics/TA0003/)
- [Windows Persistence Techniques](https://persist-ence.guide)
- [Splunk Threat Research](https://research.splunk.com)
- [Forensic Analysis Guide](https://dfir.org)
