# 🔍 Living Off The Land Threat Hunting Playbook

## Overview

Living off the Land (LOLBins) - using legitimate system tools and processes to execute malicious activities. This playbook helps detect abuse of built-in Windows utilities for lateral movement, persistence, and command execution.

---

## 🎯 MITRE ATT&CK Coverage

| Tactic | Technique | ID |
|--------|-----------|-----|
| Execution | Command and Scripting Interpreter | T1059 |
| Defense Evasion | Masquerading | T1036 |
| Defense Evasion | Trusted Developer Utilities Proxy Execution | T1127 |
| Persistence | Scheduled Task/Job | T1053 |
| Lateral Movement | Remote Service Session Hijacking | T1021.002 |

---

## 🚨 Key Hunting Indicators

### High-Risk LOLBins

| Binary | Parent Process | Suspicious Indicators |
|--------|----------------|----------------------|
| `powershell.exe` | cmd.exe, explorer.exe | Non-standard args, Base64, WebClient |
| `certutil.exe` | cmd.exe, System | Encoding/Decoding, Download URL |
| `wmic.exe` | cmd.exe, explorer.exe | Remote process create, OS version info |
| `rundll32.exe` | cmd.exe, explorer.exe | Shell32.dll, advpack.dll, ieadvpack.dll |
| `mshta.exe` | cmd.exe | .hta file execution, inline script |
| `bitsadmin.exe` | System, Services | Remote URL, Priority foreground |
| `cscript.exe` / `wscript.exe` | cmd.exe | .vbs/.js execution, encoded script |
| `regsvr32.exe` | cmd.exe | /s /u /i flags, remote URL |
| `schtasks.exe` | cmd.exe, explorer.exe | Task creation at odd hours |
| `at.exe` | System | Scheduled task abuse |

---

## 📊 Hunting Queries

### 1. Suspicious PowerShell Execution

**Objective:** Detect PowerShell abuse for command execution

**SPL Query - Encoded PowerShell:**
```spl
index=main EventCode=1 Image="*powershell.exe"
| search CommandLine IN ("*-enc*", "*-en*", "*-e*", "*FromBase64*") 
| stats count, dc(Computer) as systems_affected by User, CommandLine
| where count > 1
```

**SPL Query - PowerShell with Network Activity:**
```spl
index=main EventCode=1 Image="*powershell.exe"
| search CommandLine IN ("*DownloadString*", "*DownloadFile*", "*WebClient*", "*Invoke-WebRequest*")
| join Computer 
  [search index=main EventCode=3 Initiated=true DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*")]
| stats count by Computer, User, DestinationIp
```

**What to Look For:**
- ✅ `-EncodedCommand` or `-enc` flags
- ✅ Base64-encoded payloads
- ✅ `IEX` (Invoke-Expression) with network calls
- ✅ `.NET` type creation for network operations
- ✅ Non-standard execution contexts (System, NT AUTHORITY\NETWORK SERVICE)

**Severity:** 🔴 CRITICAL

---

### 2. CertUtil Abuse

**Objective:** Detect certutil.exe for file transfer or encoding

**SPL Query - CertUtil Download/Encode:**
```spl
index=main EventCode=1 Image="*certutil.exe"
| search CommandLine IN ("*urlcache*", "*split*", "-decode", "-encode", "-download")
| stats count, values(CommandLine) as command by Computer, User, _time
| where count >= 1
```

**SPL Query - CertUtil with Suspicious Extensions:**
```spl
index=main EventCode=1 Image="*certutil.exe"
| search CommandLine="*urlcache*"
| regex CommandLine="\.(exe|dll|ps1|bat|cmd|vbs|js|hta)"
| stats count by Computer, User, CommandLine
```

**What to Look For:**
- ✅ `urlcache` flag (downloading files)
- ✅ `-decode` / `-encode` (obfuscating files)
- ✅ Downloading `.exe`, `.dll`, `.ps1` files
- ✅ Execution immediately after download

**Severity:** 🟠 HIGH

---

### 3. WMIC Lateral Movement

**Objective:** Detect WMIC for remote process execution

**SPL Query - WMIC Remote Process Create:**
```spl
index=main EventCode=1 Image="*wmic.exe"
| search CommandLine IN ("*process*", "*call*", "*create*", "/node:")
| stats count by Computer, User, CommandLine
```

**SPL Query - WMIC to Remote System:**
```spl
index=main EventCode=1 Image="*wmic.exe"
| search CommandLine IN ("*/node:*", "*process call create*")
| regex CommandLine="/node:(?<target>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| stats count by Computer, User, target
```

**What to Look For:**
- ✅ `/node:` flag pointing to remote IP
- ✅ `process call create` for execution
- ✅ Command execution as SYSTEM on remote host
- ✅ Activity during off-hours

**Severity:** 🟠 HIGH

---

### 4. RunDLL32 Execution

**Objective:** Detect DLL proxy execution via rundll32

**SPL Query - Suspicious RunDLL32:**
```spl
index=main EventCode=1 Image="*rundll32.exe"
| search CommandLine NOT IN ("*shell32.dll*", "*setupapi.dll*")
| search CommandLine IN ("*advpack.dll*", "*ieadvpack.dll*", "*shdocvw.dll*", "*zipfldr.dll*")
| stats count by Computer, User, CommandLine
```

**SPL Query - RunDLL32 File Creation:**
```spl
index=main EventCode=1 Image="*rundll32.exe"
| join Computer [search index=main EventCode=11 Image="*rundll32.exe" TargetFilename="*.exe"]
| stats count by Computer, User, TargetFilename
```

**What to Look For:**
- ✅ Non-standard DLL arguments
- ✅ Remote DLL loading (UNC paths)
- ✅ Creating executables
- ✅ Creating `.vbs`, `.js` files

**Severity:** 🟠 HIGH

---

### 5. MSHTA Execution

**Objective:** Detect HTML Application (.hta) execution abuse

**SPL Query - MSHTA with URL:**
```spl
index=main EventCode=1 Image="*mshta.exe"
| search CommandLine IN ("*http*", "*\\\\*")
| stats count by Computer, User, CommandLine
```

**SPL Query - MSHTA Network Connection:**
```spl
index=main EventCode=1 Image="*mshta.exe"
| join Computer [search index=main EventCode=3 SourceImage="*mshta.exe" Initiated=true 
                                    DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*")]
| stats count, values(DestinationIp) as destinations by Computer, User
```

**What to Look For:**
- ✅ Remote `.hta` file execution
- ✅ Inline script execution
- ✅ Network connections from mshta.exe
- ✅ Parent process is non-standard (cmd, PowerShell)

**Severity:** 🔴 CRITICAL

---

### 6. BitsAdmin Abuse

**Objective:** Detect BITS (Background Intelligent Transfer Service) abuse for file transfer

**SPL Query - BitsAdmin Download:**
```spl
index=main EventCode=1 Image="*bitsadmin.exe"
| search CommandLine IN ("*/transfer*", "*/create*", "*/resume*")
| stats count by Computer, User, CommandLine
```

**SPL Query - BitsAdmin to External IP:**
```spl
index=main EventCode=1 Image="*bitsadmin.exe"
| join Computer [search index=main EventCode=3 SourceImage="*bitsadmin.exe" Initiated=true 
                                    DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*")]
| stats count by Computer, DestinationIp
```

**What to Look For:**
- ✅ Creating transfer jobs to external URLs
- ✅ Creating executable downloads
- ✅ Jobs set to `Foreground` priority (unusual)
- ✅ Immediate deletion after transfer

**Severity:** 🟠 HIGH

---

### 7. Script Engine Abuse (cscript/wscript)

**Objective:** Detect VBScript and JScript execution

**SPL Query - Encoded Script Files:**
```spl
index=main EventCode=1 Image IN ("*cscript.exe", "*wscript.exe")
| search CommandLine IN ("*//E:vbscript*", "*//e:jscript*", "*decoded*")
| stats count by Computer, User, CommandLine
```

**SPL Query - Script File Creation + Execution:**
```spl
index=main EventCode=11 TargetFilename IN ("*.vbs", "*.js", "*.jse", "*.vbe")
| join Computer [search index=main EventCode=1 Image IN ("*cscript.exe", "*wscript.exe")]
| stats count by Computer, User, TargetFilename, Image
```

**What to Look For:**
- ✅ Encoding/decoding flags
- ✅ Parent process is cmd.exe or explorer.exe
- ✅ Script files created by unusual processes
- ✅ Script execution from temporary directories

**Severity:** 🟠 HIGH

---

### 8. SchtASKS Persistence

**Objective:** Detect task scheduling for persistence

**SPL Query - Suspicious Scheduled Tasks:**
```spl
index=main EventCode=1 Image="*schtasks.exe"
| search CommandLine="/create"
| search CommandLine NOT IN ("*Windows\\*", "*Microsoft\\*", "*System32\\*")
| stats count by Computer, User, CommandLine
```

**SPL Query - Task Execution at Odd Hours:**
```spl
index=main EventCode=1 Image="*schtasks.exe"
| search CommandLine="/create"
| eval hour=strftime(_time, "%H")
| where hour NOT IN ("08", "09", "10", "11", "12", "13", "14", "15", "16", "17", "18")
| stats count by Computer, User, hour
```

**What to Look For:**
- ✅ `/create` flag for new tasks
- ✅ Tasks scheduled outside business hours
- ✅ Task names mimicking legitimate services
- ✅ DestinationPath to non-standard locations
- ✅ SYSTEM or high-privilege execution

**Severity:** 🟠 HIGH

---

### 9. RegSvr32 Proxy Execution

**Objective:** Detect DLL registration abuse for script execution

**SPL Query - RegSvr32 with Remote URL:**
```spl
index=main EventCode=1 Image="*regsvr32.exe"
| search CommandLine IN ("*/s", "*/u", "*/i", "*http*", "*\\\\*")
| stats count by Computer, User, CommandLine
```

**SPL Query - RegSvr32 Network Activity:**
```spl
index=main EventCode=1 Image="*regsvr32.exe" CommandLine="*/i*"
| join Computer [search index=main EventCode=3 SourceImage="*regsvr32.exe" Initiated=true]
| stats count by Computer, User, DestinationIp
```

**What to Look For:**
- ✅ `/i` flag with remote URL
- ✅ `/s` silent execution flag
- ✅ `/u` uninstall flag (used to hide activity)
- ✅ Network connections during execution
- ✅ `.sct` file downloads

**Severity:** 🔴 CRITICAL

---

## 🔗 Correlation Hunting

### LOLBin Chain Analysis

**SPL Query - Multi-Stage LOLBin Attack:**
```spl
index=main EventCode=1 (Image="*powershell.exe" OR Image="*cmd.exe" OR Image="*wmic.exe")
| stats count as cmd_count by Computer, User, _time
| where cmd_count > 5
| join Computer [search index=main EventCode=3 Initiated=true 
                                DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*")]
| stats count by Computer, User
| where count > 1
```

**SPL Query - LOLBin + File Creation + Network:**
```spl
index=main EventCode=1 Image IN ("*powershell.exe", "*certutil.exe", "*bitsadmin.exe")
| transaction Computer startswith="Image=*" endswith="EventCode=3"
| stats count by Computer, User
| where count > 1
```

---

## 📋 Investigation Checklist

- [ ] What is the parent process of the LOLBin?
- [ ] Is the LOLBin running from an unusual location?
- [ ] Are there any command-line encoding/obfuscation techniques?
- [ ] Did the LOLBin make network connections?
- [ ] Are there file operations (create/modify)?
- [ ] Is the user account unexpected (system service, admin)?
- [ ] When did execution occur (business hours)?
- [ ] Is this a single system or multiple systems?
- [ ] Is there evidence of persistence (scheduled tasks, registry)?
- [ ] Are there indicators of lateral movement?

---

## 🛡️ Defensive Strategies

**Detection:**
- Monitor child process creation from LOLBin parents
- Baseline network behavior from each LOLBin
- Alert on encoding/obfuscation flags

**Prevention:**
- Restrict PowerShell execution policies
- Disable unnecessary WMI access
- Use application whitelisting (AppLocker)
- Monitor registry for persistence mechanisms

**Response:**
- Isolate affected system immediately
- Capture memory dump
- Preserve command history and logs
- Perform timeline reconstruction

---

## 📚 Resources

- [LOLBAS Project](https://lolbas-project.github.io)
- [SysmonHunter](https://github.com/baronpiran/SysmonHunter)
- [Splunk Threat Research Lab](https://research.splunk.com)
- [Living off the Land - SANS](https://www.sans.org)
