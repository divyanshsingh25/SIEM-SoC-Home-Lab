# 🔬 Sysmon Event Analysis & Investigation

## Overview

Sysmon provides deep endpoint visibility through detailed event logs. This guide covers how to analyze key Sysmon events to detect and investigate attacks in Splunk.

---

## 📊 Key Sysmon Event IDs

| EventID | Event Type | Key Fields | Use Case |
|---------|-----------|-----------|----------|
| 1 | Process Created | Image, ParentImage, CommandLine, User | Malware execution, LOLBins |
| 3 | Network Connection | SourceIp, DestinationIp, DestinationPort, Protocol | C2 callbacks, lateral movement |
| 7 | Image/DLL Loaded | Image, ImageLoaded, Signed | DLL injection, evasion techniques |
| 8 | CreateRemoteThread | SourceImage, TargetImage, TargetProcessId | Process injection, malware |
| 11 | FileCreate | TargetFilename, CreationUtcTime | Dropped files, payload staging |
| 13 | RegistryEvent | TargetObject, Details | Persistence, configuration changes |
| 15 | FileCreateStreamHash | TargetFilename, Hash | ADS detection, hidden files |
| 17 | PipeEvent | PipeName | Process communication, lateral movement |
| 22 | DNSQuery | QueryName, QueryStatus | C2 domain resolution, exfiltration |

---

## 🔍 Investigation Techniques

### 1. **Process Execution Analysis**

#### Objective: Identify suspicious process creation chains

**SPL Query - Process Execution Chain:**
```spl
index=main EventCode=1 
| stats first(CommandLine) as cmd, first(ParentImage) as parent, 
        first(User) as user by Image
| search parent=*cmd.exe* OR parent=*powershell.exe* OR parent=*svchost.exe*
```

**What to Look For:**
- ✅ Unusual parent-child process relationships
- ✅ Processes spawned by system services (svchost, lsass, system)
- ✅ Execution from temp directories (%TEMP%, %APPDATA%)
- ✅ Double file extensions (.pdf.exe, .txt.scr)
- ✅ Obfuscated or encoded command lines

**Investigation Steps:**
1. Identify the suspicious process (Image)
2. Trace back to the parent process
3. Check for lateral movement via RPC or WMI
4. Look for file drops and registry changes
5. Correlate with network connections (EventID 3)

---

### 2. **Network Connection Analysis**

#### Objective: Detect C2 callbacks, data exfiltration, lateral movement

**SPL Query - Rare Outbound Connections:**
```spl
index=main EventCode=3 Initiated=true 
| stats count as conn_count, values(DestinationPort) by SourceImage, DestinationIp 
| where conn_count > 100 OR DestinationPort NOT IN (80, 443, 53, 88, 445)
```

**SPL Query - RDP Lateral Movement Detection:**
```spl
index=main EventCode=3 DestinationPort=3389 Protocol=tcp 
| stats count by SourceIp, DestinationIp, Image, User
| search count > 10
```

**What to Look For:**
- ✅ Connections to non-standard ports
- ✅ RDP connections (port 3389) outside business hours
- ✅ Processes connecting to external IPs
- ✅ DNS tunneling (unusual DNS queries)
- ✅ C2 beacons (repeating connections to same destination)

---

### 3. **File Creation & Registry Modification**

#### Objective: Identify persistence mechanisms and malware staging

**SPL Query - Suspicious File Creation:**
```spl
index=main EventCode=11 
| search TargetFilename IN (*\\startup*, *\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup*, 
                           *\\Windows\\System32*, *\\Temp\\*, *\.exe, *\.scr, *\.vbs, *\.ps1)
| stats count by TargetFilename, Image, User
```

**SPL Query - Registry Persistence Detection:**
```spl
index=main EventCode=13 TargetObject IN ("*\\CurrentVersion\\Run*", "*\\CurrentVersion\\RunOnce*", 
                                          "*\\Shell\\Open\\Command*", "*\\Services\\*")
| stats count by TargetObject, Image, Details, User
```

**What to Look For:**
- ✅ Files in startup directories
- ✅ Executable files in temp folders
- ✅ Registry Run keys being modified
- ✅ Scheduled tasks created
- ✅ Services registered by non-system processes

---

### 4. **DLL Injection & Code Execution**

#### Objective: Detect advanced malware techniques

**SPL Query - Suspicious DLL Loads:**
```spl
index=main EventCode=7 
| search ImageLoaded NOT IN ("C:\\Windows\\*", "C:\\Program Files\\*")
| stats count by Image, ImageLoaded, Signed
| where Signed=false
```

**SPL Query - Remote Thread Creation:**
```spl
index=main EventCode=8 
| stats count by SourceImage, TargetImage, TargetProcessId, User
| search SourceImage != TargetImage
```

**What to Look For:**
- ✅ DLLs from non-standard locations
- ✅ Unsigned or suspicious DLLs
- ✅ DLL injection into system processes
- ✅ CreateRemoteThread from suspicious executables

---

## 📈 Investigation Workflow

```
1. ALERT TRIGGERED
   └─ Detection rule fires (port scan, brute force, etc.)

2. INITIAL TRIAGE
   └─ Confirm alert legitimacy
   └─ Gather context: Time, User, Source IP, Process

3. PROCESS ANALYSIS
   └─ Review EventCode=1 (Process Creation)
   └─ Build process execution tree
   └─ Identify command line parameters

4. FILE & REGISTRY ANALYSIS
   └─ Search EventCode=11 (File Drops)
   └─ Search EventCode=13 (Registry Modifications)
   └─ Identify persistence mechanisms

5. NETWORK ANALYSIS
   └─ Review EventCode=3 (Network Connections)
   └─ Correlate with known C2 IPs/domains
   └─ Check for lateral movement indicators

6. EVIDENCE COLLECTION
   └─ Screenshot Splunk searches
   └─ Document timeline
   └─ Preserve hashes & IOCs

7. ESCALATION
   └─ Categorize severity
   └─ Create incident ticket
   └─ Alert incident response team
```

---

## 🎯 Common Attack Patterns

### Pattern 1: LOLBin Abuse
```
cmd.exe → wmic.exe / schtasks.exe / powershell.exe
  └─ Outbound connection (EventCode 3)
  └─ Registry modification (EventCode 13)
  └─ File drop in suspicious location (EventCode 11)
```

**Detection SPL:**
```spl
index=main EventCode=1 
Image IN (*\\wmic.exe, *\\schtasks.exe, *\\regsvcs.exe, *\\InstallUtil.exe) 
ParentImage IN (*\\cmd.exe, *\\powershell.exe, *\\mshta.exe)
```

---

### Pattern 2: Lateral Movement via RPC
```
Process Injection (EventCode 8)
  └─ Remote Thread in svchost/system
  └─ Network connection to remote host (EventCode 3)
  └─ Process creation on remote host
```

**Detection SPL:**
```spl
index=main EventCode=8 TargetImage IN (*\\lsass.exe, *\\svchost.exe, *\\system*)
| stats count by SourceImage, TargetImage, Computer
```

---

### Pattern 3: C2 Beacons
```
Process connects to external IP (EventCode 3)
  └─ Repeating connections to same destination
  └─ Non-standard port (not 80/443/53)
  └─ Suspicious process parent
```

**Detection SPL:**
```spl
index=main EventCode=3 Initiated=true DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*")
| stats count as beacon_count by SourceImage, DestinationIp, DestinationPort
| search beacon_count > 50
```

---

## 💾 Analysis Checklist

- [ ] Is the process execution legitimate?
- [ ] Does the parent-child relationship make sense?
- [ ] Are command line parameters encoded/obfuscated?
- [ ] Are files being dropped to suspicious locations?
- [ ] Is the process modifying registry or startup?
- [ ] Is the process making network connections?
- [ ] Are connections to known malicious IPs?
- [ ] Is the user account privileged?
- [ ] Is this execution happening outside business hours?
- [ ] Are there any Sysmon hash matches to known malware?

---

## 📚 References

- [Sysmon Event IDs - SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config)
- [Splunk Sysmon App](https://splunkbase.splunk.com/app/1914)
- [MITRE ATT&CK Techniques](https://attack.mitre.org)
- [MalwareLabs - Sysmon Analysis](https://malwarelabs.org)
