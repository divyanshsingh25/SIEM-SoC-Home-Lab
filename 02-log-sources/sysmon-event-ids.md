# 🔍 Sysmon Event IDs — The SOC Analyst's Best Friend

## 🎯 Event ID Cheat Sheet

Sysmon logs **endpoint behavior** — the "what" and "how" of execution.

| ID | Event Name | 🚨 Risk | Hunting Value | MITRE |
|----|-----------|--------|----------------|-------|
| **1** | Process Created | 🟡 HIGH | Child processes, suspicious parents | T1059 |
| **3** | Network Connection | 🔴 CRITICAL | Outbound C2, beacons | T1071 |
| **5** | Process Terminated | 🟢 LOW | Timeline reconstruction | N/A |
| **6** | Driver Loaded | 🔴 CRITICAL | Rootkits, kernel exploits | T1014 |
| **7** | Image Loaded (DLL) | 🟡 HIGH | DLL injection, side-loading | T1055 |
| **8** | CreateRemoteThread | 🔴 CRITICAL | Process injection | T1055 |
| **9** | RawAccessRead | 🔴 CRITICAL | Disk manipulation | T1005 |
| **10** | ProcessAccess | 🟡 HIGH | Credential dumping (lsass.exe) | T1003 |
| **11** | FileCreate | 🟡 MEDIUM | Malware staging, persistence | T1105 |
| **12** | RegistryEvent (Object added) | 🟡 MEDIUM | Persistence, config changes | T1112 |
| **13** | RegistryEvent (Value Set) | 🟡 HIGH | Run keys, persistence | T1547.001 |
| **14** | RegistryEvent (Object Renamed) | 🟢 LOW | Registry manipulation | N/A |
| **15** | FileCreateStreamHash | 🟡 MEDIUM | ADS detection | T1564.004 |
| **17-18** | Pipe Events | 🟡 HIGH | Inter-process communication | T1218 |
| **19-21** | WMI Events | 🔴 CRITICAL | Living-off-the-land attacks | T1047 |
| **22** | DNS Query | 🔴 HIGH | C2 domains, beaconing | T1071.004 |
| **23** | File Deleted | 🟡 MEDIUM | Cover-up attempts | T1070 |
| **26** | ClipboardChange | 🟡 MEDIUM | Data exfiltration prep | T1115 |
| **27** | ProcessTampering | 🔴 CRITICAL | Debuggers, self-modifying code | T1036 |

---

## 🚨 The "Must-Hunt" Events

### Event 1: Process Created 🎯
```
🔴 ALERT IF:
  • powershell.exe spawns from svchost.exe or explorer.exe
  • cmd.exe /c run from Network Service
  • notepad.exe talks to network
  • msiexec.exe with suspicious arguments
```

### Event 3: Network Connection 🎯
```
🔴 ALERT IF:
  • Outbound to non-standard ports (8080, 4444, 9001, etc)
  • Multiple connections to same IP (beaconing)
  • DNS to suspicious domains (.ru, .xyz, random strings)
  • Office apps connecting outside corp network
```

### Event 10: ProcessAccess 🎯
```
🔴 ALERT IF:
  • Any process accessing lsass.exe (credential dump)
  • mimikatz.exe, procdump.exe accessing lsass
  • Non-admin tool accessing System/Protected Process
```

### Event 22: DNS Query 🎯
```
🔴 ALERT IF:
  • Random subdomains (DGA — Domain Generation Algorithm)
  • Exfil domains (pastebin, discord, slack webhooks)
  • C2 callback patterns (suspicious.top, malware.net)
```

---

## 📊 Event Flow During an Attack

```
Attacker RDPs In
       ↓
Event 1: cmd.exe spawned from explorer.exe
       ↓
Event 3: cmd.exe connects to 192.168.1.100:445 (SMB)
       ↓
Event 1: mimikatz.exe launched
       ↓
Event 10: mimikatz accessing lsass.exe 🚨 ALERT
       ↓
Event 3: Outbound to C2 domain 🚨 ALERT
       ↓
Event 22: DNS queries to malware.ru 🚨 ALERT
```

---

## 🎓 Pro Tips

✅ **Stack Event 1 + Event 3** → Processes calling out to network = potential C2  
✅ **Watch Parent-Child Chains** → svchost → powershell → outbound = COMPROMISED  
✅ **Enable Event 22 (DNS)** → Catch C2 callbacks before network connection  
✅ **Tune Down Noise** → Exclude legitimate processes (Windows Update, AV, etc)  

---

## 📝 SwiftOnSecurity Config

Your lab uses the **SwiftOnSecurity Sysmon config** — pre-tuned filters to reduce noise while keeping detections.

📂 Location: `01-lab-setup/sysmonconfig.xml`
