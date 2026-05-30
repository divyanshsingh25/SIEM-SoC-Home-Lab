# 🌐 Network Logs Reference

## 📡 Network Data Sources in Your Lab

| Source | What It Logs | Key Fields | MITRE |
|--------|-------------|-----------|-------|
| **Sysmon Event 3** | Outbound connections | ProcName, DestIP, DestPort | T1071 |
| **Windows Firewall** | Blocked/Allowed traffic | SrcIP, DestIP, Protocol | T1562 |
| **DNS Queries** | Sysmon Event 22 | QueryName, QueryStatus | T1071.004 |
| **Proxies (if enabled)** | HTTP/HTTPS requests | URL, User, UserAgent | T1071.001 |

---

## 🎯 Attack Patterns You'll See

### 1️⃣ Port Scanning (MITRE: T1046)
```
🔍 Pattern: Single host → Multiple IPs/Ports in short time

Sysmon Log:
ProcessName: nmap.exe
DestPort: 22, 80, 443, 445, 3389 (sequential)
DestIP: 192.168.x.x (incrementing)
TimeDelta: <1 sec between connections

💡 Detection: Count destinations per process < 60 sec
```

### 2️⃣ Brute Force / RDP Attacks (MITRE: T1110.001)
```
🔐 Pattern: Repeated login attempts to single target

Windows Event Log:
EventID: 4625 (Failed Logon)
LogonType: 3 (Network/RDP)
SourceIP: Attacker IP
TimeDelta: Multiple per second

Sysmon Event 3:
DestIP: Victim | DestPort: 3389 (RDP)
Duration: Connection sustained (potential shell)

💡 Detection: >5 failed logins from same IP in 5 min
```

### 3️⃣ Lateral Movement (MITRE: T1021.002)
```
🔄 Pattern: Compromised host → Other internal hosts

Indicators:
• SMB connections (Port 445) to multiple IPs
• WinRM connections (Port 5985/5986)
• Multiple RDP attempts (Port 3389)
• Mimikatz dumping creds locally → using them remotely

Sysmon Events:
Event 1: Process spawned (psexec, wmiexec, etc)
Event 3: Outbound to targets on ports 445, 5985, 3389

💡 Detection: One host → many on SMB + process injection attempts
```

### 4️⃣ Data Exfiltration (MITRE: T1041)
```
📤 Pattern: Large outbound traffic to external IP

Red Flags:
• DestIP: Not in corp ranges
• DestPort: 443, 8080, 9001 (non-standard)
• BytesSent >> BytesReceived
• DNS query → immediate connection (C2 callback)

Sysmon Events:
Event 22: DNS query to suspicious domain
Event 3: Outbound connection to resolved IP

💡 Detection: Process + DNS query + outbound in <5 sec
```

---

## 🔥 Quick Hunt Queries (SPL-ready)

### Find all outbound connections from your network
```spl
Sysmon EventID=3 
| where DestIp NOT IN (your_corp_ranges)
| stats count by ProcessName, DestIp, DestPort
| where count > 3
```

### Detect port scanning
```spl
Sysmon EventID=3 
| stats dc(DestPort) as unique_ports by SrcIp 
| where unique_ports > 50
```

### Find processes accessing network then local creds
```spl
Sysmon EventID=3 DestPort=445 
| join ProcessId 
  [Sysmon EventID=10 TargetImage=lsass.exe]
```

### DNS + Network connection correlation (C2 detection)
```spl
Sysmon EventID=22 
| join QueryName 
  [Sysmon EventID=3 | regex DestIp="suspicious_tld"]
```

---

## 📊 Network Log Flow

```
Attack starts:
┌─────────────────┐
│ DNS Query       │ ← Attacker looks up C2 domain
│ Event 22        │   (sysmon logs this)
└────────┬────────┘
         │
         ↓
┌─────────────────┐
│ Network Connect │ ← Attacker connects to resolved IP
│ Event 3         │   (sysmon captures dest/port/process)
└────────┬────────┘
         │
         ↓
┌─────────────────┐
│ Beacon Callback │ ← Traffic to C2 server
│ (Outbound)      │   (likely recurring = beaconing)
└─────────────────┘

Your Detection Win: DNS + Network + Process = Confidence ✅
```

---

## 🎓 Network Analysis Tips

✅ **Baseline First** → Know what "normal" outbound looks like  
✅ **Watch Ports** → 3389 (RDP), 445 (SMB), 5985 (WinRM) = lateral movement  
✅ **DNS is Gold** → Attackers must resolve C2 domains — catch them before network traffic  
✅ **Count Connections** → One outbound? Suspicious. Many? Beaconing.  
✅ **Time Correlation** → DNS query → network connection within seconds = targeted attack  

---

## 🔗 How It Ties Together

| Event | Windows Log | Sysmon | Network View |
|-------|------------|--------|--------------|
| RDP Brute Force | Event 4625 ✅ | Event 3 (port 3389) | Multiple sources → 3389 |
| Port Scan | ❌ | Event 3 (many ports) | Host → many destinations |
| Lateral Movement | Event 4624 ✅ | Event 3 (445, 5985) | Compromised → internal |
| C2 Callback | ❌ | Event 22 + Event 3 ✅ | Process → external:high_port |

💡 **Best Practice:** Stack logs from multiple sources = highest confidence detections
