# 🎯 C2 Beacon Detection Playbook

## Overview

Command and Control (C2) beaconing represents the heartbeat of an active compromise. Compromised systems establish regular communication channels with attacker infrastructure. This playbook provides techniques to detect C2 communication patterns, identify beacon infrastructure, and attribute malware families.

---

## 🎯 MITRE ATT&CK Coverage

| Tactic | Technique | ID |
|--------|-----------|-----|
| Command & Control | Encrypted Channel | T1573 |
| Command & Control | Non-Standard Port | T1571 |
| Command & Control | Application Layer Protocol | T1071 |
| Command & Control | DNS Tunneling | T1071.004 |
| Command & Control | Web Protocols | T1071.001 |
| Command & Control | Data Obfuscation | T1001 |

---

## 🔴 C2 Beacon Characteristics

| Characteristic | Detection Method | Severity |
|---|---|---|
| **Periodic Communication** | Time-series analysis, pattern detection | 🔴 CRITICAL |
| **External Destination** | GeoIP lookup, reputation check | 🔴 CRITICAL |
| **Consistent Data Size** | Byte count analysis, fixed patterns | 🟠 HIGH |
| **Non-Business Hours** | Time-based anomaly detection | 🟠 HIGH |
| **Encrypted Traffic** | SSL/TLS fingerprinting, entropy analysis | 🟠 HIGH |
| **Unusual Ports** | Port reputation, protocol mismatch | 🟠 HIGH |
| **Failed Connections** | Retry patterns, exponential backoff | 🟡 MEDIUM |
| **Process Misalignment** | Process-port correlation analysis | 🟠 HIGH |

---

## 📊 Hunting Queries

### 1. Periodic Beaconing Detection

**Objective:** Identify regular communication intervals indicating active C2

**SPL Query - Fixed Interval Beaconing:**
```spl
index=main EventCode=3 Initiated=true 
| search DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*", "127.*")
| stats count as total_connections, 
        latest(_time) as last_conn, 
        earliest(_time) as first_conn by SourceImage, DestinationIp, DestinationPort
| eval duration=last_conn-first_conn
| eval frequency=total_connections/(duration/60)
| where frequency >= 2 AND duration > 600
| fields SourceImage, DestinationIp, DestinationPort, frequency, duration, total_connections
```

**SPL Query - Time-Series Bucket Analysis:**
```spl
index=main EventCode=3 Initiated=true 
| search DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*")
| bucket _time span=1m
| stats count as connections_per_minute by SourceImage, DestinationIp, DestinationPort, _time
| stats avg(connections_per_minute) as avg_conn, 
        stdev(connections_per_minute) as stdev_conn 
        by SourceImage, DestinationIp, DestinationPort
| eval expected=if(stdev_conn=0, avg_conn, avg_conn)
| search stdev_conn < expected*0.2
| where avg_conn >= 1
```

**SPL Query - Exponential Backoff Detection (Retry Pattern):**
```spl
index=main EventCode=3 Initiated=true 
| search DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*")
| stats count by SourceImage, DestinationIp, DestinationPort, _time
| timechart count by DestinationPort limit=20
| stats count as spike_count
| where spike_count >= 3
```

**What to Look For:**
- ✅ Connections every 5, 10, 15, 30, 60 minutes (common beacon intervals)
- ✅ Very consistent byte counts (fixed-size C2 messages)
- ✅ Connections to same IP:port across multiple days
- ✅ Zero variance in connection timing (too regular to be natural)
- ✅ Connections despite application termination/restart

**Severity:** 🔴 CRITICAL

---

### 2. Non-Standard Port Analysis

**Objective:** Detect C2 using unusual ports for protocol

**SPL Query - Port-Protocol Mismatch:**
```spl
index=main EventCode=3 Initiated=true 
| search DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*")
| search Protocol=tcp DestinationPort NOT IN ("80", "443", "53", "22", "23", "25", "110", "143", "445", "3306", "3389", "5432")
| search DestinationPort NOT IN ("1", "2", "3", "4", "5", "6", "7", "8", "9", "10")
| stats count by SourceImage, DestinationPort, DestinationIp
| where count >= 3
```

**SPL Query - High Port Range Beacon (>40000):**
```spl
index=main EventCode=3 Initiated=true DestinationPort > 40000
| search DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*")
| stats count as total_conn, 
        dc(SourceImage) as unique_processes 
        by DestinationIp, DestinationPort
| where total_conn >= 5 AND unique_processes >= 1
```

**SPL Query - Protocol Anomaly (DNS for C2):**
```spl
index=dns sourcetype=dns 
| stats count as query_count, 
        dc(query) as unique_domains 
        by client_ip
| where query_count > 10000 OR unique_domains > 500
```

**SPL Query - Port + Time Correlation:**
```spl
index=main EventCode=3 Initiated=true 
| search DestinationPort NOT IN ("80", "443", "53")
| bucket _time span=5m
| stats count by DestinationPort, DestinationIp, _time
| where count >= 2
| stats count as beacon_count by DestinationPort, DestinationIp
| where beacon_count >= 3
```

**What to Look For:**
- ✅ Traffic to high ports (8000+, 40000+) from non-web applications
- ✅ DNS queries with suspicious patterns (DGA-like domains)
- ✅ Connections to same port across multiple days/weeks
- ✅ Port in blacklist databases (42, 6667, 6666 - common malware)
- ✅ Multiple destination ports from single process (port cycling)

**Severity:** 🟠 HIGH

---

### 3. Consistent Data Volume Analysis

**SPL Query - Fixed Byte Count Pattern:**
```spl
index=main EventCode=3 Initiated=true 
| search DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*")
| stats sum(sent_bytes) as total_sent, 
        sum(received_bytes) as total_received,
        count as connection_count 
        by SourceImage, DestinationIp, DestinationPort
| eval sent_per_conn=total_sent/connection_count, 
       recv_per_conn=total_received/connection_count
| where (sent_per_conn > 50 AND sent_per_conn < 500) 
   OR (recv_per_conn > 50 AND recv_per_conn < 500)
| stats count by SourceImage, DestinationIp, DestinationPort
```

**SPL Query - Unidirectional Traffic (C2 Checkouts):**
```spl
index=main EventCode=3 Initiated=true 
| stats sum(sent_bytes) as sent, 
        sum(received_bytes) as received 
        by SourceImage, DestinationIp, DestinationPort
| eval data_ratio=sent/(received+1)
| where data_ratio > 100 OR received = 0
| stats count by SourceImage, DestinationIp
```

**SPL Query - Traffic Variance Analysis:**
```spl
index=main EventCode=3 Initiated=true 
| stats sent_bytes, received_bytes by SourceImage, DestinationIp, DestinationPort, _time
| eventstats avg(sent_bytes) as avg_sent, 
             stdev(sent_bytes) as stdev_sent 
             by SourceImage, DestinationIp, DestinationPort
| where stdev_sent < avg_sent*0.1
| stats count by SourceImage, DestinationIp, DestinationPort
| where count >= 5
```

**What to Look For:**
- ✅ Every connection sends exactly 256 bytes (very suspicious)
- ✅ Minimal variation in payload size
- ✅ Only outbound traffic (one-way communication)
- ✅ Consistent timing + consistent size (strong beaconing indicator)

**Severity:** 🟠 HIGH

---

### 4. Off-Hours Activity Detection

**SPL Query - After-Hours Beaconing:**
```spl
index=main EventCode=3 Initiated=true 
| search DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*")
| eval hour=strftime(_time, "%H"), 
       day=strftime(_time, "%A"),
       is_business=(hour>=8 AND hour<=18 AND day NOT IN ("Saturday", "Sunday"))
| where is_business=0
| stats count by SourceImage, DestinationIp, DestinationPort, hour, day
| where count >= 3
```

**SPL Query - Weekend Activity:**
```spl
index=main EventCode=3 Initiated=true 
| search DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*")
| eval day=strftime(_time, "%A")
| where day IN ("Saturday", "Sunday")
| stats count by Computer, SourceImage, DestinationIp
| where count >= 2
```

**SPL Query - Midnight Connections:**
```spl
index=main EventCode=3 Initiated=true 
| search DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*")
| eval hour=strftime(_time, "%H")
| where hour IN ("00", "01", "02", "03", "04", "05")
| stats count by Computer, SourceImage, DestinationIp
```

**What to Look For:**
- ✅ Connections outside 8 AM - 6 PM on weekdays
- ✅ Regular connections on weekends
- ✅ Beaconing during business outage window
- ✅ Patterns suggesting attacker timezone

**Severity:** 🟡 MEDIUM

---

### 5. Encrypted Traffic Analysis

**SPL Query - SSL/TLS to Suspicious IPs:**
```spl
index=main sourcetype=ssl 
| search DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*")
| stats count as tls_connections by SourceImage, DestinationIp, DestinationPort, ssl_issuer
| where tls_connections >= 3
| search ssl_issuer NOT IN ("*.microsoft.com", "*.apple.com", "*.google.com", "*.amazon.com")
```

**SPL Query - Self-Signed Certificate Beaconing:**
```spl
index=main sourcetype=ssl ssl_subject NOT IN ("*.microsoft.com", "*.google.com")
| search ssl_issuer=ssl_subject
| search DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*")
| stats count by SourceImage, DestinationIp, ssl_subject
| where count >= 3
```

**SPL Query - Certificate Entropy Analysis:**
```spl
index=main sourcetype=ssl 
| search DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*")
| stats values(ssl_certificate) as certs by DestinationIp
| eval cert_count=mvcount(certs)
| where cert_count >= 50
```

**What to Look For:**
- ✅ Self-signed certificates from external IPs
- ✅ Mismatched domain in certificate (IP vs domain)
- ✅ Unusual SSL subject names
- ✅ Connections to IP directly (bypassing DNS)

**Severity:** 🟠 HIGH

---

### 6. DNS Beaconing

**SPL Query - DNS Query Frequency Anomaly:**
```spl
index=dns sourcetype=dns 
| stats count as query_count by client_ip, query
| eventstats avg(query_count) as avg_query, 
             stdev(query_count) as stdev_query 
             by client_ip
| where query_count > (avg_query + stdev_query*2)
```

**SPL Query - Subdomain Enumeration (DGA):**
```spl
index=dns sourcetype=dns 
| regex query="^[a-zA-Z0-9]{10,}\.example\.com$"
| stats count as query_count by client_ip, query
| where query_count >= 10
| stats count as unique_subdomains by client_ip
| where unique_subdomains >= 50
```

**SPL Query - DNS Query Volume Over Time:**
```spl
index=dns sourcetype=dns 
| bucket _time span=1h
| stats count as queries_per_hour by client_ip, _time
| where queries_per_hour > 100
| stats avg(queries_per_hour) as avg_queries by client_ip
| where avg_queries >= 50
```

**What to Look For:**
- ✅ Thousands of queries to malformed domains (DGA detection)
- ✅ Regular DNS queries to same domain every 5-10 minutes
- ✅ NXDOMAIN responses (failed DNS resolution attempts)
- ✅ DNS queries from unusual processes

**Severity:** 🔴 CRITICAL

---

### 7. Process Anomaly Detection

**SPL Query - Unexpected Network Process:**
```spl
index=main EventCode=3 Initiated=true 
| search DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*")
| search Image NOT IN ("*explorer.exe", "*iexplore.exe", "*firefox.exe", "*chrome.exe", "*powershell.exe", "*cmd.exe")
| stats count by Computer, Image, DestinationIp
| where count >= 2
```

**SPL Query - System Process Network Access:**
```spl
index=main EventCode=3 Initiated=true 
| search Image IN ("*svchost.exe", "*smss.exe", "*lsass.exe", "*services.exe", "*winlogon.exe")
| search DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*", "127.*")
| stats count by Computer, Image, DestinationIp
| where count >= 1
```

**SPL Query - Recently Created Process Beaconing:**
```spl
index=main EventCode=1 Image IN ("*AppData\\*", "*Temp\\*", "*ProgramData\\*")
| join Computer [search index=main EventCode=3 Initiated=true 
                                DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*")]
| stats count by Computer, Image, DestinationIp
```

**What to Look For:**
- ✅ Non-network applications making external connections
- ✅ System services (svchost, services.exe) to external IPs
- ✅ Recently dropped executables establishing connections
- ✅ Process masquerading (fake svchost.exe from non-System32)

**Severity:** 🔴 CRITICAL

---

### 8. Infrastructure Correlation

**SPL Query - Shared C2 Infrastructure (Multiple Systems):**
```spl
index=main EventCode=3 Initiated=true 
| search DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*")
| stats dc(Computer) as affected_systems by DestinationIp, DestinationPort
| where affected_systems >= 2
| fields DestinationIp, DestinationPort, affected_systems
```

**SPL Query - Lateral Movement to C2 Communication:**
```spl
[search index=main EventCode=3 DestinationPort IN (3389, 445, 5985)]
| join Computer [search index=main EventCode=3 Initiated=true 
                                DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*")]
| stats count by Computer
| where count >= 2
```

**SPL Query - ASN/Organization Reputation:**
```spl
index=main EventCode=3 Initiated=true 
| search DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*")
| lookup asn_database DestinationIp OUTPUT asn, organization
| search organization NOT IN ("*Microsoft*", "*Google*", "*Amazon*", "*Apple*", "*Adobe*")
| stats count by organization, DestinationIp
| where count >= 3
```

**What to Look For:**
- ✅ Multiple systems connecting to same IP (infrastructure takeover)
- ✅ C2 server shared across many malware samples
- ✅ ASN owned by bulletproof hosting provider
- ✅ IP on threat intelligence lists

**Severity:** 🔴 CRITICAL

---

## 🔗 C2 Chain Analysis

**SPL Query - Compromise Chain: Execution → Lateral Movement → C2:**
```spl
[search index=main EventCode=1 Image IN ("*powershell.exe", "*cmd.exe") CommandLine IN ("*IEX*", "*WebClient*")]
| join Computer [search index=main EventCode=3 DestinationPort IN (445, 3389, 5985)]
| join Computer [search index=main EventCode=3 Initiated=true 
                                DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*")]
| stats count by Computer, User
| where count >= 3
```

**SPL Query - Indicators Convergence (Persistence + Beaconing):**
```spl
[search index=main EventCode=13 TargetObject IN ("*Run", "*Services*")]
| join Computer [search index=main EventCode=3 Initiated=true 
                                DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*") 
                                frequency >= 2]
| stats count by Computer, User
```

---

## 🎓 Investigation Workflow

```
1. IDENTIFY POTENTIAL BEACON
   └─ Alert from IDS/Firewall
   └─ Suspicious connection pattern
   └─ Manual review

2. VALIDATE BEACONING CHARACTERISTICS
   └─ Is connection periodic?
   └─ Is destination external?
   └─ Is byte count consistent?
   └─ Is timing anomalous?

3. PROCESS & INFRASTRUCTURE ANALYSIS
   └─ Is process legitimate?
   └─ Where was process created?
   └─ Is destination blacklisted?
   └─ Is destination associated with malware?

4. HISTORICAL ANALYSIS
   └─ When did beaconing start?
   └─ How many different C2 destinations?
   └─ Has beacon changed patterns?
   └─ Any successful commands executed?

5. SYSTEM CORRELATION
   └─ How many systems affected?
   └─ Lateral movement detected?
   └─ Shared infrastructure?
   └─ Common compromise vector?

6. COMMAND EXECUTION DETECTION
   └─ Look for execute commands
   └─ Elevated privileges?
   └─ File modifications?
   └─ Persistence installations?

7. ESCALATE & RESPOND
   └─ Isolate system(s)
   └─ Block C2 infrastructure
   └─ Preserve memory/disk forensics
   └─ Initiate IR procedures
```

---

## 📋 C2 Detection Checklist

- [ ] Is connection periodic and consistent?
- [ ] Is destination external/untrusted?
- [ ] Is connection data volume anomalous?
- [ ] Is process expected to make network connections?
- [ ] Is destination on threat intelligence lists?
- [ ] Is connection encrypted (suspicious certificate)?
- [ ] Are multiple systems connecting to same IP?
- [ ] Does beacon continue after application restart?
- [ ] Is there evidence of command execution?
- [ ] Is there persistence mechanism installed?

---

## 🛡️ Defense Strategies

**Detection:**
- Monitor outbound connections to non-whitelisted IPs
- Baseline process network behavior
- Alert on beaconing patterns
- Monitor SSL/TLS certificate anomalies

**Prevention:**
- Network segmentation (prevent C2 communication)
- DNS filtering (block known malicious domains)
- Endpoint protection with behavioral detection
- Application whitelisting

**Response:**
- Immediately isolate affected systems
- Block C2 infrastructure at firewall/proxy
- Preserve forensic evidence
- Threat hunt for related compromises
- Implement network detection

---

## 📚 Resources

- [ATT&CK Command & Control](https://attack.mitre.org/tactics/TA0011/)
- [Shodan (IP Intelligence)](https://www.shodan.io)
- [URLhaus (Malware Infrastructure)](https://urlhaus.abuse.ch)
- [Feodo Tracker (C2 Database)](https://feodotracker.abuse.ch)
- [C2 Classification](https://attack.mitre.org/software/)
- [SANS Hunt Instruction](https://www.sans.org/cyber-aces/)

---

## 🔬 Common C2 Frameworks

| Framework | Ports | Protocol | Indicators |
|-----------|-------|----------|------------|
| Cobalt Strike | 50050, 80, 443, 8080 | HTTPS | Beaconing, JA3 fingerprint |
| Metasploit | 4444, 8443, 8080 | TCP/HTTPS | Reverse shell patterns |
| Empire | 80, 443, 8080, 8443 | HTTP/HTTPS | PowerShell C2 |
| Sliver | 8888, 443 | HTTPS | gRPC communication |
| BabyShark | 53, 80, 443 | DNS/HTTP | DNS beaconing |
