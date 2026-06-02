# 🔍 Attack 01: Port Scanning with nmap

**Objective:** Scan the victim Windows 10 VM to discover open ports and services using `nmap` from Kali Linux.

**Tool:** nmap  
**MITRE Technique:** [T1046 - Network Service Discovery](https://attack.mitre.org/techniques/T1046/)  
**Expected Sysmon Event:** EventID 3 (Network Connection)  
**Expected Windows Event:** 5156 (Firewall Allowed Inbound Connection)

---

## 📋 Attack Playbook

### Prerequisites

- ✅ Kali Linux VM with network access to victim
- ✅ Windows 10 VM running with Splunk Universal Forwarder + Sysmon
- ✅ Both VMs on isolated network (NAT or Host-Only)
- ✅ nmap installed on Kali (`apt install nmap -y`)

### Step 1: Identify Victim IP

On **Kali Linux**, get the IP of your Windows 10 victim:

```bash
# Option 1: ARP scanning
arp-scan -l

# Option 2: Ping sweep
nmap -sn 192.168.1.0/24  # Adjust subnet to match your network

# Option 3: If you know the hostname, use host command
host victim-pc.local
```

**Example Output:**
```
Starting Nmap 7.92 at 2025-01-15 10:30 UTC
Nmap scan report for 192.168.1.100
Host is up (0.0045s latency).
```

**Record victim IP:** `192.168.1.100` (example)

---

### Step 2: Perform Basic Port Scan

On **Kali**, execute a standard SYN scan:

```bash
nmap -sS 192.168.1.100
```

**What this does:**
- `-sS` = TCP SYN scan (stealth scan, doesn't complete 3-way handshake)
- Scans top 1000 common ports by default
- Generates minimal logs on older systems

**Expected Output:**
```
Starting Nmap 7.92 at 2025-01-15 10:30 UTC
Nmap scan report for 192.168.1.100
Host is up (0.0045s latency).
Not shown: 995 filtered ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
3389/tcp  open  ms-wbt-server
5357/tcp  open  wsdapi
MAC Address: 08:00:27:AB:CD:EF (VirtualBox)

Nmap done at 2025-01-15 10:30 UTC; 1 IP address (1 host up) scanned in 3.05s
```

---

### Step 3: Aggressive Scan with Service Detection

For more detailed reconnaissance:

```bash
nmap -sS -sV -O -A -p- 192.168.1.100
```

**Flags:**
- `-sS` = TCP SYN scan
- `-sV` = Service version detection (OS fingerprinting)
- `-O` = OS detection
- `-A` = Aggressive (OS + version + script + traceroute)
- `-p-` = All 65535 ports (takes ~5-10 minutes)

**Expected Output (abbreviated):**
```
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds
3389/tcp  open  ms-wbt-server Microsoft Terminal Services (RDP)
5357/tcp  open  wsdapi?
MAC Address: 08:00:27:AB:CD:EF (VirtualBox)

OS CPE: cpe:/o:microsoft:windows:10
OS details: Microsoft Windows 10 21H2 / Server 2016
```

---

### Step 4: Scan for Vulnerabilities (NSE Scripts)

Optional — Use Nmap Scripting Engine:

```bash
# Scan with default NSE scripts
nmap -sS -sC 192.168.1.100

# Scan specifically for SMB vulnerabilities
nmap --script smb-os-discovery,smb-enum-shares -p 445 192.168.1.100

# Scan for MS17-010 (EternalBlue)
nmap --script smb-vuln-ms17-010 -p 445 192.168.1.100
```

---

## 📊 Expected Logs

### Sysmon - EventID 3 (Network Connection Created)

When Sysmon logs outbound connections from the victim's RDP or other services responding to the scan:

```
EventID: 3
Computer: VICTIM-PC
User: NT AUTHORITY\SYSTEM
UtcTime: 2025-01-15 10:30:45.123
Protocol: tcp
SourceIp: 192.168.1.100
SourcePort: 3389
DestinationIp: 192.168.1.10
DestinationPort: 45678
Initiated: true
SourcePortName: ms-wbt-server
DestinationPortName: ''
```

**Key indicators:** Multiple short-lived connections on different ports from attacker IP.

---

### Windows Firewall Log (EventID 5156)

```
EventID: 5156
Computer: VICTIM-PC
Process: System
Source IP: 192.168.1.10 (Kali attacker)
Destination IP: 192.168.1.100 (Victim)
Destination Port: 445, 3389, 135, 139, 22, etc.
Protocol: TCP
Action: Allow
Direction: Inbound
```

---

### Windows Security Log (EventID 4625 if RDP attempts)

If nmap triggers logon failures:

```
EventID: 4625
Computer: VICTIM-PC
Failure Reason: Unknown user name or bad password
Account Name: Administrator
Workstation Name: KALI-LINUX (reversed DNS)
Source IP: 192.168.1.10
Source Port: Random high port
```

*(This only occurs if services try to authenticate.)*

---

## 🔍 Detection in Splunk

### SPL Query: Detect Port Scan Activity

```spl
sourcetype=sysmon EventID=3 DestinationIp=192.168.1.100
| stats dc(DestinationPort) as unique_ports by SourceIp
| where unique_ports > 20
```

**Logic:** If a single source IP connects to 20+ different ports in a short window, it's likely a scan.

---

### SPL Query: Firewall Inbound Connections

```spl
source="Windows Firewall" EventCode=5156 Action=Allow Direction=Inbound
| where DestinationPort IN (135, 139, 445, 3389, 22)
| stats count by SourceIp, DestinationPort
| where count > 5
```

---

### SPL Query: Consecutive Failed RDP Logins

```spl
EventCode=4625 Reason="Unknown user" DestinationPort=3389
| stats count by SourceIp
| where count > 3
```

---

## 🛡️ Mitigation & Defense

| Defense | Implementation |
|---------|---|
| **IDS/IPS** | Deploy Snort/Suricata to block aggressive scans |
| **Firewall** | Restrict inbound connections to essential ports only |
| **EDR/XDR** | Monitor Sysmon EventID 3 for anomalous port patterns |
| **SIEM Alert** | Trigger on >20 unique destination ports from single source in 5 min |
| **Network Segmentation** | Isolate critical systems from attacker network |

---

## 📝 Timeline

| Time | Event | Source | Details |
|------|-------|--------|---------|
| 10:30:00 | SYN packets to random ports | Network | nmap -sS scan starts |
| 10:30:05 | Firewall logs 5156 events | Windows Security | Inbound SYN packets blocked/allowed |
| 10:30:10 | Sysmon EventID 3 logged | Sysmon | Network connections from victim response |
| 10:30:15 | Scan completes | Kali | Results displayed, attacker has port info |

---

## 🎓 Learning Objectives

✅ Understand how passive network reconnaissance appears in logs  
✅ Identify port scan patterns in Firewall & Sysmon data  
✅ Use SPL to correlate multiple network events  
✅ Baseline vs. anomaly detection in port scanning

---

## ⚠️ Important Notes

- **Stealth Variations:** Try `-sU` (UDP scan), `-sA` (ACK scan), `-sF` (FIN scan) to see different log patterns
- **Decoy Scans:** `nmap -D 192.168.1.50,192.168.1.60 192.168.1.100` adds decoy IPs to confuse SOC
- **Fragmentation:** `nmap -f 192.168.1.100` fragments packets to evade basic IDS
- **Timing Templates:** `-T5` (insane/fast) generates more logs; `-T1` (sneaky) is slower and quieter

---

## 📚 References

- [NMAP Official Docs](https://nmap.org/book/)
- [Sysmon EventID 3 Reference](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Windows 5156 Event Details](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-detailed-tracking)
- [MITRE T1046](https://attack.mitre.org/techniques/T1046/)
