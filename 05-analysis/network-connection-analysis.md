# 🌐 Network Connection Analysis & Investigation

## Overview

Network connection logs provide visibility into data flows, lateral movement, C2 communications, and exfiltration. This guide covers analyzing network events in Splunk to detect adversary activity.

---

## 📊 Network Data Sources

| Source | EventID/Type | Key Data | Detection Value |
|--------|-------------|----------|-----------------|
| Sysmon | EventCode 3 | Process-level connections | Which process, IP, port, protocol |
| Windows Firewall | 5150-5159 | Network events | Blocked/Allowed, direction, port |
| DNS Logs | QueryName, QueryStatus | DNS resolutions | C2 domain detection, beaconing |
| Netflow/Network Capture | Flow data | Network-level connections | East-West traffic, volume analysis |
| Proxy Logs | HTTP/HTTPS requests | Web traffic | Malware C2, data exfiltration |
| DHCP Logs | Event 50 | IP lease assignments | Unauthorized devices, VLAN bypass |

---

## 🔍 Investigation Techniques

### 1. **C2 Beacon Detection**

#### Objective: Identify command-and-control communication patterns

**SPL Query - Periodic Outbound Connections:**
```spl
index=main EventCode=3 Initiated=true 
| bucket _time span=1m 
| stats count as conn_count by SourceImage, DestinationIp, DestinationPort, _time
| eventstats avg(conn_count) as avg_count stdev(conn_count) as stdev_count 
            by SourceImage, DestinationIp, DestinationPort
| where count > avg_count + stdev_count
```

**SPL Query - Beaconing Pattern Detection:**
```spl
index=main EventCode=3 Initiated=true 
| stats count as total_connections, 
        latest(_time) as last_connection, 
        earliest(_time) as first_connection by SourceImage, DestinationIp, DestinationPort
| eval duration=last_connection-first_connection, 
       frequency=total_connections/(duration/60)
| where frequency > 2 AND duration > 600
```

**SPL Query - Suspicious Destination Analysis:**
```spl
index=main EventCode=3 Initiated=true 
| search DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*") 
| stats count as connection_count, values(SourceImage) as processes 
        by DestinationIp, DestinationPort
| where connection_count > 50
| lookup reputation_database DestinationIp OUTPUT reputation_score
| search reputation_score < -50
```

**What to Look For:**
- ✅ Regular time-spaced connections to same destination (e.g., every 5 minutes)
- ✅ Non-standard ports (not 80/443/53)
- ✅ Connections to external IPs from suspicious processes
- ✅ Small, consistent data transfers (typical C2 pattern)
- ✅ Connections during off-business hours
- ✅ Same destination across multiple systems (network-wide compromise)
- ✅ Connections to known malicious IPs/ASNs

**Severity Indicators:**
- 🔴 **Critical**: Beaconing to known malware C2, multiple systems affected
- 🟠 **High**: Unknown external IP with consistent beaconing pattern
- 🟡 **Medium**: Unusual port + external IP combination
- 🟢 **Low**: Known allowed traffic with anomalous timing

---

### 2. **Lateral Movement Detection**

#### Objective: Identify attackers moving across the network

**SPL Query - RDP Lateral Movement:**
```spl
index=main EventCode=3 DestinationPort=3389 Protocol=tcp Initiated=true
| stats count as rdp_connections, 
        dc(DestinationIp) as systems_accessed 
        by SourceImage, User
| where rdp_connections > 3 OR systems_accessed > 2
```

**SPL Query - SMB Lateral Movement:**
```spl
index=main EventCode=3 DestinationPort IN (445, 139) Protocol=tcp Initiated=true
| stats count as smb_connections, 
        values(DestinationIp) as target_systems 
        by SourceImage, Computer, User
| where smb_connections > 10
```

**SPL Query - WinRM/PSRemoting Detection:**
```spl
index=main EventCode=3 DestinationPort IN (5985, 5986) Protocol=tcp
| stats count by SourceImage, DestinationIp, User
| where count > 5
```

**SPL Query - Lateral Movement Timeline:**
```spl
index=main EventCode=3 Initiated=true Protocol=tcp 
| search DestinationPort IN (3389, 445, 5985, 135, 139)
| stats count by SourceImage, DestinationIp, _time
| timechart count by DestinationPort
```

**What to Look For:**
- ✅ RDP connections (port 3389) from unexpected source IPs
- ✅ SMB access (port 445) from non-admin accounts
- ✅ Multiple connection attempts to different systems
- ✅ Admin tools connecting to systems outside normal admin patterns
- ✅ Outbound connections from compromised system to other internal IPs
- ✅ Rapid connection attempts across subnets

---

### 3. **Data Exfiltration Detection**

#### Objective: Identify unauthorized data transfer

**SPL Query - High Volume Outbound Traffic:**
```spl
index=main EventCode=3 Initiated=true 
| stats count as connection_count, 
        sum(sent_bytes) as total_sent_bytes 
        by SourceIp, DestinationIp
| where total_sent_bytes > 100000000
| search DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*")
```

**SPL Query - DNS Tunneling Detection:**
```spl
index=dns sourcetype=dns 
| search query_type=A 
| stats count as query_count, dc(query) as unique_domains 
        by client_ip
| where query_count > 10000 OR unique_domains > 500
```

**SPL Query - HTTPS Traffic to Suspicious Domains:**
```spl
index=proxy action=allowed http_method IN (POST, PUT) 
| search dest_ip NOT IN ("192.168.*", "10.*", "172.16.*")
| stats count, sum(bytes_out) as total_bytes 
        by src_ip, dest_ip, dest_fqdn
| where total_bytes > 50000000
```

**What to Look For:**
- ✅ Large outbound data transfers
- ✅ Multiple uploads to cloud services
- ✅ Traffic to known file sharing/paste sites
- ✅ Unusual protocol usage (HTTP/DNS for large data)
- ✅ File transfer tools (curl, wget, scp) activity
- ✅ Encrypted tunnels to external IPs
- ✅ P2P protocol usage from business systems

**Data Exfiltration Red Flags:**
- 🔴 **Critical**: > 1GB exfiltrated to external IP
- 🟠 **High**: Large uploads to cloud storage or paste sites
- 🟡 **Medium**: Unusual port + external IP, moderate volume
- 🟢 **Low**: Small data transfer to suspected attacker IP

---

### 4. **Port Scanning Detection**

#### Objective: Identify reconnaissance activity

**SPL Query - Network Sweep Detection:**
```spl
index=main EventCode=3 Initiated=true 
| stats dc(DestinationIp) as unique_hosts, 
        dc(DestinationPort) as unique_ports 
        by SourceIp
| where unique_hosts > 20 OR unique_ports > 50
```

**SPL Query - SYN Flood/DoS Detection:**
```spl
index=main EventCode=3 Initiated=true Protocol=tcp 
| stats count as connection_attempts by SourceIp, DestinationIp, DestinationPort
| where connection_attempts > 1000
```

**SPL Query - Vertical Port Scan:**
```spl
index=main EventCode=3 Initiated=true 
| stats count as attempts, 
        avg(DestinationPort) as avg_port, 
        stdev(DestinationPort) as port_stdev 
        by SourceIp, DestinationIp
| where attempts > 100 AND port_stdev > 100
```

**What to Look For:**
- ✅ Single source scanning many IPs
- ✅ Many connection attempts to single target
- ✅ Connections to closed/filtered ports
- ✅ Sequential port attempts
- ✅ Out-of-hours scanning activity
- ✅ Non-business tools initiating connections

---

## 🔬 Advanced Network Analysis

### Connection State Analysis

**SPL Query - Unidirectional Traffic:**
```spl
index=main EventCode=3 Initiated=true 
| stats sum(sent_bytes) as sent, sum(received_bytes) as received 
        by SourceIp, DestinationIp
| eval ratio=sent/(received+1)
| where ratio > 100 OR received = 0
```

**SPL Query - Connection Duration Anomaly:**
```spl
index=main EventCode=3 
| eval duration=closed_time - started_time 
| stats avg(duration) as avg_duration, stdev(duration) as stdev_duration 
        by SourceImage, DestinationPort
| eventstats avg(avg_duration) as network_avg by DestinationPort
| where abs(avg_duration - network_avg) > stdev_duration
```

### Geographical Analysis

**SPL Query - Impossible Travel Detection:**
```spl
index=main EventCode=3 Initiated=true 
| search DestinationIp NOT IN ("192.168.*", "10.*", "172.16.*")
| lookup geoip DestinationIp as dest_country 
| stats min(_time) as first_time, max(_time) as last_time by SourceIp, dest_country
| eval time_diff=(last_time - first_time)/3600
| search time_diff < 1
| stats count by SourceIp, dest_country
| where count > 2
```

---

## 📈 Investigation Workflow

```
1. DETECT NETWORK ANOMALY
   └─ Alert from detection rule or manual review

2. INITIAL ASSESSMENT
   └─ Source IP (internal/external)
   └─ Destination IP
   └─ Port and Protocol
   └─ Process involved
   └─ Volume and direction

3. CATEGORIZE THREAT TYPE
   └─ Reconnaissance → Port scanning pattern
   └─ Lateral movement → RDP/SMB/WinRM connections
   └─ C2 → Periodic beaconing pattern
   └─ Exfiltration → High volume outbound

4. CORRELATE WITH ENDPOINT DATA
   └─ Sysmon EventCode=3 (network connections)
   └─ Process parent-child relationships
   └─ File creates/modifications
   └─ Registry changes

5. BUILD ATTACK TIMELINE
   └─ When did activity start?
   └─ How long has it been ongoing?
   └─ Is there escalation pattern?

6. ASSESS SCOPE
   └─ Single system or network-wide?
   └─ Multiple processes involved?
   └─ Persistence mechanisms?

7. DETERMINE SEVERITY & RESPONSE
   └─ Isolate affected systems
   └─ Preserve evidence
   └─ Escalate to incident response
```

---

## 🎯 Common Network Attack Patterns

### Pattern 1: Reconnaissance → Exploitation → C2
```
Day 1: Port scanning (T1046)
       └─ High volume connections to many destinations
       └─ Multiple different ports

Day 1-2: Brute force (T1110)
       └─ Failed logons across multiple accounts
       └─ From same source IP

Day 2: Exploitation (T1003, T1021)
       └─ Process execution from exploit tool
       └─ System compromise

Day 2+: C2 Beaconing (T1071)
       └─ Regular connections to external IP
       └─ Non-standard port
       └─ Encrypted or obfuscated traffic
```

### Pattern 2: Lateral Movement → Persistence
```
Initial Compromise
  └─ Reverse shell connection (T1059)

Lateral Movement (T1021.002)
  └─ RDP/SMB connections to other systems
  └─ Credential re-use across network
  └─ Admin account abuse

Persistence (T1053, T1547)
  └─ Scheduled task creation
  └─ Service installation
  └─ Registry modifications
```

---

## 💾 Analysis Checklist

- [ ] Is source IP trusted/whitelisted?
- [ ] Is destination IP known malicious?
- [ ] Is port/protocol expected for process?
- [ ] Is traffic volume normal?
- [ ] Is timing aligned with business hours?
- [ ] Are multiple systems involved?
- [ ] Is this encrypted traffic?
- [ ] Can destination be resolved to domain?
- [ ] Is process legitimate for this activity?
- [ ] Is there supporting endpoint evidence?

---

## 🛠️ Useful Tools for Network Analysis

**Splunk Lookups:**
```spl
lookup reputation_database ip OUTPUT reputation_score
lookup asn_database ip OUTPUT asn, organization
lookup geoip ip OUTPUT country, city, latitude, longitude
```

**Network Enrichment:**
```spl
index=main | lookup http_status_codes status OUTPUT status_description
| lookup process_whitelist Image OUTPUT is_whitelisted
| lookup dns_sinkhole QueryName OUTPUT is_sinkholed
```

---

## 📚 References

- [NIST Network Monitoring](https://nvlpubs.nist.gov/nistpubs/)
- [ATT&CK C2 Techniques](https://attack.mitre.org/techniques/T1071/)
- [Splunk Network TA](https://splunkbase.splunk.com/app/1621)
- [Zeek Network Analysis](https://zeek.org)
- [NetFlow Analysis Best Practices](https://www.cisco.com/c/en/us/products/ios-nx-os-software/netflow/index.html)
- [Splunk Threat Research Lab](https://research.splunk.com)
