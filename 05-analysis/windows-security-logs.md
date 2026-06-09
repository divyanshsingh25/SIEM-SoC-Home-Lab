# 🔐 Windows Security Event Log Analysis

## Overview

Windows Security Event Logs provide OS-level visibility into authentication, privilege escalation, account management, and policy changes. This guide covers analyzing these logs in Splunk to detect suspicious activity.

---

## 📋 Critical Event IDs

| EventID | Category | Event Name | Security Relevance |
|---------|----------|-----------|-------------------|
| 4624 | Logon | An account was successfully logged on | Authentication success (baseline for anomalies) |
| 4625 | Logon | An account failed to log on | Brute force attacks, failed access |
| 4720 | Account Management | A user account was created | Unauthorized account creation |
| 4722 | Account Management | A user account was enabled | Account reactivation |
| 4738 | Account Management | A user account was changed | Privilege escalation attempts |
| 4728 | Security Group | A member was added to a security group | Privilege escalation |
| 4732 | Security Group | A member was added to a local group | Local privilege escalation |
| 4756 | Security Group | A member was added to a universal group | Domain privilege escalation |
| 4688 | Process Tracking | A new process has been created | Process execution (detailed logging) |
| 4698 | Scheduled Task | A scheduled task was created | Persistence mechanism |
| 4702 | Scheduled Task | A scheduled task was updated | Persistence modification |
| 4704 | Privilege Use | A user right was assigned | Unauthorized privilege grant |
| 4719 | Policy Change | System audit policy was changed | Audit log tampering |
| 4776 | Credential Validation | The computer attempted to validate credentials | Pass-the-hash attacks |

---

## 🔍 Investigation Techniques

### 1. **Brute Force Attack Detection**

#### Objective: Identify RDP, SSH, or network service brute force attempts

**SPL Query - Failed Logon Attempts:**
```spl
index=main source="WinEventLog:Security" EventCode=4625
| stats count as failed_attempts, values(Computer) as target_systems, 
         values(Account_Name) as accounts by Source_Network_Address
| search failed_attempts > 5
```

**SPL Query - Brute Force Timeline:**
```spl
index=main source="WinEventLog:Security" EventCode=4625 Failure_Reason="*Unknown user*" 
          OR Failure_Reason="*Incorrect password*"
| timechart count by Source_Network_Address limit=10
| search count > 0
```

**SPL Query - Account Lockout Pattern:**
```spl
index=main source="WinEventLog:Security" EventCode IN (4740, 4625)
| stats count as lockout_events by Account_Name, Source_Network_Address
| where lockout_events > 10
```

**What to Look For:**
- ✅ Same source IP, multiple failed attempts (> 5 in 5 minutes)
- ✅ Different account names being tried from same IP (user enumeration)
- ✅ Failed attempts followed by successful logon (successful compromise)
- ✅ Rapid-fire attempts (automated tool behavior)
- ✅ Out-of-hours authentication attempts
- ✅ Failed attempts from unusual source IPs

**Severity Indicators:**
- 🔴 **Critical**: Successful logon after brute force from non-business IP
- 🟠 **High**: > 50 failed attempts in 1 minute from single IP
- 🟡 **Medium**: > 5 failed attempts from external IP
- 🟢 **Low**: Failed attempts from internal IP during business hours

---

### 2. **Lateral Movement Detection**

#### Objective: Identify attackers moving between systems

**SPL Query - Suspicious Logon Type 3 (Network):**
```spl
index=main source="WinEventLog:Security" EventCode=4624 Logon_Type=3
| stats count by Account_Name, Computer, Source_Network_Address
| where count > 20
```

**SPL Query - Pass-the-Hash Detection:**
```spl
index=main source="WinEventLog:Security" EventCode=4776 
Account_Name NOT IN ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
| stats count by Workstation_Name, Account_Name
| search count > 5
```

**SPL Query - Lateral Movement via Services:**
```spl
index=main source="WinEventLog:Security" EventCode IN (4688, 4697)
Image IN (*\\psexec.exe, *\\wmiexec*, *\\dcomexec*)
| stats count by Computer, Account_Name, Image
```

**What to Look For:**
- ✅ Logon Type 3 (Network logons) from non-admin accounts
- ✅ Successful logons immediately after failed attempts
- ✅ Logons from systems that shouldn't communicate
- ✅ Admin accounts logging on from unusual workstations
- ✅ Out-of-hours logon activity
- ✅ Rapid succession logons across multiple systems

---

### 3. **Privilege Escalation Detection**

#### Objective: Identify unauthorized privilege gains

**SPL Query - Group Membership Addition:**
```spl
index=main source="WinEventLog:Security" EventCode IN (4728, 4732, 4756)
| search Member_Name NOT IN ("*$", "SYSTEM", "Domain Admins")
| stats count by Member_Name, Group_Name, Computer
```

**SPL Query - Privilege Escalation via Token Impersonation:**
```spl
index=main source="WinEventLog:Security" EventCode=4624 Logon_Type=9
| stats count by Account_Name, Computer
| where count > 10
```

**SPL Query - Account Modifications:**
```spl
index=main source="WinEventLog:Security" EventCode=4738
| search SAM_Account_Name NOT IN ("krbtgt", "Guest", "DefaultAccount")
| stats count by SAM_Account_Name, Subject_Account_Name
```

**What to Look For:**
- ✅ Non-admin accounts added to admin groups
- ✅ Administrative groups modified by unusual accounts
- ✅ Accounts enabled after being disabled
- ✅ User account upgraded to admin
- ✅ Service accounts assigned high privileges
- ✅ Multiple privilege escalation events in short timespan

---

### 4. **Persistence Mechanism Detection**

#### Objective: Identify methods used for long-term access

**SPL Query - Scheduled Task Creation:**
```spl
index=main source="WinEventLog:Security" EventCode=4698
| search Task_Name NOT IN ("*Microsoft*", "*Windows*")
| stats count by Task_Name, Account_Name, Computer
```

**SPL Query - Service Installation:**
```spl
index=main source="WinEventLog:System" EventCode IN (7000, 7045)
| search Service_Name NOT IN ("Microsoft*", "Windows*")
| stats count by Service_Name, Service_File_Name
```

**SPL Query - Registry Persistence:**
```spl
index=main source="WinEventLog:Security" EventCode=4657
Object_Name IN ("*\\CurrentVersion\\Run*", "*\\CurrentVersion\\RunOnce*")
| stats count by Object_Name, Account_Name
```

**What to Look For:**
- ✅ Scheduled tasks created by non-admin accounts
- ✅ Tasks with suspicious command lines
- ✅ Service files pointing to non-standard locations
- ✅ Registry modifications to Run keys
- ✅ Persistent accounts created for backdoor access
- ✅ Scheduled tasks/services running at off-peak times

---

## 🎯 Logon Types

| Logon Type | Name | Description | Risk Level |
|-----------|------|-----------|-----------|
| 2 | Interactive | User at console | Low (local) |
| 3 | Network | SMB share access | Medium (potential lateral movement) |
| 4 | Batch | Scheduled task execution | Low (expected) |
| 5 | Service | Service startup | Low (expected) |
| 7 | Unlock | Workstation unlock | Low (local) |
| 8 | NetworkCleartext | Network logon with cleartext password | 🔴 **Critical** |
| 9 | NewCredentials | Process with alternate credentials | 🟠 **High** |
| 10 | RemoteInteractive | RDP/Terminal Server | 🟠 **High** |
| 11 | CachedInteractive | Cached credentials | Medium |

---

## 📊 Investigation Workflow

```
1. DETECT SUSPICIOUS EVENT
   └─ Analyze EventCode 4625 or 4624 anomalies

2. COLLECT CONTEXT
   └─ Source IP and Account Name
   └─ Destination computer
   └─ Timestamp and logon type

3. INVESTIGATE TIMELINE
   └─ Review 10 minutes before/after event
   └─ Check for related failures or successes
   └─ Identify pattern (single failure vs. brute force)

4. CHECK LOGON SUCCESS
   └─ Did attacker gain access after failures?
   └─ Search EventCode 4624 same IP/account combo

5. TRACE ACTIVITY POST-LOGON
   └─ EventCode 4688 (process creation) on target system
   └─ EventCode 4732/4728 (privilege escalation)
   └─ Network connections from compromised system

6. ASSESS IMPACT
   └─ What systems accessed?
   └─ What data accessed?
   └─ Administrative actions taken?

7. CONTAIN & RESPOND
   └─ Reset compromised account password
   └─ Audit other recent logons
   └─ Check for persistence mechanisms
```

---

## 💾 Analysis Checklist

- [ ] Is the source IP trusted/authorized?
- [ ] Is the account legitimate?
- [ ] Is the logon type expected?
- [ ] Does logon time align with business hours?
- [ ] Are there preceding failed logon attempts?
- [ ] Was this a successful compromise?
- [ ] Did attacker escalate privileges?
- [ ] Were other systems accessed?
- [ ] Are there persistence mechanisms?
- [ ] Has this account been used before?

---

## ⚠️ Advanced Evasion Detection

**SPL Query - Audit Policy Manipulation:**
```spl
index=main source="WinEventLog:Security" EventCode=4719
| stats count by Account_Name, Computer
| where count > 0
```

**SPL Query - Event Log Clearing:**
```spl
index=main source="WinEventLog:Security" EventCode IN (1100, 1102)
| stats count by Account_Name, Computer
```

**SPL Query - Abnormal Account Activity:**
```spl
index=main source="WinEventLog:Security" EventCode=4624 
| stats values(Computer) as systems, values(Logon_Type) as logon_types 
        by Account_Name
| search Account_Name="*Admin*" AND systems > 5
```

---

## 📚 References

- [Microsoft Event Viewer - Security Events](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-events)
- [Splunk Windows TA](https://splunkbase.splunk.com/app/742)
- [Cyberdefenders - Log Analysis](https://www.cyberdefenders.org)
- [SANS Event ID Cheatsheet](https://www.sans.org)
