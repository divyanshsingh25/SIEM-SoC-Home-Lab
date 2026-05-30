# 🪟 Windows Event Logs Reference

## 🎯 The 3 Essential Channels

| Channel | Location | Key Use | Event IDs to Hunt |
|---------|----------|---------|-------------------|
| **Security** | `C:\Windows\System32\winevt\Logs\Security.evtx` | Auth, Privileges, Audit | 4624, 4625, 4720, 4722 |
| **System** | `C:\Windows\System32\winevt\Logs\System.evtx` | Services, Drivers, Boots | 7000, 7045 |
| **Application** | `C:\Windows\System32\winevt\Logs\Application.evtx` | App Crashes, Errors | Varies by app |

---

## 🔴 RED FLAGS — Critical Event IDs

### Authentication & Logon
| ID | Event | 🚨 Severity | Why? |
|----|-------|-----------|------|
| **4624** | Successful Logon | 🟢 Normal | Baseline for comparison |
| **4625** | Failed Logon | 🔴 ALERT | Brute force attempts |
| **4720** | User Created | 🔴 ALERT | Rogue account creation |
| **4722** | User Enabled | 🔴 ALERT | Disabled account re-enabled |
| **4732** | Member Added to Group | 🔴 ALERT | Privilege escalation |
| **4728** | Member Added to Security Group | 🔴 ALERT | Privilege escalation |

### Process & Execution
| ID | Event | 🚨 Severity | Red Flags |
|----|-------|-----------|-----------|
| **4688** | Process Created | 🟡 Monitor | cmd.exe, powershell.exe from suspicious parents |
| **4697** | Service Installed | 🔴 ALERT | Unknown services |
| **7045** | Service Created (System log) | 🔴 ALERT | Persistence mechanism |

### Privilege Escalation
| ID | Event | 🚨 Severity | Look For |
|----|-------|-----------|----------|
| **4673** | Privilege Use | 🔴 ALERT | SeImpersonatePrivilege abuse |
| **4898** | Audit Policy Changed | 🔴 ALERT | Attacker disabling logging |

---

## 📊 What Gets Logged Where?

```
📋 SECURITY LOG
├─ ✅ User Logins (Local & Network)
├─ ✅ Failed Login Attempts
├─ ✅ Group Policy Changes
├─ ✅ Permissions Changes
├─ ✅ Account Lockouts
└─ ✅ Privilege Usage

🔧 SYSTEM LOG
├─ ✅ Service Start/Stop
├─ ✅ Driver Load/Unload
├─ ✅ System Startup/Shutdown
├─ ✅ Service Installation
└─ ✅ Hardware Changes

📱 APPLICATION LOG
├─ ✅ Application Errors
├─ ✅ Service Crashes
├─ ✅ Database Events
└─ ✅ Custom App Logs
```

---

## 🎓 Quick Tips for SOC Analysts

✅ **Enable Audit Policies** → Without these, events won't log!  
✅ **Focus on Failures First** → 4625 (failed logins) often reveal attacks  
✅ **Watch for Account Enumeration** → Multiple 4625s from same source = recon  
✅ **Track Disabled Auditing** → Event 4898 = attacker hiding tracks  

---

## 🔗 Sysmon vs Windows Events

**Windows Events** = OS-level authentication & service changes  
**Sysmon** = Detailed process execution & network connections  

💡 **Pro Tip:** Use Windows Events for *who* logged in. Use Sysmon for *what* they executed.
