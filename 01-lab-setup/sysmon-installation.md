# 📊 Sysmon Installation & Configuration Guide

## Overview

**Sysmon** (System Monitor) is a Windows system service and device driver that provides detailed information about process creations, network connections, and changes to file creation time. In this lab, we'll install Sysmon with the **SwiftOnSecurity configuration** - an industry-standard ruleset for enhanced endpoint telemetry.



## Prerequisites

- **OS**: Windows 10/11 VM (separate from Splunk host)
- **Admin Access**: Required for installation
- **Disk Space**: Minimal (50MB)
- **Network**: Connection to Splunk host (port 9997)
- **Antivirus**: May interfere with Sysmon (whitelist if needed)

---

## Download Sysmon

### Step 1: Download from Microsoft Sysinternals

1. Open **PowerShell** on your Windows 10 VM
2. Navigate to a download directory:
```powershell
cd C:\Users\$env:USERNAME\Downloads
```

3. Download Sysmon (direct link):
```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
```

**OR manually download from**: [Sysmon Download Page](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

![Download Sysmon](../09-screenshots/sysmon-01-download.png)

### Step 2: Extract Files

```powershell
Expand-Archive -Path "C:\Users\$env:USERNAME\Downloads\Sysmon.zip" -DestinationPath "C:\Sysmon"
```

Verify extraction:
```powershell
ls C:\Sysmon
```

Expected files:
```
Directory: C:\Sysmon

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        2024-01-15   08:30:15       123456 Sysmon.exe
-a----        2024-01-15   08:30:15        45678 Sysmon64.exe
-a----        2024-01-15   08:30:15        34567 sysmonconfig.xml
```



## Download SwiftOnSecurity Config

### Step 1: Clone or Download Config

The SwiftOnSecurity Sysmon config is an enhanced ruleset that improves logging coverage. Download it:

```powershell
cd C:\Sysmon
```

**Option A: Download from GitHub**
```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig.xml" `
  -OutFile "sysmonconfig-swift.xml"
```

**Option B: Manual Download**
1. Visit: https://github.com/SwiftOnSecurity/sysmon-config
2. Click **"sysmonconfig.xml"**
3. Right-click **"Raw"** button
4. Select **"Save link as..."**
5. Save to `C:\Sysmon\sysmonconfig-swift.xml`



### Step 2: Verify Downloaded Config

```powershell
Get-ChildItem C:\Sysmon\sysmonconfig-swift.xml
```



---

## Installation Steps

### Step 1: Open PowerShell as Administrator

1. Right-click **PowerShell** in Start menu
2. Select **"Run as administrator"**
3. Click **"Yes"** to UAC prompt


### Step 2: Install Sysmon Service

Navigate to Sysmon directory and install:

```powershell
cd C:\Sysmon
.\Sysmon64.exe -i -n -l -accepteula
```

**Parameter Explanation**:
- `-i` : Install service and driver
- `-n` : Do not apply config on install
- `-l` : Log to local event log
- `-accepteula` : Accept Sysinternals license automatically

**Expected Output**:
```
Sysmon installed.
Starting sysmon64...
sysmon64 started.
```


### Step 3: Load SwiftOnSecurity Configuration

```powershell
.\Sysmon64.exe -c C:\Sysmon\sysmonconfig-swift.xml -l -accepteula
```

**Expected Output**:
```
Loading config from C:\Sysmon\sysmonconfig-swift.xml...
Config loaded
```


### Step 4: Verify Service Installation

Check that Sysmon service is running:

```powershell
Get-Service | Where-Object {$_.Name -like "*Sysmon*"} | Select-Object Status, DisplayName
```

Expected output:
```
Status DisplayName
------ -----------
Running Sysmon64
```



### Step 5: Verify in Services Manager

1. Press **Win + R**
2. Type `services.msc`
3. Look for **"Sysmon64"** service
4. Verify **Status** is **"Running"**



---

## Verification

### Check Event Log

1. Open **Event Viewer**:
   - Press **Win + R**
   - Type `eventvwr.msc`
   - Click **OK**

2. Navigate to: **Windows Logs** → **System**

3. Look for events with **Source: "Sysmon"** or **Source: "Sysmon64"**

4. You should see events similar to:
   - Event ID: 1 (Process creation)
   - Event ID: 3 (Network connection)
   - Event ID: 5 (Process terminated)


### Run Diagnostic Command

```powershell
.\Sysmon64.exe -c
```

This command displays current configuration and statistics:

```
Sysmon v14.x.x - System Monitor
System Service Status: Running
Driver: C:\Windows\System32\drivers\Sysmon64.sys
Config File: C:\Sysmon\sysmonconfig-swift.xml
```

![Sysmon Status](../09-screenshots/sysmon-11-status.png)
*Screenshot 11: Sysmon64 status output*

---

## Sysmon Event Types

The SwiftOnSecurity config captures these key events:

| Event ID | Event Type | Purpose |
|---|---|---|
| **1** | Process Creation | All new processes, includes command line and parent process |
| **3** | Network Connection | Outbound/inbound network connections (DNS, HTTP, C2) |
| **5** | Process Terminated | When processes exit |
| **6** | Driver Loaded | Drivers loaded into kernel (privilege escalation indicator) |
| **7** | Image/DLL Loaded | DLL injection detection |
| **8** | CreateRemoteThread | Process injection techniques |
| **9** | RawAccessRead | Direct disk access (indicators of evil) |
| **10** | ProcessAccess | One process accessing another (process injection) |
| **11** | FileCreate | File creation events |
| **12-14** | Registry Events | Registry modifications (persistence mechanisms) |
| **15** | FileCreateStreamHash | Alternate data streams |
| **17-18** | Pipe Events | Named pipe creation/connection |
| **19-21** | WMI Events | WMI activity (lateral movement) |
| **22** | DNSQuery | DNS lookups (C2 beaconing) |
| **23** | FileDelete | File deletions |
| **24** | ClipboardChange | Clipboard activity |
| **25** | ProcessTampering | Process memory modification |
| **26** | HiddenImport | Hidden imports |
| **27** | FileBlockExecutable | File blocking |
| **28** | FileBlockShredding | File shredding |

---

## Configuration Details

### View Current Configuration

```powershell
.\Sysmon64.exe -c | more
```

Or view the XML file directly:
```powershell
Get-Content C:\Sysmon\sysmonconfig-swift.xml -Head 50
```

![View Configuration](../09-screenshots/sysmon-12-view-config.png)
*Screenshot 12: PowerShell displaying Sysmon configuration*

### Key Configuration Elements

The SwiftOnSecurity config filters events to reduce noise:

```xml
<Sysmon schemaversion="4.82">
  <EventFiltering>
    <!-- Event 1: Process Creation -->
    <RuleGroup name="ProcessCreate" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <!-- Exclude legitimate processes -->
        <Image condition="is">C:\Windows\System32\svchost.exe</Image>
        <CommandLine condition="contains">GoogleUpdate</CommandLine>
      </ProcessCreate>
    </RuleGroup>

    <!-- Event 3: Network Connection -->
    <RuleGroup name="NetworkConnect" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- Include suspicious connections -->
        <DestinationPort condition="is">445</DestinationPort>
        <Protocol condition="is">tcp</Protocol>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

### Customize Configuration (Optional)

To add custom rules:

1. Edit `C:\Sysmon\sysmonconfig-swift.xml`
2. Add filter rules for events of interest
3. Reload configuration:
```powershell
.\Sysmon64.exe -c C:\Sysmon\sysmonconfig-swift.xml -accepteula
```

---

## Monitoring Sysmon Activity

### Real-Time Event Monitoring in PowerShell

Monitor new Sysmon events as they occur:

```powershell
Get-WinEvent -LogName "System" -FilterXPath "*[System[(EventID=1)]]" -Oldest | Select-Object TimeCreated, ID, Message | ft -AutoSize
```

### Monitor DNS Queries (Event ID 22)

```powershell
Get-WinEvent -LogName "System" -FilterXPath "*[System[(EventID=22)]]" | Select-Object TimeCreated, Message | fl
```

### Monitor Network Connections (Event ID 3)

```powershell
Get-WinEvent -LogName "System" -FilterXPath "*[System[(EventID=3)]]" | Select-Object TimeCreated, Message | fl
```

---

## Troubleshooting

### Issue 1: Sysmon Won't Install

**Error**: "Access Denied"

**Solution**:
```powershell
# Run PowerShell as Administrator
# Ensure you're in C:\Sysmon directory
cd C:\Sysmon
.\Sysmon64.exe -i -accepteula
```

### Issue 2: No Events Appearing in Event Log

**Symptom**: Service is running but no Sysmon events in Event Viewer

**Solution**:
1. Verify Sysmon is actually running:
```powershell
Get-Service Sysmon64 | Select-Object Status
```

2. Check Windows Event Log permissions:
```powershell
wevtutil gl System /ca
```

3. Reinstall if needed:
```powershell
.\Sysmon64.exe -u
.\Sysmon64.exe -i -accepteula
```

### Issue 3: High Event Log Usage

**Symptom**: Event log fills up quickly

**Solution**: 
Adjust SwiftOnSecurity config to exclude more events:

Edit `sysmonconfig-swift.xml` and modify filter rules:

```xml
<ProcessCreate onmatch="exclude">
  <Image condition="is">C:\Windows\System32\services.exe</Image>
  <Image condition="is">C:\Windows\System32\lsass.exe</Image>
</ProcessCreate>
```

Reload config:
```powershell
.\Sysmon64.exe -c C:\Sysmon\sysmonconfig-swift.xml -accepteula
```

### Issue 4: Antivirus Blocking Sysmon

**Symptom**: Antivirus flags Sysmon as malware

**Solution**:
1. **Whitelist the driver**: `C:\Windows\System32\drivers\Sysmon64.sys`
2. **Whitelist Sysmon**: `C:\Sysmon\Sysmon64.exe`
3. Check vendor-specific instructions

### Issue 5: Config File Not Loading

**Error**: "Config failed to load"

**Solution**:
1. Validate XML syntax (use online XML validator)
2. Ensure file is in correct format
3. Check file permissions:
```powershell
icacls C:\Sysmon\sysmonconfig-swift.xml
```

4. Try Microsoft's default config first to verify setup works

---

## Advanced: Custom Configuration

### Create Minimal Config for Testing

Create `C:\Sysmon\sysmonconfig-minimal.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<Sysmon schemaversion="4.82">
  <EventFiltering>
    <RuleGroup name="ProcessCreate" groupRelation="or">
      <ProcessCreate onmatch="include"/>
    </RuleGroup>
    
    <RuleGroup name="NetworkConnect" groupRelation="or">
      <NetworkConnect onmatch="include"/>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

Load it:
```powershell
.\Sysmon64.exe -c C:\Sysmon\sysmonconfig-minimal.xml -accepteula
```

---

## Next Steps

✅ Sysmon installed with SwiftOnSecurity config  
✅ Verified events in Event Log  
→ [Next: Universal Forwarder Setup](./universal-forwarder-setup.md)

---

## Useful Resources

- [Sysmon Documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Sysmon Event Types Guide](https://docs.microsoft.com/en-us/windows/security/threat-protection/sysmon/sysmon-event-details)
- [MITRE Sysmon Mapping](https://www.malwarearchaeology.com/sysmon)

---

**Last Updated**: May 2026  
**Version**: 1.0  
**Author**: SIEM-SoC Home Lab
