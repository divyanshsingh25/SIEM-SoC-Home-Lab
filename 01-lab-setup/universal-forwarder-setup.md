# 🔗 Splunk Universal Forwarder Setup

## Installation

1. Download from [Splunk Downloads](https://www.splunk.com/en_us/download/universal-forwarder.html)
2. Run `.msi` as Administrator
3. Accept license, select **Local System** account
4. Set forwarding server: `localhost:9997` or `<HOST_IP>:9997`
5. Complete installation

## Configuration Files

### Create inputs.conf

Path: `C:\Program Files\SplunkUniversalForwarder\etc\apps\SplunkUniversalForwarder\local\inputs.conf`

```ini
[WinEventLog://Security]
disabled = false
index = wineventlog
sourcetype = WinEventLog:Security

[WinEventLog://System]
disabled = false
index = sysmon
sourcetype = sysmon

[WinEventLog://Application]
disabled = false
index = wineventlog
sourcetype = WinEventLog:Application
```

### Create outputs.conf

Path: `C:\Program Files\SplunkUniversalForwarder\etc\apps\SplunkUniversalForwarder\local\outputs.conf`

```ini
[tcpout]
defaultGroup = splunk_indexer
maxQueueSize = auto

[tcpout:splunk_indexer]
server = localhost:9997
```

## Restart Service

```powershell
Restart-Service -Name "SplunkForwarder" -Force
```

## Verify

```powershell
# Check service running
Get-Service SplunkForwarder

# Test connection
Test-NetConnection -ComputerName localhost -Port 9997

# Check logs
Get-Content "C:\Program Files\SplunkUniversalForwarder\var\log\splunk\splunkd.log" -Tail 20
```

## Search in Splunk

Go to Splunk Web → Search:

```spl
index=wineventlog OR index=sysmon | stats count by host, sourcetype
```

---

**Version**: 1.0 | **Last Updated**: May 2026
