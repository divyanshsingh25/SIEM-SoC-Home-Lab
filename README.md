

# 🛡️ SIEM & SOC Home Lab

 A fully documented, hands-on SOC analyst lab built with Splunk Enterprise, Sysmon, Kali Linux, and Windows 10. Covers installation, configuration, attack simulation, detection engineering, threat hunting, and dashboard building.


## 🏗️ Lab Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                  Physical Host — Windows                     │
│            Splunk Enterprise  •  localhost:8000              │
│                   Indexer + Search Head                      │
│                      Port 9997 ◄─────────────────────┐       │
└──────────────────────────────────────────────────────────────┘
                                                        │ TCP 9997
                                                        │ (log forwarding)
┌──────────────────────────┐      ┌─────────────────────────────────┐
│     Kali Linux VM        │      │      Windows 10 VM (Victim)     │
│       Attacker           │─────►│   Splunk Universal Forwarder    │
│                          │      │   Sysmon (SwiftOnSecurity)      │
│  nmap  •  Metasploit     │      │   Windows Event Logs            │
│  Hydra •  CrackMapExec   │      │   Security / System / App       │
│  Atomic Red Team         │      │                                 │
└──────────────────────────┘      └─────────────────────────────────┘
```

---

## 📁 Repository Structure

```
SIEM-SoC-HomeLab/
│
├── 01-lab-setup/                    # Installation guides + config files
│   ├── splunk-install.md            #   Splunk Enterprise setup on host
│   ├── sysmon-install.md            #   Sysmon + SwiftOnSecurity config
│   ├── universal-forwarder.md       #   UF install & configuration guide
│   ├── inputs.conf                  #   Forwarder input configuration
│   ├── outputs.conf                 #   Forwarder output (→ host:9997)
│   ├── sysmonconfig.xml             #   SwiftOnSecurity Sysmon ruleset
│   └── indexes.conf                 #   Splunk index definitions
│
├── 02-log-sources/                  # Log source reference documentation
│   ├── windows-event-logs.md
│   ├── sysmon-event-ids.md
│   └── network-logs.md
│
├── 03-attack-simulation/            # Attack scenarios run from Kali
│   ├── 01-port-scanning.md
│   ├── 02-brute-force-rdp.md
│   ├── 03-metasploit-payload.md
│   ├── 04-lateral-movement.md
│   └── 05-atomic-red-team.md
│
├── 04-detection-rules/              # SPL detection queries
│   ├── port-scan-detection.spl
│   ├── brute-force-detection.spl
│   ├── suspicious-process.spl
│   ├── lateral-movement.spl
│   └── privilege-escalation.spl
│
├── 05-analysis/                     # Log analysis & investigation
│   ├── sysmon-analysis.md
│   ├── windows-security-logs.md
│   └── network-connection-analysis.md
│
├── 06-threat-hunting/               # Threat hunting playbooks
│   ├── hunting-living-off-the-land.md
│   ├── hunting-persistence.md
│   └── hunting-c2-beacons.md
│
├── 07-dashboards/                   # Splunk dashboard XMLs
│   ├── security-overview.xml
│   ├── brute-force-monitor.xml
│   └── process-activity.xml
│
├── 08-mitre-mapping/                # MITRE ATT&CK mappings
│   ├── techniques-covered.md
│   └── mitre-matrix.md
│
├── 09-screenshots/                  # Lab screenshots & evidence
│   └── ...
│
└── README.md
```

---

## 🚀 Quick Start

### Prerequisites

| Tool | Purpose | Link |
|---|---|---|
| VMware / VirtualBox | Hypervisor | [vmware.com](https://www.vmware.com) |
| Splunk Enterprise | SIEM (free 500MB/day) | [splunk.com](https://www.splunk.com/en_us/download/splunk-enterprise.html) |
| Splunk Universal Forwarder | Log shipping | [splunk.com](https://www.splunk.com/en_us/download/universal-forwarder.html) |
| Sysmon | Endpoint telemetry | [sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) |
| Kali Linux | Attack simulation | [kali.org](https://www.kali.org/get-kali/) |

### Setup Order

```
01-lab-setup  →  02-log-sources  →  03-attack-simulation
                                           ↓
             08-mitre-mapping  ←  07-dashboards  ←  06-threat-hunting
                                           ↑
                          04-detection-rules  →  05-analysis
```

---

## 📂 Folder Guide

### `01-lab-setup`
Everything needed to get the lab running — install guides for Splunk Enterprise, Sysmon, and the Universal Forwarder, plus all raw config files (`inputs.conf`, `outputs.conf`, `sysmonconfig.xml`, `indexes.conf`) in one place.

### `02-log-sources`
Reference documentation on what each log source generates, which Event IDs matter, and how data is indexed in Splunk.

### `03-attack-simulation`
Step-by-step attack playbooks executed from Kali Linux. Each file covers the objective, exact commands, and what logs are expected to be generated on the victim.

### `04-detection-rules`
Standalone SPL `.spl` files — one detection per file. Ready to paste into Splunk as saved searches or scheduled alerts.

### `05-analysis`
Post-attack investigation walkthroughs. How to pivot across log sources, reconstruct attacker timelines, and triage alerts.

### `06-threat-hunting`
Hypothesis-driven hunting playbooks covering LOLBins, persistence mechanisms, and C2 beacon patterns.

### `07-dashboards`
Splunk dashboard XML files. Import via Settings → User Interface → Dashboards → Import XML.

### `08-mitre-mapping`
Maps every attack scenario and detection rule to its MITRE ATT&CK technique ID.

---

## ⚔️ Attack Scenarios Covered

| # | Attack | Tool | Sysmon Event | MITRE |
|---|---|---|---|---|
| 01 | Port Scan | nmap | EventID 3 | T1046 |
| 02 | RDP Brute Force | Hydra | EventID 4625 | T1110.001 |
| 03 | Reverse Shell | Metasploit | EventID 1, 3 | T1059 |
| 04 | Lateral Movement | CrackMapExec | EventID 4624 | T1021.002 |
| 05 | LOLBIN Execution | Atomic Red Team | EventID 1 | T1218 |
| 06 | Persistence | Reg / Sched. Task | EventID 13 | T1053 |


---

## 📚 References

- [Splunk Docs](https://docs.splunk.com)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [MITRE ATT&CK](https://attack.mitre.org)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [Boss of the SOC Dataset](https://github.com/splunk/botsv3)
- [Splunk Security Essentials](https://splunkbase.splunk.com/app/3435)
- [TryHackMe SOC Level 1](https://tryhackme.com/path/outline/soclevel1)

---

## ⚠️ Disclaimer

This lab is built for **educational and research purposes only**. All attacks are performed inside an **isolated virtual network**. Never use these techniques on systems you do not own or have explicit written permission to test.

---

## 👤 Author

**Divyansh Singh**
- 🐙 GitHub:  https://github.com/divyanshsingh25
- 💼 LinkedIn:https://www.linkedin.com/in/divyansh-singh-8b8955381

---

*Learn. Attack. Detect. Repeat.* 🔁
