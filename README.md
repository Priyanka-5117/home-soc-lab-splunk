
🛡️ Home SOC Lab — Splunk SIEM + OPNsense + Sysmon + Kali Linux

![SIEM](https://img.shields.io/badge/SIEM-Splunk_Enterprise_10.4-orange?style=for-the-badge&logo=splunk)
![Firewall](https://img.shields.io/badge/Firewall-OPNsense_26.1-blue?style=for-the-badge)
![Endpoint](https://img.shields.io/badge/Endpoint-Windows_10_+_Sysmon-lightblue?style=for-the-badge&logo=windows)
![Attacker](https://img.shields.io/badge/Attacker-Kali_Linux-red?style=for-the-badge&logo=kalilinux)
![Framework](https://img.shields.io/badge/Framework-MITRE_ATT%26CK-yellow?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

*Project Overview*

This project documents the end-to-end design, deployment, and operation of a **home Security Operations Center (SOC) lab** built entirely from scratch using industry-standard tools. The lab simulates a real enterprise environment where attacks are launched, detected, investigated, and documented — replicating the daily workflow of a Tier 1 and Tier 2 SOC Analyst.

Every detection rule is mapped to the **MITRE ATT&CK framework**, every attack is documented as a **formal incident report**

*Lab Architecture*
┌─────────────────────────────────────────────────────────┐
│                    HOME SOC LAB                         │
│                                                         │
│  Kali Linux (Attacker)                                  │
│  IP: 10.0.0.30                                          │
│       │                                                 │
│       ▼                                                 │
│  OPNsense Firewall ──── logs ────► Splunk SIEM          │
│  IP: 10.0.0.1                      IP: 10.0.0.5:8000    │
│       │                                 ▲               │
│       ▼                                 │ Splunk UF     │
│  Windows 10 Endpoint ───────────────────┘               │
│  IP: 10.0.0.10                                          │
│  + Sysmon v15 (SwiftOnSecurity config)                  │
│                                                         │
│  Hypervisor: VirtualBox 7.2 on Windows 11 Host          │
└─────────────────────────────────────────────────────────┘

**Network:** All VMs communicate over a VirtualBox Host-Only network (10.0.0.0/24). OPNsense acts as the perimeter gateway. Splunk receives logs from all endpoints via Universal Forwarder (TCP 9997) and OPNsense syslog (UDP 514).


*Tools & Technologies*

| Category                 | Tool                       | Version | Purpose                                               |
|---|---|---|---|
| SIEM                     | Splunk Enterprise          | 10.4.0  | Log ingestion, correlation, alerting, dashboards      |
| Firewall                 | OPNsense                   | 26.1.6  | Network segmentation, traffic logging                 |
| EDR/Telemetry            | Sysmon                     | v15     | Deep endpoint visibility — process, network, registry |
| Log Forwarder            | Splunk Universal Forwarder | 10.4.0  | Ships Windows logs to Splunk                          |
| Attacker Machine         | Kali Linux                 | 2024.2  | Attack simulation — Hydra, Nmap, Metasploit           |
| Endpoint OS              | Windows 10 Pro             | 22H2    | Monitored target system                               |
| Hypervisor               | VirtualBox                 | 7.2.6   | Lab virtualization on Windows 11 host                 |
| Framework                | MITRE ATT&CK               | v14     | Detection mapping and threat categorization           |


*Data Sources Configured*

| Source                     | Index    | Sourcetype            | Events Collected           |
|---|---|---|---|
| Windows Security Event Log | windows  | WinEventLog:Security  | 2,200+ events              |
| Windows Sysmon             | windows  | XmlWinEventLog:Sysmon | Process, network, registry |
| OPNsense Firewall          | opnsense | syslog                | Firewall allow/block rules |


*Detection Rules — SPL Queries*

All detections are saved as **real-time Splunk Alerts** and mapped to **MITRE ATT&CK**.

### Detection 1 — Brute Force Login Attack
**MITRE: T1110 | Tactic: Credential Access | Severity: 🔴 High**
```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, Source_Network_Address
| where count > 3
| eval mitre_technique="T1110 - Brute Force"
| eval severity="High"
| table Account_Name, Source_Network_Address, count, mitre_technique, severity
```

### Detection 2 — Backdoor Account Creation
**MITRE: T1136.001 | Tactic: Persistence | Severity: 🔴 High**
```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4720
| eval mitre_technique="T1136.001 - Create Local Account"
| eval severity="High"
| table _time, host, Account_Name, Sam_Account_Name, mitre_technique, severity
```

### Detection 3 — Privileged Account Usage
**MITRE: T1078 | Tactic: Privilege Escalation | Severity: 🟡 Medium**
```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4672
| stats count by Account_Name
| where Account_Name!="SYSTEM" AND Account_Name!="LOCAL SERVICE"
| eval mitre_technique="T1078 - Valid Accounts"
| eval severity="Medium"
| table Account_Name, count, mitre_technique, severity
| sort -count
```

### Detection 4 — Suspicious PowerShell Execution
**MITRE: T1059.001 | Tactic: Execution | Severity: 🔴 High**
```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4688
| search New_Process_Name="*powershell*"
| eval mitre_technique="T1059.001 - PowerShell"
| eval severity="High"
| table _time, host, Account_Name, New_Process_Name, 
  Process_Command_Line, mitre_technique, severity
```

### Detection 5 — Account Lockout
**MITRE: T1110 | Tactic: Credential Access | Severity: 🔴 High**
```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4740
| eval mitre_technique="T1110 - Brute Force"
| eval severity="High"
| table _time, host, Account_Name, Caller_Computer_Name, 
  mitre_technique, severity
| sort -_time
```

*Attack Simulations & Results*

| # | Attack Scenario           | Tool          | MITRE ID  | Detected? | Alert Fired? |
|---|---|---|---|
| 1 | SMB Brute Force           | Hydra         | T1110     | ✅ Yes    | ✅ Yes      |
| 2 | Network Port Scan         | Nmap          | T1046     | ✅ Yes    | ✅ Yes      |
| 3 | Backdoor Account Creation | net user      | T1136.001 | ✅ Yes    | ✅ Yes      |
| 4 | PowerShell Abuse          | PowerShell    | T1059.001 | ✅ Yes    | ✅ Yes      |
| 5 | Failed Login Simulation   | Custom Script | T1110     | ✅ Yes    | ✅ Yes      |

**Detection Rate: 5/5 (100%)** ✅

*Splunk Dashboard*

Built a real-time SOC dashboard with 5 panels:

| Panel                   | Description                                  |
|---|---|
| Events by Log Source    | Bar chart showing event distribution         |
| Failed Logins Over Time | Line chart tracking authentication failures  |
| Top Processes Created   | Bar chart of most spawned processes          |
| New User Accounts       | Table of all account creation events         |
| PowerShell Timeline     | Line chart of PowerShell execution frequency |

*Repository Structure*
home-soc-lab-splunk/
│
├── README.md                          ← You are here
│
├── detections/                        ← SPL detection rules
│   ├── brute_force_ssh.spl            ← T1110 Brute Force
│   ├── new_user_account.spl           ← T1136.001 Persistence
│   ├── powershell_execution.spl       ← T1059.001 Execution
│   ├── privileged_account_usage.spl   ← T1078 Privilege Escalation
│   └── account_lockout.spl            ← T1110 Credential Access
│
└── reports/                           ← Incident reports
├── INC-2026-001-failed-login-bruteforce.md
├── INC-2026-002-backdoor-account-created.md
└── INC-2026-003-powershell-execution.md

*Key Skills Demonstrated*

Security Operations
├── SIEM Administration & Tuning (Splunk)
├── Log Analysis & Event Correlation
├── Threat Detection & Alert Writing
├── Incident Response & Documentation
└── MITRE ATT&CK Framework Application
Technical Skills
├── SPL (Splunk Processing Language)
├── Windows Event Log Analysis
├── Sysmon Deployment & Configuration
├── Network Security (OPNsense Firewall)
├── Linux & Windows Administration
└── Virtualization (VirtualBox)
Offensive Security Awareness
├── Brute Force Attack Detection
├── Persistence Technique Recognition
├── Reconnaissance Detection (Nmap)
└── Living-off-the-Land (LOL) Technique Detection

📈 Lab Statistics

| Metric                   | Value                             |
|---|---|
| Total Events Collected   | 2,400+                            |
| Detection Rules Written  | 5                                 |
| Alerts Configured        | 5 (Real-time)                     |
| Attack Simulations Run   | 5                                 |
| Incident Reports Written | 3                                 |
| MITRE Techniques Covered | T1110, T1136, T1078, T1059, T1046 |
| Detection Rate           | 100%                              |
