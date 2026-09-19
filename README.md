# Splunk SOC Detection Lab 🔍

## Overview
A hands-on Splunk lab documenting real detection 
use cases, SPL queries, and security dashboards 
built to simulate SOC analyst workflows.

Built to develop practical skills aligned with 
SOC analyst roles at Palo Alto Networks, 
CrowdStrike, and Cisco.

---

## Lab Environment

| Component | Details |
|-----------|---------|
| SIEM | Splunk Free 9.x |
| Log Sources | Sysmon, Windows Event Logs |
| Operating System | Windows 10 (VirtualBox VM) |
| Detection Framework | MITRE ATT&CK |

---

## Detection Use Cases

### 1. Brute Force Login Detection
**MITRE ATT&CK:** T1110 — Brute Force  
**Windows Event ID:** 4625 — Failed Logon

```spl
index=windows EventCode=4625
| stats count by src_ip, user
| where count > 3
| sort -count
| table src_ip, user, count
```

**What it detects:** More than 3 failed login 
attempts from the same source IP — indicates 
brute force or credential stuffing.

---

### 2. New User Account Created
**MITRE ATT&CK:** T1136 — Create Account  
**Windows Event ID:** 4720

```spl
index=windows EventCode=4720
| table _time, user, src_user, host
| sort -_time
```

**What it detects:** Newly created accounts — 
attacker creating backdoor accounts 
after compromise.

---

### 3. User Added to Administrators Group
**MITRE ATT&CK:** T1078 — Valid Accounts  
**Windows Event ID:** 4732

```spl
index=windows EventCode=4732
| where Group_Name="Administrators"
| table _time, user, Group_Name, src_user, host
```

**What it detects:** Unauthorised privilege 
escalation by adding user to local admin group.

---

### 4. Suspicious PowerShell Execution
**MITRE ATT&CK:** T1059.001 — PowerShell  
**Windows Event ID:** 4104 — Script Block Logging

```spl
index=windows EventCode=4104
| search ScriptBlockText="*IEX*" 
  OR ScriptBlockText="*DownloadString*" 
  OR ScriptBlockText="*Invoke-Expression*"
  OR ScriptBlockText="*-EncodedCommand*"
| table _time, host, user, ScriptBlockText
```

**What it detects:** Malicious PowerShell 
patterns used in fileless malware and 
lateral movement attacks.

---

### 5. Security Log Cleared
**MITRE ATT&CK:** T1070.001 — Clear Windows Event Logs  
**Windows Event ID:** 1102

```spl
index=windows EventCode=1102
| table _time, host, user
| sort -_time
```

**What it detects:** Security log deletion — 
almost always indicates attacker covering tracks.
This is a critical alert — investigate immediately.

---

### 6. Scheduled Task Created
**MITRE ATT&CK:** T1053.005 — Scheduled Task  
**Windows Event ID:** 4698

```spl
index=windows EventCode=4698
| table _time, host, user, TaskName
| sort -_time
```

**What it detects:** New scheduled tasks — 
common malware persistence mechanism.

---

### 7. Process Creation — Suspicious Parent
**MITRE ATT&CK:** T1059 — Command Execution  
**Sysmon Event ID:** 1

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" 
EventCode=1
| where ParentImage LIKE "%winword.exe%" 
  OR ParentImage LIKE "%excel.exe%"
| where Image LIKE "%powershell.exe%" 
  OR Image LIKE "%cmd.exe%"
| table _time, host, user, Image, 
  ParentImage, CommandLine
```

**What it detects:** Office application spawning 
PowerShell or CMD — classic malicious 
macro execution pattern.

---

### 8. LSASS Access — Credential Dumping
**MITRE ATT&CK:** T1003.001 — LSASS Memory  
**Sysmon Event ID:** 10

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=10 TargetImage="*lsass.exe*"
| where SourceImage!="*MsMpEng.exe*"
| table _time, host, SourceImage, 
  TargetImage, GrantedAccess
```

**What it detects:** Processes accessing LSASS 
memory — indicates credential dumping 
tools like Mimikatz.

---

## Dashboard Overview

Security monitoring dashboard built with the 
following panels:

- Failed login attempts over time (line chart)
- Top targeted usernames (bar chart)
- Suspicious PowerShell executions (table)
- Privilege escalation events (table)
- Security log clearing events (alert table)
- Process creation anomalies (table)

---

## Key Learnings

- Configured Splunk data inputs for Windows logs
- Wrote SPL queries for threat detection
- Mapped all detections to MITRE ATT&CK framework
- Built security dashboards for SOC monitoring
- Understood Windows event log structure
- Identified common attacker techniques in logs

---

## Tools and References

| Tool/Resource | Link |
|--------------|------|
| Splunk Free | splunk.com |
| Sysmon | Microsoft Sysinternals |
| MITRE ATT&CK | attack.mitre.org |
| Sysmon Config | SwiftOnSecurity/sysmon-config |
| Splunk Docs | docs.splunk.com |

---

## Certifications Supporting This Work
- CompTIA CySA+ (CS0-003)
- CompTIA Security+
- MSc Cybersecurity — University of York
