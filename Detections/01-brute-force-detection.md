# Detection 01: Brute Force Login Detection 

## Overview
Detects multiple failed login attempts from 
the same source indicating potential brute 
force or credential stuffing attack.

## Metadata
| Field | Details |
|-------|---------|
| Detection ID | DET-001 |
| Severity | High |
| MITRE ATT&CK | T1110 , Brute Force |
| Event ID | 4625 , Failed Logon |
| Data Source | Windows Security Log |
| Author | Nish |
| Date | September 2026 |

---

## MITRE ATT&CK Mapping

Tactic: Credential Access
Technique: T1110: Brute Force
Sub-tech: T1110.001: Password Guessing
T1110.003: Password Spraying
T1110.004: Credential Stuffing


---

## Detection Logic

### SPL Query
```spl
index=main EventCode=4625
| eval TargetAccount=coalesce(
  'Target_Account_Name',
  Account_Name,
  'TargetUserName')
| stats count by TargetAccount,
  Source_Network_Address, host
| where count > 3
| sort -count
| rename TargetAccount as "Target Account",
  Source_Network_Address as "Source IP",
  count as "Failed Attempts"
| table "Target Account", "Source IP",
  host, "Failed Attempts"
```

### Detection Threshold

Trigger condition:
More than 3 failed logins from same source
within the search time window

Why threshold of 3:
├── Low enough to catch slow attacks
├── High enough to avoid false positives
│ from normal typo-based failures
└── Adjustable based on environment


---

## Evidence Collected

### Table View
Shows aggregated failed login attempts
grouped by target account and source IP

![Brute Force Table](../screenshots/brute-force-table.png)

### Raw Events View
Shows individual failed login events
with timestamps, logon types, and
failure reasons

![Brute Force Events](../screenshots/brute-force-events.png)

---

## Real Lab Results

Findings from lab environment:

Target Account Source IP Failed Attempts
DESKTOP-6M26L0E$ 127.0.0.1 4

              127.0.0.1   4

Analysis:
Source: 127.0.0.1 (loopback/local)
Logon Type: 2 (Interactive)
Failure Reason: Error during logon
Timeframe: Multiple attempts within
minutes of each other


---

## Investigation Steps

When this alert fires a SOC analyst should:

Step 1: Identify the source IP
Is it internal or external?
Is it a known system?

Step 2: Identify the target account
Is it a privileged account?
Is it a service account?

Step 3: Check timing
Is this during business hours?
Is it automated (regular intervals)?

Step 4: Check for successful login after failures
EventCode=4624 after 4625 =
possible successful brute force!

Step 5: Correlate with other events
Any lateral movement after?
Any new accounts created after?

Step 6: Determine if malicious or benign
Misconfigured service = benign
External IP = escalate immediately


---

## Follow-Up SPL Query

Check if brute force was followed by
successful login:

```spl
index=main (EventCode=4625 OR EventCode=4624)
| eval EventType=case(
  EventCode=="4625", "Failed Login",
  EventCode=="4624", "Successful Login")
| stats count by Account_Name, 
  EventType, Source_Network_Address
| sort Account_Name, EventType
```

---

## False Positives

Common benign causes:
Service account with expired password
User typing wrong password accidentally
Misconfigured application
Locked account being retried by service

How to tune:
Whitelist known service account IPs
Increase threshold for internal IPs
Create separate rule for external IPs
with lower threshold (1-2 attempts)


---

## Recommended Response Actions

LOW confidence (internal IP, low count):
Monitor and document
Check if service account issue

MEDIUM confidence (internal, high count):
Investigate source system
Check for malware or misconfiguration
Alert system owner

HIGH confidence (external IP):
Block source IP at firewall immediately
Reset targeted account password
Check for successful logins
Escalate to senior analyst
Begin incident response procedure
