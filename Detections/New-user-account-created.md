# Detection 03: New User Account Created 

## Overview
Detects creation of new user accounts on 
Windows systems, a common attacker technique 
for establishing persistence and backdoor access 
after initial compromise.

## Metadata
| Field | Details |
|-------|---------|
| Detection ID | DET-003 |
| Severity | High |
| MITRE ATT&CK | T1136 - Create Account |
| Event ID | 4720 - User Account Created |
| Data Source | Windows Security Log |
| Author | Nish |
| Date | September 2026 |

---

## MITRE ATT&CK Mapping

Tactic: Persistence
Technique: T1136 - Create Account
Sub-tech: T1136.001 - Local Account
T1136.002 - Domain Account


---

## Why This Matters

After gaining initial access attackers
commonly create new accounts to:

├── Maintain persistent access
│ (even if original entry point is closed)
├── Avoid using compromised accounts
│ (reduce detection risk)
├── Create accounts that blend in
│ (names like "svc-backup" or "helpdesk")
└── Escalate privileges
(add new account to admin groups)

Any unexpected account creation outside
of normal IT processes = investigate immediately


---

## Detection Logic

### Primary SPL Query
```spl
index=main EventCode=4720
| eval Time=strftime(_time,"%Y-%m-%d %H:%M:%S")
| table Time, host,
  SAM_Account_Name,
  Subject_Account_Name,
  Subject_Domain_Name
| rename SAM_Account_Name as "New Account Created",
  Subject_Account_Name as "Created By",
  Subject_Domain_Name as "Domain"
| sort -Time
```

### Extended Query - Account Lifecycle
```spl
index=main (EventCode=4720 OR EventCode=4722 OR EventCode=4738)
| eval EventType=case(
  EventCode="4720", "Account Created",
  EventCode="4722", "Account Enabled",
  EventCode="4738", "Account Modified")
| eval Time=strftime(_time,"%Y-%m-%d %H:%M:%S")
| table Time, host, EventType,
  Account_Name, Subject_Account_Name
| sort -Time
```

---

## Lab Test - How Event Was Generated

```powershell
# Generated on Windows 10 VM
# using local user creation command:

net user TestUser01 Password123! /add

# This immediately triggered Event ID 4720
# in Windows Security log
# which Splunk detected within 60 seconds
```

---

## Evidence

![New User Detection](../screenshots/detection3-new-user-created.png)

---

## Real Lab Results

Finding:
Event ID 4720 fired immediately after
running net user command

Detection confirmed:
├── New account: TestUser01
├── Created by: Administrator
├── Host: DESKTOP-6M26L0E
└── Time: 2026-09-26


---

## Investigation Steps

When this alert fires:

Step 1: Identify the new account name
Does it follow naming conventions?
Is it a known IT request?

Step 2: Identify who created it
Was it a legitimate admin?
Was it created during off-hours?

Step 3: Check what groups it was added to
Search for Event ID 4732 (added to admins)
correlating with same timeframe

Step 4: Check account activity after creation
Did it log in immediately?
What did it access?

Step 5: Verify with IT/HR
Is this an approved new user?
Is there a ticket for this account?

Step 6: Determine if malicious
No ticket + off-hours + admin group
= almost certainly malicious


---

## Correlation Query

Check if new account was immediately
added to admin group:

```spl
index=main (EventCode=4720 OR EventCode=4732)
| eval EventType=case(
  EventCode="4720", "Account Created",
  EventCode="4732", "Added to Admin Group")
| eval Time=strftime(_time,"%Y-%m-%d %H:%M:%S")
| stats values(EventType) as Events
  by Account_Name, host
| where mvcount(Events) > 1
| table Account_Name, host, Events
```

---

## False Positives

Common legitimate causes:
├── New employee onboarding
├── IT creating service accounts
├── Contractor account creation
└── Automated provisioning systems

How to reduce false positives:
├── Whitelist known admin accounts that
regularly create users (IT team)
├── Only alert during off-hours creation
├── Correlate with HR ticketing system
└── Alert only when combined with
immediate admin group addition


---

## Recommended Response

LOW confidence (business hours, IT admin):
└── Verify with IT - likely legitimate
Document and close

MEDIUM confidence (off-hours, unknown creator):
└── Contact IT immediately
Verify if approved
Disable account pending verification

HIGH confidence (unknown account + admin group

off-hours + no ticket):
└── Disable account immediately
Reset all admin passwords
Check for lateral movement
Begin incident response
Escalate to senior analyst


---

## Related Event IDs

| Event ID | Description |
|----------|-------------|
| 4720 | User account created |
| 4722 | User account enabled |
| 4724 | Password reset attempt |
| 4732 | Added to local admin group |
| 4728 | Added to global group |
| 4738 | User account changed |


