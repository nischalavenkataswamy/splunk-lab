# Troubleshooting — Sysmon Forwarder Fix 🔧

## Problem Identified
During lab setup Sysmon events were not 
appearing in Splunk despite Sysmon being 
installed and running on Windows 10 client.

## Symptoms

Splunk search for EventCode=1 returned 97 events
but CommandLine field was completely blank

Sourcetype check revealed:
├── WinEventLog:Application ← appearing
├── WinEventLog:System ← appearing
└── Sysmon sourcetype ← NOT appearing

Raw event inspection showed:
└── Events were Windows Application log
EventCode=1 (not Sysmon EventCode=1)
Being confused due to same Event ID number


## Root Cause

inputs.conf on Windows 10 Universal Forwarder
was missing the Sysmon log path entirely

Also missing renderXml=true setting which
is required for proper field extraction
from Windows event logs

Without renderXml=true:
└── Events arrive as raw text blob
Individual fields (CommandLine, Image etc)
cannot be extracted by Splunk
All field values appear blank


## Fix Applied

### 1. Updated inputs.conf
Location:

C:\Program Files\SplunkUniversalForwarder
etc\system\local\inputs.conf


Added Sysmon input and renderXml=true
to all existing inputs:

```ini
[WinEventLog://Security]
index = main
disabled = false
renderXml = true
sourcetype = XmlWinEventLog:Security

[WinEventLog://System]
index = main
disabled = false
renderXml = true
sourcetype = XmlWinEventLog:System

[WinEventLog://Application]
index = main
disabled = false
renderXml = true
sourcetype = XmlWinEventLog:Application

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = main
disabled = false
renderXml = true
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

### 2. Verified Sysmon Service Running
```powershell
Get-Service Sysmon64
# Status must show: Running
```

### 3. Restarted Universal Forwarder
```powershell
Restart-Service SplunkForwarder
```

### 4. Verified Fix in Splunk
```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count by EventCode
| sort -count
```

Expected result after fix:

EventCode count
1 XXX ← Process creation
3 XXX ← Network connections
10 XXX ← Process access
11 XXX ← File created


## Key Lessons Learned

renderXml=true is ESSENTIAL for proper
field extraction from Windows event logs
Sysmon and Windows Application log both
use EventCode=1 — always filter by
sourcetype to avoid confusion
Always verify data is arriving correctly
before building detection rules on top
Check sourcetype FIRST when fields
appear blank — it reveals parsing issues
immediately
inputs.conf changes require forwarder
restart to take effect


## Verification Commands

```powershell
# Verify Sysmon generating events
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" `
             -MaxEvents 5 |
Select TimeCreated, Id, Message |
Format-List

# Verify forwarder running
Get-Service SplunkForwarder

# Verify Sysmon service running  
Get-Service Sysmon64
```

## Impact on Detection Rules

All Sysmon-based detections now use:
```spl
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
```

This ensures we search Sysmon logs
specifically and not other Windows logs
with overlapping Event IDs.
