# Safe KQL starter queries (Microsoft Defender advanced hunting)

All are read-only and bounded. Adjust the filter and time window, keep the
`| take` bound, and pass the result to `run_hunting_query`.

## Process execution (e.g. living-off-the-land, PowerShell downloads)

```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe")
| where ProcessCommandLine has_any ("DownloadString", "Invoke-WebRequest", "curl", "certutil")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| take 50
```

## Suspicious logons (e.g. failed-then-success, unusual accounts)

```kql
DeviceLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonFailed"
| summarize Failures = count() by AccountName, DeviceName, bin(Timestamp, 1h)
| where Failures > 10
| take 50
```

## Network connections to a specific indicator

```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIP == "<IP>" or RemoteUrl has "<domain>"
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessFileName
| take 50
```

## Email / phishing signals

```kql
EmailEvents
| where Timestamp > ago(1d)
| where ThreatTypes has "Phish" or ThreatTypes has "Malware"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, ThreatTypes
| take 50
```

## Discovery — what tables exist

```kql
DeviceInfo
| take 1
```
