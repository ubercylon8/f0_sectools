# Detection Coverage Report

*Prepared for Detection Engineering · Contoso · Trailing 7 days · Generated locally by f0_sectools*

## Executive summary

Two detection signals stand out this window: a suspicious PowerShell execution and an outbound beaconing pattern.

## Findings

The PowerShell execution warrants a tuning review; the beacon pattern is a hunting lead worth pivoting on.

- **[HIGH]** Suspicious PowerShell on web-01.corp.local — defender · ATT&CK: T1059
  - device: web-01.corp.local
  - account: CORP\jsmith
- **[MEDIUM]** Outbound beacon pattern to rare domain — limacharlie · ATT&CK: T1071, T1571
  - domain: rare.example.test
  - count: 42

## Scope & coverage

- Assessed: Detections

## Open questions

1. Do our existing D&R rules already cover T1059 execution on managed endpoints?
2. Should the rare-domain beacon become a standing detection or a one-off hunt?

## Provenance

2026-07-24 14:22 · 2 platforms queried · 2 findings · all data redacted at source · no external calls
