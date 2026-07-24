## Executive Summary
Two detection signals stand out this window: a suspicious PowerShell execution and an outbound beaconing pattern.

## Risk Framing
The PowerShell execution warrants a tuning review; the beacon pattern is a hunting lead worth pivoting on.

## Open Questions
- Do our existing D&R rules already cover T1059 execution on managed endpoints?
- Should the rare-domain beacon become a standing detection or a one-off hunt?
