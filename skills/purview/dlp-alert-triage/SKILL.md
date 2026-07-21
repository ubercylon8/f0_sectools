---
name: triage-dlp-alerts
description: Triage Microsoft Purview DLP alerts by severity
version: 1.0.0
metadata:
  hermes:
    tags: [security, purview, dlp, soc, triage]
    category: security
---

# Triage Purview DLP Alerts

## When to Use

The user wants to work through data-loss alerts: "show me DLP alerts",
"what data-loss events fired", "who tried to send sensitive data".

## Procedure

Base tool names: `get_dlp_summary`, `list_dlp_alerts`.

1. Start with `get_dlp_summary` for the window in question (fractional
   `hours_back` is fine: 0.25 = last 15 minutes).
2. `list_dlp_alerts` with `severity_min="high"`; step down to `medium`/`low`
   only after the higher tier is handled. Keep `limit` small (≤25).
3. For each alert relay: title (the policy + what matched), severity, status
   (new / inProgress / resolved), category, and when.
4. Recommend the next step per alert: confirm with the data owner, review the
   policy match in the Purview portal, or mark resolved there. (This server is
   read-only — status changes happen in the portal.)

## Pitfalls

- The "More alerts available" note means the window has more than `limit` —
  narrow `hours_back` or raise `severity_min` instead of paging blindly.
- Alert titles may contain message subjects — sensitive; quote sparingly.
- Deep per-event forensics (exact matched content) is NOT available through
  this tool by design; say so instead of guessing.

## Verification

Alert counts and severities match the summary finding; every triaged alert
corresponds to a returned alert finding (`alert_id` in evidence).
