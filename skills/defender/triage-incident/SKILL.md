---
name: triage-defender-incident
description: Triage a Microsoft Defender incident end-to-end
version: 1.0.0
metadata:
  hermes:
    tags: [security, soc, defender, incident-response]
    category: security
---

# Triage a Microsoft Defender Incident

## When to Use

The user wants to investigate, triage, or understand a Microsoft Defender
incident — e.g. "what's going on with our incidents", "triage the active
incidents", "look into the exfiltration incident". Use the **f0_sectools
Defender** MCP server (read-only).

## Tools

Base tool names (your runtime may prefix them — Hermes uses
`mcp_f0-defender_<tool>`, Claude Code uses `mcp__f0-defender__<tool>`):
`list_incidents`, `list_alerts`. All read-only; nothing changes state.

## Procedure

1. Call `list_incidents` with a `severity_min` that matches the ask
   (`medium` by default; `high` if the user only wants what matters now).
2. Identify the incident(s) of interest. Note each one's **severity**,
   **alert count**, **status**, and the entity it concerns.
3. Call `list_alerts` (`severity_min: high`) to pull the correlated alerts.
   Note each alert's **title**, **category**, and **MITRE techniques**
   (the `references` of type `mitre`).
4. Build a tight summary per incident: *what happened → affected entity →
   evidence → MITRE TTPs → current status.*
5. State a recommended next action (e.g. "investigate in the Defender portal",
   "validate the affected device"). Response/containment actions are **not**
   available in read-only mode — say so rather than implying you can act.

## Discipline (small local models)

- Call **one tool at a time**, wait for the result, then decide the next step.
- Report **only** what the tools return. Never invent incident IDs, alert
  titles, severities, or counts.
- If a tool returns a `posture` finding saying a permission is missing or the
  platform is rate-limited, relay that to the user — do **not** retry blindly.

## Pitfalls

- High-volume tenants return many incidents; always bound with `severity_min`.
- DLP-policy incidents are common and often low-signal — don't over-escalate.
- A `critical` incident here means a high-severity incident correlating several
  alerts; explain the basis rather than just the label.

## Verification

Every statement in your summary should trace to a specific finding's `title`,
`evidence`, or `references`. If you cannot point to a finding for a claim,
remove the claim.
