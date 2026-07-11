---
name: triage-incident-cross-platform
description: Triage a Defender incident across Entra, LimaCharlie & PA
version: 1.0.0
metadata:
  hermes:
    tags: [security, soc, incident-response, cross-platform, correlation]
    category: security
---

# Triage a Defender Incident Across Platforms

## When to Use

The user wants to triage a Microsoft Defender incident with **full cross-platform
context** — not just the incident itself, but whether the involved user is risky
in Entra, what the host shows in LimaCharlie, and whether our defenses are
validated against the technique in ProjectAchilles. Triggers: "triage this
incident and tell me everything", "is the user in this incident risky", "give me
the full picture on that incident".

Uses four **f0_sectools** MCP servers, all read-only: Defender, Entra,
LimaCharlie, ProjectAchilles.

## Tools

Base tool names (your runtime prefixes them — Hermes `mcp_f0-<server>_<tool>`,
Claude Code `mcp__f0-<server>__<tool>`):
- Defender: `list_incidents`, `list_alerts`
- Entra: `list_risky_users`, `list_risk_detections`
- LimaCharlie: `get_sensor`, `query_telemetry`
- ProjectAchilles: `get_weak_techniques`

All read-only; nothing changes state.

## Procedure

Work **one tool at a time**: call, read the result, then decide the next step.

1. **Incident (Defender).** Call `list_incidents` with a `severity_min` matching
   the ask (`high` if they only want what matters now). Pick the incident of
   interest. Note its **entity** (device name and/or user), **severity**,
   **status**, and **MITRE techniques** (the `references` of type `mitre`). For
   the correlated alert detail, call `list_alerts`.
2. **User pivot (Entra).** If a user account is involved, call `list_risky_users`
   and look for that user's **UPN / display name**. If present, note the risk
   level and call `list_risk_detections` for the risk events (e.g. impossible
   travel). If the user is **not** in the risky list, say "not currently flagged
   risky in Entra" — do not infer risk that isn't there.
3. **Host pivot (LimaCharlie).** If a device is involved, call `get_sensor` with
   the **hostname** → online status + platform. Then call `query_telemetry`
   scoped to that host for recent activity. The Defender device name and the
   LimaCharlie sensor hostname may differ — if the name doesn't resolve to a
   sensor, say "no matching LimaCharlie sensor found for <name>", don't guess a
   different host.
4. **Technique pivot (ProjectAchilles).** Call `get_weak_techniques`. Check
   whether the incident's **MITRE technique id** appears — i.e. is this a
   technique our attack simulations show we're **weak** against? Note the score.
5. **Synthesize.** One tight summary: *what happened (incident + alerts) → is the
   involved user risky (Entra) → what the host telemetry shows (LimaCharlie) →
   are our defenses validated against this technique (ProjectAchilles) →
   recommended next triage step.* Call out any pivot whose cross-platform join
   you could **not** confirm by name.

## Pitfalls

- **Cross-platform joins are best-effort by name.** Device name ↔ sensor
  hostname ↔ user UPN ↔ MITRE id are matched by string, not a guaranteed join.
  When a match is uncertain, say so; never fabricate the link.
- **Read-only.** This skill never isolates a host or changes state. If asked to
  contain, hand off to the gated `isolate_host` flow — don't imply you acted.
- **Never invent** incident ids, risk levels, telemetry rows, or technique
  scores. Report only what the tools return.

## Small models

This is a multi-step, four-server chain — it selects the right tool from ~22 at
each step and carries state across calls. It favours a **capable local model**
(e.g. GPT-OSS 20B). Smaller models may drop a pivot or misroute a step; if the
model loses the thread, run the single-platform skills separately
(`triage-defender-incident`, `review-entra-identity-risk`,
`investigate-lc-endpoint`) and combine the results by hand.

## Verification

- Each step names one real tool from the list above and waits for its result.
- The final summary distinguishes **confirmed** facts (from tool output) from
  **unverified** cross-platform joins.
- No state was changed; no values were invented.
