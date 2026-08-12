---
name: roll-up-ciso-risk
description: Executive risk rollup across all security platforms
version: 1.0.0
metadata:
  hermes:
    tags: [security, ciso, risk, posture, cross-platform, executive]
    category: security
---

# Roll Up CISO Risk Posture (Cross-Platform)

## When to Use

The user wants a **single executive risk picture** spanning every security
platform, not one platform's view. Triggers: "give me the overall risk
posture", "board-level security summary", "where do we stand across
everything", "what are our top risks right now", "CISO dashboard". Best paired
with the **CISO** persona.

Pulls one headline posture number from each of seven **f0_sectools** MCP
servers, all read-only. Favour a capable local model — this is seven
sequential calls plus synthesis.

## Tools

Base tool names (your runtime prefixes them — Hermes `mcp_f0-<server>_<tool>`,
Claude Code `mcp__f0-<server>__<tool>`). One posture pillar each:

- **Config hardening** — Defender `get_secure_score` (Microsoft Secure Score %)
- **Attack validation** — ProjectAchilles `get_defense_score` (defense vs
  simulated attacks)
- **Vulnerability exposure** — Tenable `get_vulnerability_summary` (open vulns
  by severity)
- **Device compliance** — Intune `get_compliance_summary` (managed / compliant
  / encrypted)
- **Data risk** — Purview `get_dlp_summary` (data-loss pressure)
- **Endpoint coverage** — LimaCharlie `get_org_overview` (sensor coverage;
  note dormant `lc:sleeper` sensors, which collect nothing)
- **Detection coverage** — Sentinel `get_detection_coverage` (ATT&CK tactics
  covered by the analytics-rule inventory). Use the CUSTOM figure
  (`tactics_covered_custom` / `rules_custom`), never the overall one — see
  Pitfalls.

All read-only; nothing changes state.

## Procedure

Work **one tool at a time**: call, read the single posture finding it returns,
record the number and its severity, then move to the next pillar. Do not chain
or batch.

1. Call each of the seven tools above, in any order. Each returns one posture
   finding with the pillar's headline metric in its `evidence` and a severity.
2. **Handle a dark pillar gracefully.** If a tool returns a `posture` finding
   that is a *degradation* — permission missing, not licensed, throttled, or
   "not configured" — that pillar is **NOT ASSESSED**. Record it as such and
   **keep going**; never abandon the rollup because one platform is dark. A
   partial rollup across the remaining six pillars is still valuable; the
   CISO just needs to know which one is missing.
3. **Rank by actual severity, not a fixed order.** Read each assessed pillar's
   severity and the number behind it; decide which 1–3 represent the biggest
   real risk *this week*. A low Secure Score, a pile of critical vulns, active
   DLP pressure, or a fleet that's mostly dormant sensors each outweigh a
   healthy pillar — let the findings drive the ranking, don't assume.
4. **Synthesize for an executive** (CISO lens): no tool names, no IDs, no JSON.
   - One line per **assessed** pillar: the metric in plain language + a short
     risk read ("device compliance 61% — a third of the fleet is out of
     policy").
   - A **"not assessed"** line naming any dark pillars, so the coverage of the
     picture is explicit.
   - **Top 1–3 risks** across pillars, worst first.
   - The **single highest-value next step**.

## Pitfalls

- **Don't fabricate a pillar you couldn't read.** A dark pillar is reported as
  "not assessed", never guessed or filled with a plausible number.
- **Don't average the seven into one score.** They measure different things on
  different scales; a single blended number misleads. Present them as distinct
  pillars with a reasoned top-risks list.
- **Endpoint coverage nuance:** a fleet reporting many sensors can still be
  mostly *dormant* (`lc:sleeper`) — read the online-vs-dormant split from
  `get_org_overview`, don't take the raw sensor count as coverage.
- **Purview data risk:** the DLP headline counts **unresolved** alerts. `0` is
  ambiguous (quiet, no policies / licensing, or everything already resolved —
  the last means DLP is working, not absent) — re-run with `state: "all"` to
  tell them apart rather than reporting "no data risk".
- **Detection coverage nuance:** always report the CUSTOM figure
  (`tactics_covered_custom` / `rules_custom`), never the overall figure
  (`tactics_covered_all`, which includes Microsoft-managed rule kinds —
  `Fusion`, `MicrosoftSecurityIncidentCreation`, `MLBehaviorAnalytics`,
  `ThreatIntelligence`). A tenant whose analytics coverage is nearly all
  Microsoft-managed has built very little detection engineering of its own,
  and the overall number hides exactly that gap — say so explicitly rather
  than quoting only the flattering total.
- Relay any degradation finding plainly and move on — do not retry a dark
  pillar in a loop.

## Verification

Every pillar line traces to a returned posture finding's evidence; dark pillars
are labelled "not assessed", never estimated; the top-risks ranking reflects
the actual severities returned, not a preset order.
