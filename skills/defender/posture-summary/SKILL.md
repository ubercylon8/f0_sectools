---
name: defender-posture-summary
description: Summarize Defender security posture for leadership
version: 1.0.0
metadata:
  hermes:
    tags: [security, posture, defender, ciso, reporting]
    category: security
---

# Microsoft Defender Posture Summary

## When to Use

The user wants an overview of security posture rather than a single incident —
e.g. "how's our security posture", "give me a CISO summary", "what should we
worry about". Produces an aggregated rollup, not a raw dump.

## Tools

Base tool names (runtime may prefix — see the Defender server README):
`get_secure_score`, `list_incidents`. Read-only.

## Procedure

1. Call `get_secure_score` for the current Microsoft Secure Score (current/max
   and percentage).
2. Call `list_incidents` with `severity_min: medium` to gather open incidents.
3. Aggregate: count incidents by **severity**; identify the top 2–3 by impact.
4. Produce a brief rollup:
   - **Posture:** Secure Score X% (and what that band implies).
   - **Open incidents:** N total — breakdown by severity.
   - **Top risks:** the 2–3 most significant, one line each.
   - **Recommended focus:** the single highest-value next step.
5. Frame for the audience. For a CISO, use risk/business language and keep it
   short; avoid tool names, IDs, and raw JSON.

## Discipline (small local models)

- One tool at a time. Report only what the tools return.
- Do not estimate or trend-extrapolate beyond what the score finding provides.
- Relay any `posture` finding (missing permission / rate-limited) plainly.

## Pitfalls

- Resist dumping every finding — leadership wants the signal, not the log.
- A high Secure Score does not mean "no open incidents"; report both.
- Numbers must match tool output exactly; do not round misleadingly.

## Verification

Each number in the summary maps to a `get_secure_score` or `list_incidents`
finding. The "top risks" are real incidents, named from their `title`.
