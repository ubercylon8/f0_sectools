---
name: defender-threat-hunt
description: Run guided Microsoft Defender advanced hunting (KQL)
version: 1.0.0
metadata:
  hermes:
    tags: [security, threat-hunting, defender, kql]
    category: security
---

# Guided Microsoft Defender Threat Hunt

## When to Use

The user wants to hunt for activity in Microsoft Defender — e.g. "hunt for
PowerShell downloads", "any unusual logons?", "look for this IP across the
estate". Uses advanced hunting (KQL) over the **last 30 days** of event data.

## Tools

Base tool name (runtime may prefix — see the Defender server README):
`run_hunting_query`. Read-only; it executes a read query and returns rows.

## Procedure

1. State the **hypothesis** in one sentence (what behaviour, on what, why).
2. Pick a starting query. See `references/kql-starters.md` for safe templates by
   table (process, logon, network, email). Always include a `| take N` bound.
3. Call `run_hunting_query` with the KQL.
4. Read the returned rows (already capped). Note what supports or refutes the
   hypothesis.
5. Refine once or twice — narrow the time window, add a filter, or pivot to a
   related table — then summarise: hypothesis, what you ran, what you found,
   and the relevant TTPs.

## Discipline (small local models)

- Build **one** query at a time; inspect results before writing the next.
- Always bound results (`| take 50` or smaller). Never request unbounded rows.
- Report only rows the tool returned. Do not invent device names or values.
- If the tool returns a `posture` finding (e.g. `ThreatHunting.Read.All` not
  granted, or rate-limited), relay it and stop — do not retry blindly.

## Pitfalls

- Hunting only sees the **last 30 days**; say so if the user asks about older
  activity.
- Broad queries without a filter or `take` are slow and noisy — start narrow.
- KQL table/column names must be exact; prefer the vetted starters over
  free-handing a query for a small model.

## Verification

The summary's findings correspond to actual returned rows. If zero rows came
back, report "no matching activity in the window", not a fabricated result.
