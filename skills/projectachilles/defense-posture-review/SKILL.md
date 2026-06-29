---
name: review-defense-posture
description: Review ProjectAchilles defense posture and trend
version: 1.0.0
metadata:
  hermes:
    tags: [security, projectachilles, posture, ciso, validation]
    category: security
---

# Review ProjectAchilles Defense Posture

## When to Use

The user wants the validated-defense picture — e.g. "how good is our defense",
"what's our attack-simulation posture", "give me a CISO security-validation
summary". ProjectAchilles runs `f0_library` attack simulations and scores
whether controls blocked or detected them. Uses the **f0_sectools
ProjectAchilles** MCP server (read-only).

## Tools

Base tool names (runtime may prefix — see the ProjectAchilles server README):
`get_defense_score`, `get_defense_score_trend`, `get_weak_techniques`. Read-only.

## Procedure

1. Call `get_defense_score` for the headline — % of simulated attacks blocked or
   detected, with the protected / detected / unprotected breakdown.
2. Call `get_defense_score_trend` to see whether posture is improving, flat, or
   regressing over the window.
3. Call `get_weak_techniques` for the lowest-scoring MITRE techniques — the
   areas defenses most often fail.
4. Summarize for the audience: posture %, the trend direction, the top 2-3 weak
   techniques, and the single highest-value place to improve.

## Discipline (small local models)

- One tool at a time; report only what the tools return.
- For a CISO, lead with the number and the direction; keep it short.
- Relay any `posture` finding (auth / permission / API unavailable) plainly.

## Pitfalls

- The defense score reflects the **API's** computation and can differ from the
  PA web dashboard depending on risk-acceptance exclusions, EDR-detection
  weighting, and default filters. Treat the raw number as **directional**; for
  exec reporting, confirm against the dashboard.
- A score over 100% or a negative unprotected count signals inconsistent
  source data (e.g. a capped execution total) — flag it, don't present it as
  real.
- Trend needs enough history; a short window may read "flat".

## Verification

The posture %, trend, and weak techniques each trace to a `get_defense_score` /
`get_defense_score_trend` / `get_weak_techniques` finding.
