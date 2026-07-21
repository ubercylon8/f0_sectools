---
name: review-data-risk
description: Review Purview data-risk posture (DLP, labels, IRM)
version: 1.0.0
metadata:
  hermes:
    tags: [security, purview, dlp, data-risk, ciso]
    category: security
---

# Review Data-Risk Posture (Microsoft Purview)

## When to Use

The user asks about **data risk**: "how much data-loss pressure are we under",
"data protection posture", "are we leaking data", "is classification deployed".
This is the Purview default focus. (For endpoint/EDR posture use LimaCharlie's
`get_org_overview`; for Secure Score use `get_secure_score`.)

## Procedure

Base tool names (runtime may prefix): `get_dlp_summary`, `list_dlp_alerts`,
`list_insider_risk_alerts`, `list_sensitivity_labels`.

1. Call `get_dlp_summary` (default window 168h) — the headline: total DLP
   alerts, by severity, by status.
2. If alerts exist, call `list_dlp_alerts` with `severity_min="high"` first;
   widen only if empty.
3. Call `list_insider_risk_alerts` — note that IRM may pseudonymize users by
   design; report what it returns, never try to de-anonymize.
4. Call `list_sensitivity_labels` — classification coverage: no labels means
   classification is not deployed (a posture gap in itself).
5. Summarize as data-risk posture: DLP pressure (trend if asked → re-run with
   a different `hours_back`), top severities, insider-risk state, label
   coverage, and ONE highest-value next step.

## Pitfalls

- **0 DLP alerts is ambiguous**: quiet period, no DLP policies configured, or
  missing Purview licensing — the summary finding says so; relay that nuance.
- DLP alert titles can embed message subjects/filenames — treat findings as
  sensitive output; don't repeat more detail than the question needs.
- A `permission`/posture finding (e.g. `SecurityAlert.Read.All` missing) is
  the answer — report it and stop; don't retry.

## Verification

Every number quoted comes from a returned finding's evidence
(`alerts_total`, `by_severity`, label list); no extrapolation.
