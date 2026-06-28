---
name: review-entra-identity-risk
description: Review Entra ID Protection risky users and detections
version: 1.0.0
metadata:
  hermes:
    tags: [security, identity, entra, risk, identity-protection]
    category: security
---

# Review Entra ID Protection Risk

## When to Use

The user wants to review identity risk in Entra ID — e.g. "who's risky right
now", "any impossible-travel sign-ins", "review our identity risk". Uses the
**f0_sectools Entra** MCP server (read-only). Requires Entra ID **P2**.

## Tools

Base tool names (runtime may prefix — see the Entra server README):
`list_risky_users`, `list_risk_detections`. Read-only.

## Procedure

1. Call `list_risky_users`. Note each user's **risk level**. **Prioritize
   `medium` and `high`**; `info`/`low` are usually background noise in a large
   tenant.
2. Call `list_risk_detections`. Note the **detection type** (e.g.
   `unlikelyTravel` = impossible travel, `unfamiliarFeatures`) and which user it
   maps to.
3. Correlate: do the elevated-risk users have active detections explaining the
   risk?
4. Summarize: the top risky users (by level), the notable detections, and what
   they suggest.
5. Recommend next steps — e.g. risk-based Conditional Access, a password reset
   for a confirmed-compromised account, or investigating an impossible-travel
   detection. (You cannot take these actions; recommend them.)

## Discipline (small local models)

- One tool at a time. Report only users/detections the tools return.
- Don't enumerate hundreds of `info` users — summarize counts, name the
  `medium`/`high` ones.
- If a tool returns a `posture` finding (P2 / permission missing, or
  rate-limited), relay it and stop. The Identity Protection endpoints throttle
  aggressively — do not retry in a loop.

## Pitfalls

- Large tenants can have hundreds of risky users; the signal is in the elevated
  levels, not the count.
- `unlikelyTravel` and `unfamiliarFeatures` are common but worth confirming —
  flag, don't conclude compromise.
- These endpoints require Entra ID P2; without it the tool says so.

## Verification

Every named user and detection traces to a `list_risky_users` /
`list_risk_detections` finding. Counts match the tool output.
