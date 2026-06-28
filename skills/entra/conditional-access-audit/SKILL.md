---
name: audit-conditional-access
description: Audit Entra conditional access policies for gaps
version: 1.0.0
metadata:
  hermes:
    tags: [security, identity, entra, conditional-access, hardening]
    category: security
---

# Audit Entra Conditional Access

## When to Use

The user wants to review Conditional Access (CA) configuration — e.g. "audit our
conditional access", "are any CA policies disabled", "do we enforce MFA". Uses
the **f0_sectools Entra** MCP server (read-only).

## Tools

Base tool name (runtime may prefix — see the Entra server README):
`list_conditional_access_policies`. Read-only.

## Procedure

1. Call `list_conditional_access_policies`. Each policy finding carries its
   **state**: `enabled`, `disabled`, or report-only
   (`enabledForReportingButNotEnforced`).
2. Group them: enforced (enabled) vs **disabled** (`misconfig`, severity medium)
   vs **report-only** (not enforcing, severity low).
3. Highlight the gaps that matter: a **disabled** policy that looks security-
   relevant (MFA, legacy-auth block, risk-based access), or a key control stuck
   in report-only.
4. Summarize: how many policies, how many actually enforced, and the specific
   ones worth attention.
5. Recommend: enable/enforce a disabled-but-important policy, or confirm a
   disabled one is intentionally retired.

## Discipline (small local models)

- One tool call; report only the policies returned.
- Don't assume intent — flag disabled/report-only policies for **review**,
  don't declare them wrong.
- Relay any `posture` finding (permission missing / rate-limited) plainly.

## Pitfalls

- Report-only is often intentional (a policy under evaluation) — note it,
  don't alarm.
- A disabled policy may be deliberately retired; recommend confirmation.
- Policy names are the operator's; quote them exactly from the findings.

## Verification

Each flagged policy and its state comes from a
`list_conditional_access_policies` finding.
