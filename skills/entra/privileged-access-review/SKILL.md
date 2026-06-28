---
name: review-privileged-access
description: Review Entra privileged directory role assignments
version: 1.0.0
metadata:
  hermes:
    tags: [security, identity, entra, privileged-access, hardening]
    category: security
---

# Review Entra Privileged Access

## When to Use

The user wants to review who holds privileged directory roles — e.g. "who are
our Global Admins", "review privileged access", "is admin access sprawled". Uses
the **f0_sectools Entra** MCP server (read-only).

## Tools

Base tool name (runtime may prefix — see the Entra server README):
`list_privileged_role_assignments`. Read-only. Findings are sorted with the most
critical roles first.

## Procedure

1. Call `list_privileged_role_assignments`. Each finding names a role assigned to
   a principal; **high** severity marks the most critical roles (Global
   Administrator, Privileged Role Administrator, Security Administrator, …).
2. Count the critical roles — especially **Global Administrators**. A high count
   of standing Global Admins is a classic exposure.
3. Spot users holding **multiple** privileged roles (e.g. Global Admin *and*
   Security Admin) — note them.
4. Summarize: how many privileged assignments, the critical-role holders, and
   any concentration of privilege.
5. Recommend: move standing access to **PIM eligibility** (just-in-time), reduce
   the number of permanent Global Admins, and confirm break-glass accounts are
   accounted for. (Recommend; you cannot change assignments.)

## Discipline (small local models)

- One tool call; report only the assignments returned.
- Lead with the critical (high-severity) roles; don't bury them under routine
  ones.
- Relay any `posture` finding (permission missing / rate-limited) plainly.

## Pitfalls

- Some privileged assignments are legitimate; recommend PIM, not blanket
  removal.
- Expect 1–2 break-glass (emergency) accounts — flag for confirmation, not as a
  problem.
- A large tenant may have many assignments; the output is capped and
  critical-first.

## Verification

Every named role/holder traces to a `list_privileged_role_assignments` finding;
the "Global Admin count" matches the findings of that role.
