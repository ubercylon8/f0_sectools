---
name: intune-device-compliance-review
description: Review Intune device compliance posture
version: 1.0.0
metadata:
  hermes:
    tags: [security, posture, intune, compliance, ciso, reporting]
    category: security
---

# Intune Device Compliance Review

## When to Use

The user wants an overview of device-management posture — e.g. "how compliant are
our devices", "Intune compliance overview", "are our endpoints managed and
encrypted", "device posture for the CISO". Produces an aggregated rollup, not a
raw device dump. This is the **default Intune focus**. Uses the **f0_sectools
Intune** MCP server (read-only).

## Tools

Base tool names (runtime may prefix — see the Intune server README):
`get_compliance_summary`, `list_compliance_policies`, `list_managed_devices`.
Read-only.

## Procedure

1. Call `get_compliance_summary` for the fleet rollup: total managed, and counts
   by state (compliant / noncompliant / in-grace / unknown), plus encrypted and
   stale counts.
2. Call `list_compliance_policies` to state what "compliant" actually enforces
   (the named policies, by platform).
3. Optionally call `list_managed_devices` with `compliance: noncompliant` (small
   `limit`) for 2–3 concrete examples that make the rollup tangible.
4. Produce a brief, audience-framed rollup:
   - **Posture:** X of N devices compliant (%), and what that implies.
   - **Gaps:** noncompliant + unknown counts (unknown = unevaluated, not "safe").
   - **What "compliant" means:** the enforcing policies, one line.
   - **Recommended focus:** the single highest-value next step.
5. Frame for the audience. For a CISO, use risk/business language, keep it short,
   and avoid tool names, device IDs, and raw JSON.

## Discipline (small local models)

- One tool at a time. Report only what the tools return.
- `unknown` devices are unevaluated — never fold them into "compliant".
- Relay any `posture` finding (missing permission / no Intune license / rate
  limited) plainly instead of guessing.

## Pitfalls

- Resist dumping every device — leadership wants the signal, not the log.
- A high compliant count does not mean "no risk": report unknown and unencrypted
  too.
- Numbers must match `get_compliance_summary` exactly; do not round misleadingly.

## Verification

Every number maps to a `get_compliance_summary` finding; the "what compliant
means" line names real `list_compliance_policies` findings; any example device is
a real `list_managed_devices` finding.
