---
name: intune-coverage-gap-review
description: Find Intune device coverage and compliance gaps
version: 1.0.0
metadata:
  hermes:
    tags: [security, intune, compliance, gaps, endpoint, security-engineering]
    category: security
---

# Intune Coverage Gap Review

## When to Use

The user wants the **at-risk device list and what to fix** — e.g. "which devices
are non-compliant", "show me stale or unencrypted devices", "where are our device
coverage gaps", "which endpoints should we remediate first". Uses the
**f0_sectools Intune** MCP server (read-only).

## Tools

Base tool names (runtime may prefix — see the Intune server README):
`get_compliance_summary`, `list_stale_devices`, `list_managed_devices`.
Read-only.

## Procedure

1. Call `get_compliance_summary` to scope the fleet (how many devices, how many
   noncompliant / unknown / unencrypted).
2. Call `list_stale_devices` (`days: 30`) for devices that have stopped syncing —
   a coverage-drift / possibly-abandoned signal.
3. Call `list_managed_devices` with `compliance: noncompliant` for the
   non-compliant list.
4. Flag **unencrypted** devices from each device's `encrypted` evidence
   (`encrypted: False`) — there is no dedicated tool; it comes from the device
   finding.
5. Produce a prioritized remediation list, worst first: stale + unencrypted +
   noncompliant devices lead; for each, name the device and the specific gap
   (not synced since <date> / not encrypted / failing compliance).

## Discipline (small local models)

- One tool at a time; report only the devices the tools return.
- Lead with the highest-risk devices (stale AND unencrypted); don't bury them.
- Relay any `posture` finding (permission / license / throttle) plainly.

## Pitfalls

- `list_stale_devices` is **bounded to `limit`** and uses a **server-side
  `$filter`** on last-sync time, because `managedDevices` **ignores
  `$orderby lastSyncDateTime`**. To widen the net, raise `limit` — do **not**
  assume a "fetch everything then sort" model; the tool returns stale devices
  directly, capped at `limit`.
- Unencrypted status is the per-device `encrypted` evidence field, not a separate
  query. `unknown` compliance is not the same as noncompliant — call it out
  separately.
- Recommend fixes grounded in the findings; don't invent devices or policies.

## Verification

Each flagged device maps to a `list_stale_devices` or `list_managed_devices`
finding; stale comes from `last_sync`, unencrypted from `encrypted`, non-compliant
from `compliance`. Counts reconcile with `get_compliance_summary`.
