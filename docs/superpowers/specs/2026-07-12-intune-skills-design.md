# Design: Intune skills (`skills/intune/*`)

**Date:** 2026-07-12
**Status:** Approved (design), pending spec review
**Scope:** One implementation plan — the three portable `SKILL.md` playbooks for the
live-validated Intune MCP server, plus the doc updates that complete the Intune server.

## Problem

The Intune MCP server (server #5) is built and live-validated (6 read tools over Microsoft
Graph `/deviceManagement`), but has no skills. Every other platform ships three
[agentskills.io](https://agentskills.io) `SKILL.md` playbooks (a posture skill, a gap skill,
a platform-native one) so a local model can drive the tools through a guided procedure rather
than freelancing. Intune needs the same, plus the doc updates that mark the server complete.

## Constraints (from CLAUDE.md + the skills validator)

- **One portable set, never forked per runtime** (Critical Rule 9). Skills refer to tools by
  **base name**; runtimes prefix (Hermes `mcp_f0-intune_<tool>`, Claude Code
  `mcp__f0-intune__<tool>`).
- **Validator (`skills/test_skills_valid.py`) is a hard gate:** YAML frontmatter with
  kebab-case `name`, a `description` **≤ 60 chars** (Hermes list limit), a `version` string;
  body must contain `## When to Use`, `## Procedure`, `## Verification`.
- **Mirror the existing 12 single-platform skills.** Section order: `## When to Use`,
  `## Tools`, `## Procedure`, `## Discipline (small local models)`, `## Pitfalls`,
  `## Verification`. `metadata.hermes` carries `tags: [...]` and `category: security`.
- **Read-only.** Intune has no gated writes; skills never imply a state change.

## Default focus

**Device-compliance posture** is Intune's default focus (as endpoint-investigation is
LimaCharlie's). The skill set says so explicitly, and skill #1 is the default entry point.

## The three skills (all under `skills/intune/`, read-only)

### 1. `device-compliance-review` — `intune-device-compliance-review` (DEFAULT)

- **description:** `Review Intune device compliance posture` (39 chars).
- **Focus / persona:** compliance posture rollup — CISO / security engineer.
- **Tools:** `get_compliance_summary`, `list_compliance_policies` (and `list_managed_devices`
  with `compliance: noncompliant` for a few concrete examples).
- **Procedure:** (1) `get_compliance_summary` for the rollup (total / compliant / noncompliant
  / in-grace / unknown, encrypted count); (2) `list_compliance_policies` to state what
  "compliant" is actually enforcing; (3) optionally `list_managed_devices(noncompliant)` for
  2–3 concrete examples; (4) produce an audience-framed rollup (CISO = risk language, no IDs).
- **Pitfalls:** don't dump every device; a high compliant count doesn't mean zero risk (report
  unknown + unencrypted too); numbers must match tool output exactly.

### 2. `coverage-gap-review` — `intune-coverage-gap-review`

- **description:** `Find Intune device coverage and compliance gaps` (47 chars).
- **Focus / persona:** the risk list — stale / noncompliant / unencrypted — security engineer.
- **Tools:** `get_compliance_summary`, `list_stale_devices`, `list_managed_devices`
  (`compliance: noncompliant`).
- **Procedure:** (1) `get_compliance_summary` to scope the fleet; (2) `list_stale_devices`
  (`days: 30`) for devices not syncing; (3) `list_managed_devices(noncompliant)` for the
  non-compliant list; (4) flag unencrypted from each device's `encrypted` evidence
  (`isEncrypted=False`); (5) a prioritized remediation list (stale + unencrypted first).
- **Pitfalls (bake in the live-validated quirk):** `list_stale_devices` is **bounded to
  `limit`** and uses a **server-side `$filter`** because `managedDevices` **ignores
  `$orderby lastSyncDateTime`** — to widen the net raise `limit`, don't assume a
  "fetch-all-then-sort" model. Unencrypted status comes from the per-device `encrypted`
  evidence field, not a dedicated tool.

### 3. `device-triage` — `intune-device-triage`

- **description:** `Check a device's Intune state during triage` (43 chars).
- **Focus / persona:** device-centric cross-platform pivot during incident triage — SOC
  analyst / IR. Lives under `skills/intune/` (device-first framing), not `skills/cross-platform/`.
- **Tools:** `get_managed_device` (Intune); optionally Defender `list_incidents` /
  `list_alerts` to obtain the device name from an incident.
- **Procedure:** (1) obtain the device name (from a Defender incident/alert, or the user);
  (2) `get_managed_device(device_name)`; (3) report compliance state, encryption, OS, owner
  (company/personal), last sync, and the assigned user; (4) turn that into a triage judgment
  (e.g. "personal, unencrypted, non-compliant → higher risk").
- **Pitfalls:** a Defender device name may differ from the Intune `deviceName` →
  `get_managed_device` returns a graceful "no managed device named X" finding; try the
  hostname variant rather than concluding "unmanaged". This is a 2-server pivot, not the full
  4-server correlation (that's `cross-platform/triage-incident-cross-platform`).

## Doc updates (fold in to complete the server)

- **CLAUDE.md:** add the three skills to the "Current skills" list; the Platform Integrations
  table already has an Intune row — confirm it, and confirm the Architecture tree's `skills/`
  block mentions intune.
- **README.md:** mark Intune live-validated in the status/skill counts.
- **User guide** (`docs/user-guide/`): add Intune to the support matrix and a one-line workflow.

These are the same doc surfaces every prior server touched; no new doc structure.

## Out of scope (YAGNI)

- No fourth skill, no `skills/cross-platform/` Intune skill (the device-triage pivot covers the
  cross-platform need, device-first).
- No new tools, no server change, no gated writes.
- No Hermes persona re-wiring beyond the skills' own `metadata.hermes` tags.

## Testing / verification

- `skills/test_skills_valid.py` passes for all three new `SKILL.md` (frontmatter + ≤60-char
  description + required sections) — the hard gate.
- Manual read-through: each skill's Procedure references only real Intune tool base names and
  real finding fields (`complianceState`→`compliance`, `isEncrypted`→`encrypted`,
  `lastSyncDateTime`→`last_sync`, `managedDeviceOwnerType`→`owner`, `userPrincipalName`→`user`).
- `uv run pytest` and `ruff` stay green (skills add no code; the validator test covers them).

## Files touched

| File | Change |
|---|---|
| `skills/intune/device-compliance-review/SKILL.md` | new — default posture skill |
| `skills/intune/coverage-gap-review/SKILL.md` | new — gap / risk-list skill |
| `skills/intune/device-triage/SKILL.md` | new — device-centric triage pivot |
| `CLAUDE.md` | add 3 skills to the skills list; confirm Platform table + tree |
| `README.md` | Intune live-validated status / skill count |
| `docs/user-guide/*` | Intune support-matrix row + one workflow |
