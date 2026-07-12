# Intune Skills Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the three portable `SKILL.md` playbooks for the live-validated Intune MCP server, plus the doc updates that mark the server complete.

**Architecture:** Three agentskills.io `SKILL.md` files under `skills/intune/`, mirroring the existing 12 single-platform skills. Content only — no code. The existing validator (`skills/test_skills_valid.py`) is the gate. Then update CLAUDE.md, README, and the user-guide matrix.

**Tech Stack:** Markdown + YAML frontmatter (agentskills.io `SKILL.md`); `pytest` (the validator); no runtime code.

## Global Constraints

- Skills refer to Intune tools by **base name only**: `list_managed_devices`, `get_compliance_summary`, `get_managed_device`, `list_stale_devices`, `list_compliance_policies`, `list_configuration_profiles`. Never hard-code a runtime prefix.
- Frontmatter (validator hard gate): kebab-case `name`, `description` **≤ 60 chars**, `version` string. Body must contain `## When to Use`, `## Procedure`, `## Verification`.
- Section order mirrors existing skills: `## When to Use`, `## Tools`, `## Procedure`, `## Discipline (small local models)`, `## Pitfalls`, `## Verification`. `metadata.hermes` carries `tags: [...]` and `category: security`.
- Read-only — no skill implies a state change. All three live under `skills/intune/`.
- Default Intune focus = **device-compliance review** (skill #1); the skill set says so.
- Device finding evidence keys (from the live-validated server): `os`, `compliance`, `encrypted`, `owner`, `user`, `last_sync`. Compliance-summary evidence keys: `total`, `compliant`, `noncompliant`, `in_grace_period`, `unknown`, `error`, `conflict`.
- `list_stale_devices` uses a server-side `$filter` and is bounded to `limit`, because `managedDevices` ignores `$orderby lastSyncDateTime` (live-validated 2026-07-12). This goes in skill #2's pitfalls verbatim in intent.
- `uv run pytest skills/test_skills_valid.py -q` and `ruff` stay green.

---

### Task 1: Skill #1 — `device-compliance-review` (default focus)

**Files:**
- Create: `skills/intune/device-compliance-review/SKILL.md`

**Interfaces:**
- Produces: a skill named `intune-device-compliance-review` that the validator accepts and that references only real Intune tool base names.

- [ ] **Step 1: Create the SKILL.md**

Create `skills/intune/device-compliance-review/SKILL.md` with exactly:

```markdown
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
```

- [ ] **Step 2: Run the validator**

Run: `uv run pytest skills/test_skills_valid.py -q`
Expected: PASS (the new `intune-device-compliance-review` case included; description is 39 chars ≤ 60; required sections present).

- [ ] **Step 3: Commit**

```bash
git add skills/intune/device-compliance-review/SKILL.md
git commit -m "feat(intune): device-compliance-review skill (default focus)"
```

---

### Task 2: Skill #2 — `coverage-gap-review`

**Files:**
- Create: `skills/intune/coverage-gap-review/SKILL.md`

**Interfaces:**
- Produces: a skill named `intune-coverage-gap-review` the validator accepts.

- [ ] **Step 1: Create the SKILL.md**

Create `skills/intune/coverage-gap-review/SKILL.md` with exactly:

```markdown
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
```

- [ ] **Step 2: Run the validator**

Run: `uv run pytest skills/test_skills_valid.py -q`
Expected: PASS (description is 47 chars ≤ 60; required sections present).

- [ ] **Step 3: Commit**

```bash
git add skills/intune/coverage-gap-review/SKILL.md
git commit -m "feat(intune): coverage-gap-review skill (stale/noncompliant/unencrypted)"
```

---

### Task 3: Skill #3 — `device-triage` (cross-platform pivot, device-first)

**Files:**
- Create: `skills/intune/device-triage/SKILL.md`

**Interfaces:**
- Produces: a skill named `intune-device-triage` the validator accepts.

- [ ] **Step 1: Create the SKILL.md**

Create `skills/intune/device-triage/SKILL.md` with exactly:

```markdown
---
name: intune-device-triage
description: Check a device's Intune state during triage
version: 1.0.0
metadata:
  hermes:
    tags: [security, intune, soc, incident-response, endpoint, triage]
    category: security
---

# Intune Device Triage

## When to Use

During incident triage the user has a **specific device** — often from a Defender
incident or alert — and wants its Intune management state: "is this host compliant
and encrypted", "what's the Intune state of device X", "is the device in this
incident managed". A device-first, two-server pivot (Intune, plus Defender for the
device name). Uses the **f0_sectools Intune** MCP server (read-only); may read
Defender for context. For the full four-server incident picture, use
`cross-platform/triage-incident-cross-platform` instead.

## Tools

Base tool names (runtime may prefix — see each server README):
- Intune: `get_managed_device`
- Defender (optional, for the device name): `list_incidents`, `list_alerts`

All read-only.

## Procedure

Work **one tool at a time**: call, read the result, then decide the next step.

1. **Get the device name.** From the user directly, or from a Defender
   `list_incidents` / `list_alerts` finding's device entity.
2. **Look it up.** Call `get_managed_device` with that `device_name`.
3. **Report the management state:** compliance state, encryption, OS, owner
   (company vs personal), last sync time, and the assigned user.
4. **Turn it into a triage judgment:** e.g. "personal-owned, unencrypted, and
   noncompliant → elevated risk; verify/contain"; or "company, compliant,
   encrypted, synced today → lower device risk".

## Discipline (small local models)

- One tool at a time; report only what the finding contains.
- Do not assert isolation/remediation happened — these tools are read-only.
- Relay any `posture` finding (permission / license / throttle) plainly.

## Pitfalls

- A Defender device name may differ from the Intune `deviceName`.
  `get_managed_device` returns a graceful "no managed device named X" finding when
  there is no match — try the hostname variant (short name vs FQDN) rather than
  concluding the device is unmanaged.
- Personal ("BYOD") devices legitimately expose less; note it, don't treat every
  gap as a misconfiguration.

## Verification

The reported state comes entirely from the `get_managed_device` finding
(`compliance`, `encrypted`, `os`, `owner`, `last_sync`, `user`); the device name
traces back to the Defender finding or the user's request.
```

- [ ] **Step 2: Run the validator**

Run: `uv run pytest skills/test_skills_valid.py -q`
Expected: PASS (description is 43 chars ≤ 60; required sections present).

- [ ] **Step 3: Commit**

```bash
git add skills/intune/device-triage/SKILL.md
git commit -m "feat(intune): device-triage skill (Defender device -> Intune state pivot)"
```

---

### Task 4: Docs — CLAUDE.md skills list, README status, user-guide matrix

**Files:**
- Modify: `CLAUDE.md`
- Modify: `README.md`
- Modify: `docs/user-guide/README.md`

- [ ] **Step 1: CLAUDE.md — add the three skills to the "Current skills" list**

In `CLAUDE.md`, replace:

```
`projectachilles/{defense-posture-review,coverage-gap-analysis,validation-fleet-review}`, and `cross-platform/{triage-incident-cross-platform,validation-coverage-loop}`
```

with:

```
`projectachilles/{defense-posture-review,coverage-gap-analysis,validation-fleet-review}`, `intune/{device-compliance-review,coverage-gap-review,device-triage}` (device-compliance review is the Intune default focus), and `cross-platform/{triage-incident-cross-platform,validation-coverage-loop}`
```

- [ ] **Step 2: README.md — mark Intune live-validated, fix the skill count**

In `README.md`, replace:

```
**Working today:** the `core/` foundation; the **Microsoft Defender**, **Microsoft
Entra ID**, **LimaCharlie**, and **ProjectAchilles** MCP servers (all
live-validated); the **Microsoft Intune** MCP server (built, live-validation
pending); the eval harness; nine skills; the four role personas; and the
Hermes integration. Next: ProjectAchilles skills, then more platforms.
```

with:

```
**Working today:** the `core/` foundation; the **Microsoft Defender**, **Microsoft
Entra ID**, **LimaCharlie**, **ProjectAchilles**, and **Microsoft Intune** MCP
servers (all live-validated); the eval harness; seventeen skills; the four role
personas; and the Hermes integration. Next: more platforms.
```

- [ ] **Step 3: user-guide/README.md — add the Intune support-matrix row**

In `docs/user-guide/README.md`, replace:

```
| ProjectAchilles | `f0-projectachilles-mcp` | ✅ live-validated | defense score, score trend, weak techniques, test results, risk acceptances, agents, fleet health |
```

with:

```
| ProjectAchilles | `f0-projectachilles-mcp` | ✅ live-validated | defense score, score trend, weak techniques, test results, risk acceptances, agents, fleet health |
| Microsoft Intune | `f0-intune-mcp` | ✅ live-validated | managed devices, compliance summary, stale devices, compliance policies, config profiles |
```

- [ ] **Step 4: Verify the edits + full validator/lint**

Run: `grep -c "intune/{device-compliance-review" CLAUDE.md && grep -c "seventeen skills" README.md && grep -c "f0-intune-mcp" docs/user-guide/README.md`
Expected: `1` on each line.

Run: `uv run pytest skills/test_skills_valid.py -q && uv run ruff check .`
Expected: validator PASS, ruff clean.

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md README.md docs/user-guide/README.md
git commit -m "docs(intune): add skills to the skill list, mark Intune live-validated"
```

---

## Self-Review

**1. Spec coverage:**
- Skill #1 device-compliance-review (default) → Task 1. ✓
- Skill #2 coverage-gap-review (stale/noncompliant/unencrypted + `$orderby` pitfall) → Task 2. ✓
- Skill #3 device-triage (2-server device-first pivot, name-mismatch pitfall) → Task 3. ✓
- All under `skills/intune/`, base tool names, read-only → every task. ✓
- Validator gate (≤60-char description, required sections) → each task's Step 2. ✓
- Docs: CLAUDE.md skills list, README status, user-guide matrix → Task 4. ✓
- Default focus stated → Task 1 body + CLAUDE.md skills line (Task 4). ✓

**2. Placeholder scan:** No TBD/TODO; every SKILL.md is complete verbatim; every doc edit shows exact old→new strings. ✓

**3. Type consistency:** Tool base names, evidence keys (`compliance`/`encrypted`/`last_sync`/`owner`/`user`/`os`), and skill `name` values are consistent across tasks and match the live-validated server. Descriptions: 39 / 47 / 43 chars — all ≤ 60. ✓
