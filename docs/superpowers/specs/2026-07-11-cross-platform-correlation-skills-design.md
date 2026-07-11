# Design: Cross-platform correlation skills (roadmap #3)

**Date:** 2026-07-11
**Status:** Approved (design), pending spec review
**Scope:** One implementation plan — two new `SKILL.md` packages + docs.

## Problem

The 12 existing skills are all single-platform. f0_sectools' reason to have four servers is
that a real investigation *pivots* across them — but nothing demonstrates that. Two
cross-platform playbooks make the "four servers earn their keep" story concrete:
1. **Cross-platform incident triage** — a Defender incident enriched with Entra identity risk,
   LimaCharlie host telemetry, and ProjectAchilles validation status.
2. **Offensive↔defensive loop** — ProjectAchilles weak techniques checked against LimaCharlie
   D&R coverage, closing back to f0_library (the offensive repo) as a retest recommendation.

## Honest tensions (design around these, don't hide them)

- **Least small-model-friendly artifacts in the repo.** Each step selects the right tool from
  all 22 (the combined-registry eval measured 5–7% routing cost even for capable models; tiny
  models much worse, Ministral 3 = 0%), plus multi-step state and cross-platform pivots. Mitigate
  with ultra-explicit procedures (one named tool per step, platform-anchored) and an honest
  per-skill note that these favor a capable local tier (GPT-OSS 20B — measured 100% even on the
  combined registry) and degrade on tiny models.
- **Entity identifiers differ across platforms.** Defender device name vs LimaCharlie sensor
  hostname vs Entra UPN; MITRE id vs a D&R rule that may not tag MITRE. Correlation is
  **best-effort by name, not a guaranteed join** — the skills must say when a link is unverified
  and never fabricate it.
- **f0_library is a separate offensive repo, not an MCP server here.** The loop skill can only
  **recommend** which f0_library test to re-run; it cannot execute it.

## Location & structure

New dir **`skills/cross-platform/`**, two agentskills.io `SKILL.md` packages following the
existing skill pattern (frontmatter: `name`, `description` ≤60 chars, `version`,
`metadata.hermes.{tags,category}`; sections: *When to Use / Tools / Procedure / Pitfalls /
Verification*). Tools referred to by **base name** (runtime prefixes vary). `skills/test_skills_valid.py`
already enforces valid frontmatter + the ≤60-char description on every `SKILL.md` — the two new
ones must pass it (the automated gate).

```
skills/cross-platform/
  triage-incident-cross-platform/SKILL.md   # description: "Triage a Defender incident across Entra, LimaCharlie & PA"
  validation-coverage-loop/SKILL.md         # description: "Weak techniques -> LC coverage -> retest recommendation" (55 chars)
```

## Skill 1 — triage-incident-cross-platform

**When to Use:** the user wants to triage a Defender incident *with full cross-platform context*
("triage this incident and tell me everything", "is the user in this incident risky", "what does
the host show").

**Tools (base names):** Defender `list_incidents`, `list_alerts`; Entra `list_risky_users`,
`list_risk_detections`; LimaCharlie `get_sensor`, `query_telemetry`; ProjectAchilles
`get_weak_techniques`. All read-only.

**Procedure (one tool per step):**
1. `list_incidents` (Defender, `severity_min` matching the ask) → pick the incident; note its
   **entity** (device and/or user) and **MITRE techniques** (from `references` of type `mitre`).
   Optionally `list_alerts` for the correlated alert detail.
2. **User pivot (Entra):** if a user account is involved, `list_risky_users` → is that UPN flagged
   risky? Then `list_risk_detections` for the risk events. Match by **UPN/display name**; if it
   doesn't appear, say "not flagged risky in Entra," don't infer.
3. **Host pivot (LimaCharlie):** if a device is involved, `get_sensor` by hostname → online status
   + platform; then `query_telemetry` scoped to that host for recent activity. Match by
   **hostname**; if the Defender device name doesn't resolve to an LC sensor, say so.
4. **Technique pivot (ProjectAchilles):** `get_weak_techniques` → is the incident's MITRE technique
   one our attack simulations show we're weak against? Match by **MITRE id**.
5. **Synthesize:** *what happened → is the involved user risky → what the host telemetry shows →
   are our defenses validated against this technique → recommended next step.* Note any pivot
   whose join was unverified.

## Skill 2 — validation-coverage-loop

**When to Use:** "where are we weak and do we have detection coverage for it", "what should we
re-test", "close the offensive/defensive loop."

**Tools (base names):** ProjectAchilles `get_weak_techniques`; LimaCharlie `list_dr_rules`,
`list_detections`. All read-only.

**Procedure:**
1. `get_weak_techniques` (PA) → the MITRE techniques our attack simulations most often get through
   (note each technique's MITRE id + score).
2. **Coverage check (LimaCharlie):** `list_dr_rules` → is there a detection rule that would catch
   each weak technique? Match by the rule naming/mentioning the technique (D&R rules don't always
   tag MITRE — best-effort). Then `list_detections` → is that rule actually firing recently?
3. **Recommend (do not execute):** for techniques that are **weak AND lack effective D&R
   coverage**, recommend re-running the matching **f0_library** test (name the technique/test) to
   re-validate *after* a rule is added. State clearly that f0_library is a separate offensive repo
   the operator runs — this skill only recommends.

## Cross-cutting (both skills)

- **Read-only.** No gated writes. The f0_library recommendation is a recommendation, not an action.
- **No fabrication.** Report only what the tools return; when a cross-platform join can't be
  confirmed by name, say the link is unverified.
- **One tool at a time**, wait for the result, decide the next step (small-model discipline).
- **Model-tier note** in each skill: multi-step cross-server chains favor a capable local tier
  (GPT-OSS 20B); tiny models will drop steps or misroute.

## Testing

- **Automated (the gate):** both skills pass `skills/test_skills_valid.py` (frontmatter + ≤60-char
  description). Run `uv run pytest skills/`.
- **No new eval machinery** — measuring multi-step skill execution needs a new agentic eval; that
  is a separate roadmap item (below).
- **Optional manual smoke (human-gated):** a capable local model (GPT-OSS 20B) driving one skill
  end-to-end hits LIVE security platforms, so it is operator-run, not part of CI.

## Docs & wiring

- User-guide workflows page: add the two cross-platform workflows.
- CLAUDE.md: update the skills list + count (12 → 14) and the skills tree.
- Optionally note them under the threat-hunter / CISO Hermes personas (wiring only, no skill
  content duplicated — Rule 9).

## Out of scope (YAGNI / roadmap)

- **Multi-step / agentic skill eval** (measuring whether small models drive the full chain) →
  roadmap. Deferred by decision; it's a new eval type, its own project.
- No new servers, tools, `core/`, or schema changes.
- No automatic cross-platform entity resolution (a real join engine) — best-effort-by-name only.

## Files touched

| File | Change |
|---|---|
| `skills/cross-platform/triage-incident-cross-platform/SKILL.md` | new |
| `skills/cross-platform/validation-coverage-loop/SKILL.md` | new |
| `docs/user-guide/workflows.md` | add the two cross-platform workflows |
| `CLAUDE.md` | skills list/count 12→14, skills tree |
| `integrations/hermes/*` | (optional) note skills under threat-hunter/CISO personas — wiring only |
