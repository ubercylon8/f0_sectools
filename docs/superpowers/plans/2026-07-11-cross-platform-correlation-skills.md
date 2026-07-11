# Cross-Platform Correlation Skills — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add two portable agentskills.io `SKILL.md` playbooks under `skills/cross-platform/` that pivot across all four servers — a cross-platform incident triage and an offensive↔defensive coverage loop — demonstrating the "four servers earn their keep" story.

**Architecture:** Pure content deliverable — two new `SKILL.md` files plus docs. No code, no servers, no `core/`. The existing `skills/test_skills_valid.py` (globs `**/SKILL.md`) is the automated gate: valid frontmatter + ≤60-char description + required sections. Skills are read-only, small-model-tight (one named tool per step), and honest about best-effort entity joins.

**Tech Stack:** Markdown (`SKILL.md` with YAML frontmatter), `pytest` for the validity guard, `uv`.

## Global Constraints

- **agentskills.io `SKILL.md` format**, enforced by `skills/test_skills_valid.py`: frontmatter must have `name` (lowercase kebab-case), `description` (**≤60 chars**), `version` (string); body must contain `## When to Use`, `## Procedure`, `## Verification`. New skills also include `## Tools`, `## Pitfalls`, `## Small models` to match house style.
- **Refer to tools by base name** (runtimes prefix them: Hermes `mcp_f0-<server>_<tool>`, Claude Code `mcp__f0-<server>__<tool>`). Every tool named must be a REAL tool: Defender `list_incidents`/`list_alerts`; Entra `list_risky_users`/`list_risk_detections`; LimaCharlie `get_sensor`/`query_telemetry`/`list_dr_rules`/`list_detections`; ProjectAchilles `get_weak_techniques`.
- **Read-only; no fabrication.** No gated writes. Cross-platform joins are best-effort by name — state when a join is unverified, never invent it. The f0_library retest step is a **recommendation**, not an action (f0_library is a separate offensive repo, not an MCP server here).
- **Cross-referenced single-platform skill names** (verified): `triage-defender-incident`, `review-entra-identity-risk`, `investigate-lc-endpoint`.
- **One portable set** — no per-runtime forks (Rule 9). Runtime wiring (Hermes) is optional and carries no skill content.
- **Commit style:** conventional commits ending with the two trailer lines exactly:
  `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`
  `Claude-Session: https://claude.ai/code/session_01TMoap3fRVq13TQah7BMdLm`
  Stage specific files; never `git add -A`. Do not push.

---

### Task 1: Skill 1 — triage-incident-cross-platform

**Files:**
- Create: `skills/cross-platform/triage-incident-cross-platform/SKILL.md`

**Interfaces:**
- Produces: a valid `SKILL.md` (name `triage-incident-cross-platform`, description ≤60 chars) that passes `skills/test_skills_valid.py`.

- [ ] **Step 1: Write the SKILL.md**

Create `skills/cross-platform/triage-incident-cross-platform/SKILL.md` with EXACTLY this content:

```markdown
---
name: triage-incident-cross-platform
description: Triage a Defender incident across Entra, LimaCharlie & PA
version: 1.0.0
metadata:
  hermes:
    tags: [security, soc, incident-response, cross-platform, correlation]
    category: security
---

# Triage a Defender Incident Across Platforms

## When to Use

The user wants to triage a Microsoft Defender incident with **full cross-platform
context** — not just the incident itself, but whether the involved user is risky
in Entra, what the host shows in LimaCharlie, and whether our defenses are
validated against the technique in ProjectAchilles. Triggers: "triage this
incident and tell me everything", "is the user in this incident risky", "give me
the full picture on that incident".

Uses four **f0_sectools** MCP servers, all read-only: Defender, Entra,
LimaCharlie, ProjectAchilles.

## Tools

Base tool names (your runtime prefixes them — Hermes `mcp_f0-<server>_<tool>`,
Claude Code `mcp__f0-<server>__<tool>`):
- Defender: `list_incidents`, `list_alerts`
- Entra: `list_risky_users`, `list_risk_detections`
- LimaCharlie: `get_sensor`, `query_telemetry`
- ProjectAchilles: `get_weak_techniques`

All read-only; nothing changes state.

## Procedure

Work **one tool at a time**: call, read the result, then decide the next step.

1. **Incident (Defender).** Call `list_incidents` with a `severity_min` matching
   the ask (`high` if they only want what matters now). Pick the incident of
   interest. Note its **entity** (device name and/or user), **severity**,
   **status**, and **MITRE techniques** (the `references` of type `mitre`). For
   the correlated alert detail, call `list_alerts`.
2. **User pivot (Entra).** If a user account is involved, call `list_risky_users`
   and look for that user's **UPN / display name**. If present, note the risk
   level and call `list_risk_detections` for the risk events (e.g. impossible
   travel). If the user is **not** in the risky list, say "not currently flagged
   risky in Entra" — do not infer risk that isn't there.
3. **Host pivot (LimaCharlie).** If a device is involved, call `get_sensor` with
   the **hostname** → online status + platform. Then call `query_telemetry`
   scoped to that host for recent activity. The Defender device name and the
   LimaCharlie sensor hostname may differ — if the name doesn't resolve to a
   sensor, say "no matching LimaCharlie sensor found for <name>", don't guess a
   different host.
4. **Technique pivot (ProjectAchilles).** Call `get_weak_techniques`. Check
   whether the incident's **MITRE technique id** appears — i.e. is this a
   technique our attack simulations show we're **weak** against? Note the score.
5. **Synthesize.** One tight summary: *what happened (incident + alerts) → is the
   involved user risky (Entra) → what the host telemetry shows (LimaCharlie) →
   are our defenses validated against this technique (ProjectAchilles) →
   recommended next triage step.* Call out any pivot whose cross-platform join
   you could **not** confirm by name.

## Pitfalls

- **Cross-platform joins are best-effort by name.** Device name ↔ sensor
  hostname ↔ user UPN ↔ MITRE id are matched by string, not a guaranteed join.
  When a match is uncertain, say so; never fabricate the link.
- **Read-only.** This skill never isolates a host or changes state. If asked to
  contain, hand off to the gated `isolate_host` flow — don't imply you acted.
- **Never invent** incident ids, risk levels, telemetry rows, or technique
  scores. Report only what the tools return.

## Small models

This is a multi-step, four-server chain — it selects the right tool from ~22 at
each step and carries state across calls. It favours a **capable local model**
(e.g. GPT-OSS 20B). Smaller models may drop a pivot or misroute a step; if the
model loses the thread, run the single-platform skills separately
(`triage-defender-incident`, `review-entra-identity-risk`,
`investigate-lc-endpoint`) and combine the results by hand.

## Verification

- Each step names one real tool from the list above and waits for its result.
- The final summary distinguishes **confirmed** facts (from tool output) from
  **unverified** cross-platform joins.
- No state was changed; no values were invented.
```

- [ ] **Step 2: Run the validity guard (auto-discovers the new file)**

Run: `uv run pytest skills/test_skills_valid.py -q`
Expected: PASS — the new `triage-incident-cross-platform/SKILL.md` is picked up by the `**/SKILL.md` glob and validates (frontmatter fields present, description ≤60 chars, the three required sections present).

- [ ] **Step 3: Sanity-check description length and referenced names**

Run:
```bash
python3 -c "print(len('Triage a Defender incident across Entra, LimaCharlie & PA'))"
```
Expected: `57` (≤60). Then confirm the three cross-referenced skills exist:
```bash
grep -l "name: triage-defender-incident\|name: review-entra-identity-risk\|name: investigate-lc-endpoint" skills/*/*/SKILL.md | wc -l
```
Expected: `3`.

- [ ] **Step 4: Commit**

```bash
git add skills/cross-platform/triage-incident-cross-platform/SKILL.md
git commit -m "feat(skills): add cross-platform Defender incident triage skill

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TMoap3fRVq13TQah7BMdLm"
```

---

### Task 2: Skill 2 — validation-coverage-loop

**Files:**
- Create: `skills/cross-platform/validation-coverage-loop/SKILL.md`

**Interfaces:**
- Produces: a valid `SKILL.md` (name `validation-coverage-loop`, description ≤60 chars) that passes `skills/test_skills_valid.py`.

- [ ] **Step 1: Write the SKILL.md**

Create `skills/cross-platform/validation-coverage-loop/SKILL.md` with EXACTLY this content:

```markdown
---
name: validation-coverage-loop
description: Weak techniques -> LC coverage -> retest recommendation
version: 1.0.0
metadata:
  hermes:
    tags: [security, detection-engineering, projectachilles, limacharlie, cross-platform]
    category: security
---

# Close the Offensive/Defensive Loop

## When to Use

The user wants to close the loop between **offensive validation** and
**defensive coverage**: which MITRE techniques our ProjectAchilles attack
simulations keep getting through, whether LimaCharlie has a detection rule for
them, and what to re-test. Triggers: "where are we weak and do we have coverage",
"what should we re-test", "close the offensive/defensive loop", "turn our weak
techniques into a retest plan".

Uses two **f0_sectools** MCP servers, read-only: ProjectAchilles and LimaCharlie.
The retest step targets **f0_library** — a separate offensive repo, **not** an MCP
server here — so this skill **recommends** a test to run there; it does not run it.

## Tools

Base tool names (runtime prefixes them):
- ProjectAchilles: `get_weak_techniques`
- LimaCharlie: `list_dr_rules`, `list_detections`

All read-only.

## Procedure

One tool at a time.

1. **Weak techniques (ProjectAchilles).** Call `get_weak_techniques`. These are
   the MITRE techniques our attack simulations most often get through. Note each
   technique's **MITRE id** and score.
2. **Coverage (LimaCharlie).** Call `list_dr_rules`. For each weak technique, look
   for a detection rule that would catch it — matched by the rule's name or
   content referencing the technique (D&R rules don't always tag a MITRE id, so
   this is **best-effort**). Then call `list_detections` to see whether that rule
   has actually fired recently. A rule that exists but never fires is weak
   coverage too.
3. **Recommend a retest (f0_library — do not execute).** For each technique that
   is **weak AND lacks effective coverage** (no rule, or a rule that isn't
   firing), recommend re-running the matching **f0_library** test to re-validate
   *after* a detection rule is added or fixed. Name the technique and the test.
   State plainly: f0_library is the separate offensive repo the operator runs —
   this skill only produces the recommendation.

## Pitfalls

- **Technique ↔ rule matching is best-effort.** If you can't tie a weak technique
  to a specific rule by name/content, say "no clear LimaCharlie rule found for
  <technique>" rather than assuming coverage exists or doesn't.
- **Recommend, don't execute.** This skill never runs an f0_library test or
  changes a D&R rule — it hands the operator a prioritized retest list.
- **Never invent** technique scores, rule names, or detection counts.

## Small models

This chains two servers with per-technique matching. It favours a **capable local
model** (e.g. GPT-OSS 20B). On smaller models, run it for a **single** weak
technique at a time (get one technique from `get_weak_techniques`, then check just
that one against `list_dr_rules`) to keep each step simple.

## Verification

- Every recommendation ties a specific **weak technique** (from
  `get_weak_techniques`) to its **coverage status** (from `list_dr_rules` /
  `list_detections`), or explicitly says the coverage couldn't be determined.
- The f0_library retest is framed as a **recommendation**, never as an action taken.
- No values invented; no state changed.
```

- [ ] **Step 2: Run the validity guard**

Run: `uv run pytest skills/test_skills_valid.py -q`
Expected: PASS (both new skills validate).

- [ ] **Step 3: Sanity-check description length**

Run: `python3 -c "print(len('Weak techniques -> LC coverage -> retest recommendation'))"`
Expected: `55` (≤60).

- [ ] **Step 4: Commit**

```bash
git add skills/cross-platform/validation-coverage-loop/SKILL.md
git commit -m "feat(skills): add offensive/defensive validation-coverage-loop skill

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TMoap3fRVq13TQah7BMdLm"
```

---

### Task 3: Docs — user guide, CLAUDE.md, roadmap note

**Files:**
- Modify: `docs/user-guide/workflows.md` (add two cross-platform workflows)
- Modify: `CLAUDE.md` (skills list + architecture tree)
- Modify: `evals/README.md` (future-work note: multi-step/agentic skill eval)

**Interfaces:**
- Consumes: the two skill names from Tasks 1–2.

- [ ] **Step 1: Add the two workflows to the user guide**

In `docs/user-guide/workflows.md`, add a "Cross-platform workflows" section (match the page's existing `##` heading + `> **Prompt:**` style used by the other workflows). Add:

```markdown
## Cross-platform incident triage (SOC analyst / threat hunter)

> **Prompt:** "Triage this Defender incident and give me the full picture."

The `triage-incident-cross-platform` skill pivots across all four servers:
`list_incidents` (Defender) → for the involved user, `list_risky_users` /
`list_risk_detections` (Entra) → for the host, `get_sensor` + `query_telemetry`
(LimaCharlie) → for the technique, `get_weak_techniques` (ProjectAchilles). It
returns one correlated summary and flags any cross-platform join it could not
confirm by name. Read-only. Favours a capable local model (e.g. GPT-OSS 20B).

## Offensive/defensive loop (detection engineer)

> **Prompt:** "Turn our weak techniques into a retest plan."

The `validation-coverage-loop` skill runs `get_weak_techniques` (ProjectAchilles)
→ checks each against `list_dr_rules` / `list_detections` (LimaCharlie) → and
recommends which **f0_library** test to re-run for techniques that are weak and
uncovered. f0_library is the separate offensive repo the operator runs — the
skill only recommends. Read-only.
```

- [ ] **Step 2: Update the skills list in CLAUDE.md**

In `CLAUDE.md`, find the "Current skills:" sentence (around line 164) and append the cross-platform skills. Change the end of that sentence from:

```
`projectachilles/{defense-posture-review,coverage-gap-analysis,validation-fleet-review}`.
```

to:

```
`projectachilles/{defense-posture-review,coverage-gap-analysis,validation-fleet-review}`, and `cross-platform/{triage-incident-cross-platform,validation-coverage-loop}` (multi-server correlation playbooks — favour a capable local model).
```

Then, in the Architecture directory tree in `CLAUDE.md` (the `skills/` block that lists `defender/`, `entra/`, `limacharlie/`), add a line under it:

```
    cross-platform/         # multi-server correlation: incident triage, offensive<->defensive loop
```

- [ ] **Step 3: Add the multi-step-eval future note**

In `evals/README.md`, add a short "Future" note (match its heading style):

```markdown
## Future: multi-step (agentic) skill eval

Today the harness measures **single** tool selection per prompt. The cross-platform
correlation skills (`skills/cross-platform/`) chain several tools across servers with
state between steps — measuring whether a small model drives the *whole chain*
end-to-end needs a new multi-step/agentic eval (drive a skill, score each step's tool
choice + the final synthesis). Tracked as a roadmap item; not built yet.
```

- [ ] **Step 4: Verify everything passes**

Run: `uv run pytest skills/ -q && uv run pytest -q`
Expected: all pass (skills validity + full suite unaffected).

Run a markdown-link sanity check on the edited docs (no broken relative links introduced):
```bash
grep -o "](\.\./[^)]*)" docs/user-guide/workflows.md | head
```
Expected: only pre-existing relative links; the new sections add none that don't resolve.

- [ ] **Step 5: Commit**

```bash
git add docs/user-guide/workflows.md CLAUDE.md evals/README.md
git commit -m "docs: wire cross-platform skills into user guide + CLAUDE.md; note multi-step eval as future

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TMoap3fRVq13TQah7BMdLm"
```

---

## Self-Review

**Spec coverage:**
- Two `SKILL.md` under `skills/cross-platform/` → Tasks 1, 2. ✓
- Skill 1 procedure (Defender→Entra→LC→PA, one tool per step) → Task 1 content. ✓
- Skill 2 procedure (PA→LC→f0_library recommend-only) → Task 2 content. ✓
- Read-only, no fabrication, best-effort-by-name joins stated, model-tier note → both skills' Pitfalls/Small-models/Verification sections. ✓
- Passes `test_skills_valid.py` → Tasks 1/2 Step 2. ✓
- User-guide workflows + CLAUDE.md skills list/tree → Task 3. ✓
- Multi-step agentic eval → roadmap (evals/README future note) → Task 3 Step 3. (Also recorded in controller memory.) ✓
- f0_library recommend-only, separate repo → Skill 2 When-to-Use + Procedure step 3 + Pitfalls. ✓

**Placeholder scan:** No TBD/TODO. The two `SKILL.md` files are given in full, verbatim. Task 3 doc edits show exact before/after text. Docs prose is content, not code — acceptable.

**Type/name consistency:** Skill names `triage-incident-cross-platform` / `validation-coverage-loop` are identical across Tasks 1/2 (frontmatter), Task 3 (CLAUDE.md list + user guide), and the Global Constraints. Descriptions ("...across Entra, LimaCharlie & PA" = 57; "Weak techniques -> LC coverage -> retest recommendation" = 55) are ≤60. All tool base names named in the skills are real (verified list in Global Constraints). Cross-referenced skill names (`triage-defender-incident`, `review-entra-identity-risk`, `investigate-lc-endpoint`) verified against the repo.
