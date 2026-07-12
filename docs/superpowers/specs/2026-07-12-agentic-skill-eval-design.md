# Design: Multi-step / agentic skill eval

**Date:** 2026-07-12
**Status:** Approved (design), pending spec review
**Scope:** One implementation plan — a new multi-step eval harness that measures whether a
small local model can DRIVE a whole `SKILL.md` procedure, alongside (not replacing) the
existing single-turn scorecard.

## Problem

The current eval harness (`evals/run.py`, per-server `tasks.yaml`, `evals/scorecard.py`)
measures **single-turn** tool-calling: given one natural-language prompt, does the model pick
the right tool and fill its args (`tool-selection% / argument-filling%`). It never tests the
thing skills actually are: **multi-step procedures**. Can a small model run
`triage-incident-cross-platform` (list_incidents → risky_users → sensor+telemetry →
weak_techniques) or `intune-coverage-gap-review` (compliance_summary → stale_devices →
managed_devices[noncompliant]) — call the right *sequence*, feed results forward, and reach the
right conclusion? This design adds that measurement.

## What we measure (decided in brainstorming)

- **Skill-adherence, not unaided orchestration.** The model receives the target skill's
  `## Procedure` in context (as it does in production via progressive disclosure). The question
  is "**can a small local model drive OUR skills**", which directly grades skill quality +
  model capability together — the repo's core thesis.
- **Dual metric per scenario** (mirrors the scorecard's `tool%/args%`):
  - **coverage%** = `|required_tools ∩ tools_called| / |required_tools|` — order-tolerant
    (reordering is not punished; extra exploratory calls do not lower it). Catches *missing*
    steps.
  - **goal-reached** (bool) = every `goal_keywords` entry appears in the final answer
    (case-insensitive substring). Catches *wrong conclusions*.
  - A scenario **passes** when coverage = 100% **and** goal-reached. Over N runs a cell reports
    `coverage% / goal-rate` (e.g. `100% / 3⁄3`).
- **Deterministic mock tools**, local-only, never in CI (needs Ollama/GPU) — same rule as the
  scorecard.

## Architecture

```
evals/
  agentic.py                     # multi-step harness: agent loop + trajectory scoring
  scenarios/
    triage-incident-cross-platform.yaml   # cross-platform (4-server pivot)
    intune-coverage-gap-review.yaml        # single-platform multi-step
    defender-triage-incident.yaml          # single-platform multi-step
  agentic_scorecard.py           # skill × model matrix generator (mirrors scorecard.py)
  AGENTIC.md                     # rendered skill×model matrix (committed, hand-annotated tail)
  results/agentic-<date>.json    # resumable results (mirrors scorecard results)
  tests/test_agentic.py          # offline harness contract test (fake model, no Ollama)
```

**Reuse the single-turn harness.** `ModelClient` (in `run.py`) gains a multi-turn method:

```
async def run_agent(self, system: str, user: str, tools: list[dict],
                    mock_fn: Callable[[str, dict], list[dict]],
                    max_steps: int = 8) -> AgentRun
```

It keeps an OpenAI message history: send (system + user + tools) → model returns `tool_calls`
→ for each, call `mock_fn(name, args)` and append a `role: tool` result message → loop until
the model returns a message with **no** tool calls (final answer) or `max_steps` is hit. Returns
`AgentRun(trajectory: list[str], final_answer: str, steps: int, error: str | None)` where
`trajectory` is the ordered list of tool names called.

**Skill-adherence prompt.** The system prompt = a short shared operator identity + the target
skill's `## Procedure` section, **read live from `skills/<skill>/SKILL.md` at run time** (so the
eval always grades the *current* skill text, never a stale copy) + a one-line instruction: "call
one tool at a time; when finished, give a final answer."

**Deterministic mocks.** Each scenario YAML carries canned, redacted findings keyed by tool
name. `mock_fn(tool_name, args)` returns the canned finding list for that tool regardless of
args (v1). A tool the model calls that has **no** mock returns a graceful
`{"note": "no mock for <tool>"}` finding (the run continues; the tool still appears in the
trajectory, so a missing mock is visible, not a crash). Arg-keyed mocks (different responses per
call) are noted as future work — the three chosen scenarios call each tool ~once.

## Scenario file shape

```yaml
skill: cross-platform/triage-incident-cross-platform   # path under skills/ (for the Procedure)
task: "Triage this Defender incident and give me the full picture."
required_tools: [list_incidents, list_risky_users, get_sensor, query_telemetry, get_weak_techniques]
goal_keywords: ["risky", "web-01", "T1110"]            # all must appear in the final answer
mocks:
  list_incidents:   [ { schema_version: "1.0", source: defender, finding_type: incident, ... } ]
  list_risky_users: [ { ... } ]
  get_sensor:       [ { ... } ]
  query_telemetry:  [ { ... } ]
  get_weak_techniques: [ { ... } ]
```

The three v1 scenarios are hand-authored with small, realistic findings drawn from the
platforms' known field shapes (the same shapes the contract-test fakes use). Scenarios are kept
to ~1 incident/entity so each tool is called about once (keeps tool-name mock keying sufficient).

## Output & fit alongside the scorecard

- `evals/AGENTIC.md` — a **skill (rows) × model (cols)** matrix, each cell `coverage% /
  goal-rate`; a hand-annotated findings section is preserved below a marker on regeneration
  (same mechanic as `SCORECARD.md`).
- `evals/results/agentic-<date>.json` — resumable, date-stamped, same shape/handling as the
  scorecard results.
- **Kept separate from the single-turn `SCORECARD.md`** — different unit (whole-skill
  orchestration vs one tool-call) and different axis (skills vs servers). They are siblings
  under `evals/`, both driven by `evals/models.yaml`.
- The **speed/resource** roadmap item (latency + VRAM) is a THIRD, orthogonal concern that
  belongs on the single-turn scorecard — explicitly out of scope here.

## Models

Both evals read the model set from **`evals/models.yaml`**. **Ministral 3 is removed from
`models.yaml`** (it emits no OpenAI `tool_calls` — 0% on the single-turn scorecard and unusable
for tool dispatch), so it drops from the scorecard AND this agentic eval in one change. (The
scorecard's existing Ministral row is pruned when `models.yaml` is updated and the matrix
regenerated.)

## Testing (the harness itself, offline & CI-safe)

`evals/tests/test_agentic.py` drives `run_agent` with a **fake ModelClient** that emits a
scripted `tool_calls` sequence (no Ollama), asserting:
- the loop feeds each mock tool result back and captures the trajectory in order;
- `max_steps` halts a runaway (a fake that never stops calling tools);
- scoring computes coverage/goal correctly — including a **partial-coverage** case (a required
  tool never called → coverage < 100%) and a **goal-missed** case (all tools called but a
  keyword absent → goal-reached false);
- a tool with no mock yields the graceful "no mock" finding and the run continues.

Deterministic, no model/network — the agentic harness's contract test, analogous to the existing
`evals/` harness-logic tests. `uv run pytest` and `ruff` stay green.

## Out of scope (YAGNI)

- No live-platform tool responses (deterministic mocks only).
- No arg-keyed mocks, no per-run branching scenarios (v1 keys mocks by tool name).
- No "both conditions" (with/without skill) A/B — skill-adherence only.
- No speed/resource metrics (separate roadmap item, on the scorecard).
- Not wired into CI (needs a local model box), same as the scorecard.
- Only 3 scenarios in v1; more skills added incrementally later.

## Files touched

| File | Change |
|---|---|
| `evals/run.py` | add `run_agent` (multi-turn loop) + `AgentRun` to `ModelClient` |
| `evals/agentic.py` | new — load scenarios, build the skill-adherence prompt, run + score |
| `evals/scenarios/*.yaml` | new — 3 hand-authored scenarios with mocks |
| `evals/agentic_scorecard.py` | new — skill×model matrix generator (mirrors `scorecard.py`) |
| `evals/AGENTIC.md` | new — rendered matrix (generated) |
| `evals/tests/test_agentic.py` | new — offline harness contract test |
| `evals/models.yaml` | remove Ministral 3 |
| `evals/README.md` | document the agentic eval + how to run it |
