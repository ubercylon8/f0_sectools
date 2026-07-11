# Design: Eval scorecard matrix + multi-server (combined-registry) eval

**Date:** 2026-07-11
**Status:** Approved (design), pending spec review
**Scope:** One implementation plan. (Roadmap item #2. Item #3, cross-platform skills, is deferred.)

## Problem

The small-model eval harness (`evals/run.py`) proves *one* thing today: a single server's
~6 tools, driven by *one* model, scored once and printed to the terminal. Two gaps weaken the
repo's core claim ("tools small local models can actually drive"):

1. **No model matrix.** The 100%/100% baseline is a single model (Gemma 4 E4B). The repo's
   stated floor names GPT-OSS and Qwen3 too. There is no published, reproducible scorecard
   across models — the table that *is* the product's credibility.
2. **No composition test.** Every eval runs a server in isolation (~6 tools). But real
   operators register all four servers at once — **22 tools** — and tool mis-selection across
   many tools is precisely the documented small-model failure mode the repo exists to guard
   against. The `≤8-tools-per-server` discipline has never been tested *under composition*.

This design adds both, reusing the existing harness internals. No server or `core/` change.

## Grounding facts (verified 2026-07-11)

- The four servers expose **22 tools total, all uniquely named** (no collisions), so a combined
  registry can reuse existing per-server tasks — `expect_tool` stays unambiguous with all 22
  present.
- The harness already drives **GPT-OSS 20b on Ollama** (OpenAI-compatible endpoint at
  `http://localhost:11434/v1`) to 100%/100% single-server. Endpoint + tool-calling path confirmed.
- Reusable `run.py` internals: `server_tool_schemas(server)`, `ModelClient`, `load_tasks(server)`,
  `run_suite(tools, tasks, client, runs)`, `score_task`, `_args_match`, `format_report`.
- Broad-sweep model set (all tool-capable, already pulled): `gpt-oss:20b-c128k`,
  `qwen3:8b-c40k`, `qwen3:4b-c256k`, `qwen3.5:latest`, `gemma4:e4b`, `gemma4:12b`,
  `ministral-3:latest-c256k`, `granite4:tiny-h-c128k`.

## Architecture

Two additions, both reusing `run.py`'s building blocks. `run.py` stays the single-run tool.

```
evals/
  run.py            # (modify) add combined-registry mode: --server all
  scorecard.py      # (new) matrix orchestrator: models × servers → JSON + SCORECARD.md
  models.yaml       # (new) the broad-sweep model list (tag + display name)
  combined/
    probes.yaml     # (new) ~6 deliberately cross-platform-ambiguous routing probes
  results/          # (new, gitignored) per-run JSON scorecards
  SCORECARD.md      # (new, committed) generated human-readable matrix table
  tests/
    test_scorecard.py    # (new) offline unit tests (fake ModelClient)
    test_combined.py     # (new) offline unit tests for combined registry + scoring
```

### Part 2a — scorecard matrix (`evals/scorecard.py`)

- **Model list** from `evals/models.yaml`: a list of `{tag, display}` entries (the broad-sweep 8).
  Base URL is a CLI arg (default `http://localhost:11434/v1`) — environment-specific, not
  committed into the model list.
- **CLI:** `uv run python -m evals.scorecard --base-url <url> [--runs N] [--models a,b] [--servers …] [--no-write]`.
  Defaults: all models in `models.yaml` × all servers (`defender, entra, limacharlie, projectachilles`)
  plus the combined `all` registry as an additional column.
- **Incremental, resumable persistence.** Each (model, server) cell is written to
  `evals/results/<date>.json` the moment it completes. On restart, cells already present for that
  date are skipped unless `--force`. A crashed 40-minute sweep loses nothing.
- **Output:** `evals/SCORECARD.md` — rows = models (display name), columns = servers + `all` +
  an overall, each cell `tool% / args%`. Regenerated from the JSON so it can be rebuilt without
  re-running. `--no-write` skips writing both the JSON and the markdown (ad-hoc checks). The
  README/user-guide links to `SCORECARD.md`.
- **Runs default = 1.** The harness uses `temperature=0`, so `runs>1` mostly catches
  GPU/sampling nondeterminism rather than true variance; the matrix favours breadth. `--runs`
  stays configurable, and the single-server *baseline* can still be validated at `runs=3` via
  `run.py`. A `runs=1` cell that scores <100% is re-checked at higher runs before being reported
  as a defect (nondeterminism vs a real miss).

### Part 2b — combined-registry mode (`run.py`)

- `--server all` builds the union of all four servers' tool schemas (22 tools) into one OpenAI
  tool list and runs **every existing per-server task** against it.
- **Collision guard:** the combined builder raises if two servers expose the same tool name
  (today none) — fail loud, never silently drop a tool.
- **Per-origin routing report.** Each task carries its origin server (the tasks.yaml it came
  from). The combined report aggregates accuracy **by origin server**, so a Defender-origin prompt
  that gets routed to LimaCharlie's `query_telemetry` shows up as a Defender routing miss. This is
  the core new signal: cross-platform mis-routing = a tool-description defect to fix (sharper,
  platform-naming descriptions), not a lowered bar.
- **`evals/combined/probes.yaml`:** ~6 hand-written prompts that are deliberately ambiguous
  across platforms (e.g. hunting — Defender `run_hunting_query` vs LimaCharlie `query_telemetry`;
  "list agents" (PA) vs "list sensors" (LimaCharlie); "risky users" (Entra) vs "risk acceptances"
  (PA)). Same schema as tasks.yaml (`prompt`, `expect_tool`, optional `expect_args*`), plus an
  `origin` field naming the platform the ask *should* route to. Run alongside the reused tasks in
  combined mode.
- The gated write tools (`isolate_host`/`release_host`) are in the registry; the eval only asks
  *which* tool the model would call, never executes — so "isolate host X → isolate_host" is a
  measured routing case.

## Data flow

```
scorecard.py
  read models.yaml → for each model:
    for each server in [defender, entra, limacharlie, projectachilles, all]:
      tools  = combined_tool_schemas()  if server=='all' else server_tool_schemas(server)
      tasks  = combined_tasks()         if server=='all' else load_tasks(server)
      report = run_suite(tools, tasks, client, runs)   # existing internal
      write cell → results/<date>.json          # incremental
  regenerate SCORECARD.md from results/<date>.json
```

Two new combined helpers (used by both `scorecard.py` and `run.py --server all`):
- `combined_tool_schemas()` — union of all four servers' schemas (asserts no name collision).
- `combined_tasks()` — every per-server task with its `origin` set to that server, concatenated
  with `evals/combined/probes.yaml` (each probe already carries `origin`). There is **no**
  `evals/all/tasks.yaml`; `load_tasks` is never called with `'all'`.

`run.py --server all` uses the same two helpers for a single ad-hoc combined run, printing the
per-origin report to the terminal.

## Error handling

- **Model unreachable / HTTP error:** a cell records an `error` status (not a crash); the sweep
  continues to the next cell and the scorecard shows `err` for that cell. One dead model never
  aborts the matrix.
- **Model returns no tool call:** already handled by `score_task` (counts as a miss) — unchanged.
- **Malformed `models.yaml` / missing tasks:** fail fast with a clear message before any run.
- **Collision in combined registry:** raise immediately (see 2b).

## Testing

**Offline unit tests (CI, no live model) — the layer that gates merges:**
- `test_combined.py`: combined registry unions all 22 tools; collision assertion fires on a
  duplicate; per-origin scoring attributes a miss to the correct origin server; probes.yaml loads
  and validates.
- `test_scorecard.py`: matrix aggregation math; incremental JSON write + resume-skip (a
  pre-populated results file skips completed cells); `SCORECARD.md` table generation from a fixed
  JSON fixture; `error`-cell handling; `--no-write` writes nothing. All driven by a **fake
  `ModelClient`** returning canned `ToolCall`s — deterministic, fast, no network.

**Live runs (produce the real numbers, run after infra is built + unit-tested):**
- A quick 2-model smoke to confirm matrix wiring against live Ollama.
- The full broad-sweep matrix + combined eval, run in the background; report the populated
  `SCORECARD.md` and the per-origin routing findings. Poorly scoring tools are filed as design
  defects (sharpen description/schema), never accommodated by lowering the bar.

## Out of scope (YAGNI)

- Cross-platform correlation skills (roadmap #3) — deferred by decision.
- Auto-serving models / managing Ollama — the harness only consumes an existing endpoint.
- Per-token latency / cost metrics — the scorecard measures callability (tool + arg accuracy) only.
- CI-gating on live model scores — live runs are manual/scheduled; only the offline harness-logic
  tests gate CI (unchanged policy from the existing eval design).
- Changing any tool description in this pass — the eval *surfaces* defects; fixing a specific
  tool's description is a follow-up driven by what the combined run reveals.

## Files touched

| File | Change |
|---|---|
| `evals/run.py` | add `--server all` combined-registry mode + per-origin report |
| `evals/scorecard.py` | new — matrix orchestrator, incremental JSON, SCORECARD.md generator |
| `evals/models.yaml` | new — broad-sweep model list (tag + display) |
| `evals/combined/probes.yaml` | new — cross-platform routing probes |
| `evals/SCORECARD.md` | new (committed) — generated matrix table (populated by the live sweep) |
| `evals/results/.gitignore` | new — ignore per-run JSON results |
| `evals/tests/test_scorecard.py` | new — offline unit tests (fake client) |
| `evals/tests/test_combined.py` | new — offline unit tests |
| `evals/README.md` | document scorecard + combined mode; link SCORECARD.md |
| `docs/user-guide/…` | note the scorecard in the eval/testing section |
