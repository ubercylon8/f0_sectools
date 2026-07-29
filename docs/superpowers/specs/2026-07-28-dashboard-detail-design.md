# Eval dashboard — explanatory detail

**Status:** approved 2026-07-28
**Goal:** make the scorecard legible. A reader who has never seen the repo should
understand what is being measured and why; a contributor should be able to click any
cell and see exactly which task failed and what the model called instead.

## Why

The dashboard today shows a grid of percentages. It answers "what is the number" and
nothing else. Neither audience is served:

- A newcomer cannot tell what a "task" is, what `tool-selection` vs `argument-filling`
  means, or what a good number would be.
- A contributor looking at `86%` cannot see *which* task failed without re-running the
  cell on a GPU — which is exactly how the afternoon of 2026-07-28 was spent.

That second point is the sharp one, because **the data was never missing — it was
discarded.**

## The core finding: the harness already computes this

`run_suite` (`evals/run.py`) returns, for every cell:

```python
{"tasks": [{"prompt", "expect_tool", "tool_rate", "args_rate", "runs", "calls"}],
 "overall_tool_rate", "overall_args_rate",
 "no_call_rate", "schema_kb", "tool_count"}
```

`run_matrix` persists **three** of those fields — `status`, `tool_rate`, `args_rate`
(plus `elapsed_s`) — and drops the rest.

`calls` is the ordered list of tool names the model actually chose on each run. **It
names the misroute.** Every question answered by re-running the GPU on 2026-07-28 —
*which task failed, what did it call instead* — had already been computed during the
sweep and thrown away.

Results file today: **7.4 KB**. With per-task rows for the full matrix: **~200 KB**.
The cost of keeping it is nil.

## Constraints

1. **Read-only observer**, `127.0.0.1` only, no URL mapped to a filesystem path — all
   inherited from the existing dashboard and non-negotiable.
2. **No new dependencies.** stdlib + vanilla JS.
3. **Backward compatible.** Result files written before this change lack per-task rows.
   The dashboard must degrade to today's behaviour for them, never error.
4. **Poll payloads stay small.** The matrix endpoint keeps returning summary only; a
   200 KB file must not be shipped every five seconds.

## Where the detail comes from

Two independent sources, deliberately:

| Source | Gives | Works for |
|---|---|---|
| `evals/<server>/tasks.yaml` | the task **inventory** — every prompt, its expected tool, the asserted args | **every run, retroactively** |
| persisted per-task rows | the **outcome** — pass rate per task, and which tool was actually called | runs from this change onward |

The YAML source is what makes today's 49 cells immediately more legible: even without
outcomes, the dashboard can show *what each server tests*. The persisted rows add what
happened. Neither substitutes for the other.

## Architecture

Unchanged in shape — one stdlib server, one self-contained page:

| Piece | Change |
|---|---|
| `evals/scorecard.py` | `run_matrix` persists `tasks`, `schema_kb`, `tool_count`, `no_call_rate` per cell |
| `scripts/eval_dashboard.py` | new `/api/cell` (one cell's detail, on demand) and `/api/servers` (task inventory + tool counts) |
| `scripts/dashboard/index.html` | narrative header, clickable cells, drill-down panel, per-server cards |

### Query parameters, without breaking the security property

`/api/cell` needs `model` and `server` parameters, which the current exact-match router
cannot express. The router will split path from query string and exact-match the **path**
only; parameters are parsed separately.

**This preserves the invariant that matters:** the parameters are used solely as **dict
keys into already-parsed JSON**. They are never joined to a path, never opened, never
resolved. A request for `?server=../../.env.defender` returns "no such cell", because
there is no such key — not because a check caught it.

## The page, layered

**1. What this measures** — three or four sentences in plain language, then **one real
task shown end-to-end**: the prompt, the tool that should be chosen, the arguments that
must be filled, and what a pass means. A single concrete example teaches more than a
paragraph of definitions. The example is read live from the task YAML, so it cannot drift
from the real task set.

**2. The matrix** — as today, with every cell clickable.

**3. Drill-down** (the payoff) — click a cell, get every task in that server's set,
**failures first**: prompt, expected tool, pass rate across runs, and when it failed,
the tool the model chose instead. This is where `86%` becomes *"`find_tests`
cyber-hygiene fails 0/3; the model calls `get_test` instead."*
For a cell whose result predates this change, the panel shows the task inventory from
YAML with outcomes marked "not recorded for this run" — honest about which half is
missing rather than blank.

**4. Per-server cards** — tools, schema KB, task count per server. This is where the
composition story becomes visible: 8 tools at ~6 KB versus 51 at ~32 KB.

**5. Signal-vs-noise band** — stated where numbers are read, not in a footnote: a
`runs=3` cell is a noisy point estimate; only failures that reproduce are defects. This
is the central methodological finding of 2026-07-28 and the dashboard is where it will
actually be seen.

## Re-sweep

The enriched view needs enriched data, so after the `all` column completes, the full
per-server matrix is re-run with the new persistence (~2 h on a free GPU). Two benefits
beyond the detail: it produces a second independent sample of every cell, which directly
tests the reproduces-vs-noise question the current table can only raise.

## Error handling

| Case | Behaviour |
|---|---|
| Cell has no per-task rows (old run) | Panel shows YAML inventory, outcomes marked unrecorded |
| `/api/cell` names a model/server with no cell | 200 with `{"found": false}` — not an error |
| Task YAML unreadable or malformed | Server card omits counts; page still renders |
| Results file half-written | Existing `stale` behaviour, unchanged |

## Testing

- per-task rows survive the round trip through `run_matrix` and appear in the results JSON
- a cell written **without** per-task rows still renders (backward compatibility)
- `/api/cell` returns `found: false` for an unknown model/server, including
  `?server=../../.env.defender` — asserting the parameter is a dict key, never a path
- the existing security suite still passes: no URL resolves to a filesystem path
- task inventory loads from YAML for a server with no cell results at all
- drill-down orders failures before passes

## Out of scope (YAGNI)

- Linking cells to the PRs that moved them — needs a hand-maintained annotation file.
  Revisit once the rest exists.
- Editing task sets, re-running cells, or any write action from the page. The dashboard
  stays a read-only observer.
- Charting per-task history across runs. The trend panel covers the model level; per-task
  trends need more runs than exist.
