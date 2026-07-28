# Eval dashboard — design

**Status:** approved 2026-07-27
**Goal:** a local, live web dashboard over the eval scorecard — watch a matrix sweep
fill in cell by cell, see the results as a heatmap, and see each model's trajectory
across past runs.

## Why

`evals/SCORECARD.md` is the repo's evidence for its central claim — that small local
models can drive these tools. It is regenerated at the *end* of a sweep. A full
6×9 matrix at `runs=3` takes 12–18 hours, during which the only visible signal is a
JSON file growing one cell at a time. There is no way to see progress, spot a dead
cell early, or read the shape of the results without waiting for the whole run.

This dashboard reads what the harness already writes. It changes no eval logic and
computes no scores of its own.

## Constraints

1. **Read-only observer.** It must never disturb a running sweep: no writes, no
   process control, no locks. A sweep that would have succeeded must succeed
   identically whether or not the dashboard is running.
2. **Nothing leaves the host** (Critical Rule 2 / the repo's local-only thesis).
   No CDN, no external fetch, no telemetry. The page is self-contained.
3. **No new dependencies.** stdlib `http.server` + `json`. The repo uses `uv`;
   pulling in a web framework to render one page is unjustified.
4. **Never serve the repo tree.** See the security note below — this is the single
   most important constraint in this document.

## Security: why not `python -m http.server`

The obvious way to serve a local page is `python -m http.server` from the repo root.
**This must never be done in this repo.** It would expose `.env.defender`,
`.env.entra`, `.env.limacharlie` and every other credential file over HTTP to
anything that can reach the port — a direct violation of Critical Rule 2 (secrets
never leave the host) and Rule 7 (per-platform credential isolation).

The dashboard server therefore:

- serves an **explicit allow-list of paths**, never a directory tree;
- binds **`127.0.0.1` only**, never `0.0.0.0`;
- resolves every requested path and refuses anything that escapes its allow-list,
  including encoded traversal (`%2e%2e%2f`) and symlinks.

A test asserts that `.env.defender` and a traversal payload are both refused.

## Architecture

Three pieces with clear boundaries:

| Piece | Responsibility | Depends on |
|---|---|---|
| `scripts/eval_dashboard.py` | HTTP server + data shaping (progress, ETA, trend) | `evals/results/*.json` (read-only) |
| `scripts/dashboard/index.html` | The view. Polls the API, renders three panels. | the JSON API |
| `evals/scorecard.py` | Records `elapsed_s` per cell (one small addition) | — |

Data shaping lives in the **server**, not the page: it is the part worth testing, and
keeping it in Python means `pytest` covers it. The page is a view over already-shaped
data.

### Why `scripts/`

`scripts/` already holds the repo's operator tooling — `gen_docs.py`,
`report_gather.py`, `confirm_action.py`, `live_smoke_*.py` — and is excluded from
strict mypy for exactly this class of code. The dashboard is operator tooling for the
eval harness and belongs beside them. It is **not** part of `core/` (no safety logic)
and **not** a server (it exposes no MCP tools).

## Data flow

```
evals/scorecard.py  --writes-->  evals/results/<date>.json
                                        |
                                        | (read-only, polled)
                                        v
                          scripts/eval_dashboard.py
                                 /api/progress
                                 /api/matrix
                                 /api/trend
                                        |
                                        | (fetch every 5s)
                                        v
                          scripts/dashboard/index.html
```

### The results JSON

Written by `run_matrix` after **every** cell, so it is always current and the sweep is
resumable. Shape:

```json
{
  "date": "2026-07-28", "runs": 3, "base_url": "...", "tool_total": 51,
  "models":  [{"tag": "gpt-oss:20b-ctx16k", "display": "GPT-OSS 20B"}, ...],
  "servers": ["defender", ..., "all"],
  "cells": {
    "gpt-oss:20b-ctx16k::defender": {"status": "ok", "tool_rate": 1.0, "args_rate": 1.0},
    "<tag>::<server>":              {"status": "error",    "error": "..."},
    "<tag>::<server>":              {"status": "unusable", "error": "..."}
  }
}
```

Cell count is `len(models) × len(servers)`; a key absent from `cells` is *pending*.

## The ETA problem

The results JSON records no timestamps, so there is no stored basis for an ETA. This
is solved in two places, because the two cases are genuinely different.

**Future runs.** `run_matrix` gains one addition: it records `elapsed_s` per cell as
that cell completes. ETA is then arithmetic over real observations.

**A run already in flight** (including the one running when this was written) has no
such data. The server records its own observations from the moment it starts and
reports `establishing` until it has seen at least 3 cells complete. Showing that is
correct; showing a confident number derived from one data point is not.

### ETA must be column-weighted

A naive mean over completed cells badly under-estimates. The `all` column registers
all 51 tools at once — a ~32 KB schema prefix on every call — and measured 20–73 s per
call versus ~5 s for a 7-tool server. That one column is the majority of a sweep's
runtime.

So the estimator keeps **two separate means**: one for per-server cells, one for `all`
cells, and projects `remaining_per_server × mean_per_server + remaining_all × mean_all`.
Until an `all` cell has completed, the `all` portion is reported as an unknown lower
bound rather than folded into a single number.

## The three views

### 1. Progress header

`N/<total> cells` where total is `len(models) × len(servers)` read from the results
file — never hardcoded, since the roster changes between runs (54 for the current
sweep, 49 for `2026-07-13`). Plus the model/server currently in flight, elapsed, and
ETA.

"Currently in flight" is derived as the first *pending* cell in `run_matrix`'s
iteration order (models outer, servers inner). This is correct for a resumed run too:
already-present cells are skipped, so the first pending cell is genuinely the next one
to execute.

A **red banner** lists every `error` or `unusable` cell with its message. This is the
panel's real job: `unusable` means a model emitted no tool call on an entire task set,
which is a serving problem (context too small for the schema), not a capability
result — the failure that produced four bogus 0% cells on 2026-07-26. Finding it 40
cells later instead of at 3 a.m. wastes hours of GPU.

### 2. Matrix heatmap

The models × servers grid, colour-scaled on score, filling in live. Pending cells
render visibly empty so the fill order is readable at a glance.

- Colour encodes `args_rate` (the stricter of the two rates; `args_correct` implies
  `tool_correct` in the harness).
- `error`/`unusable` cells are visually distinct from a *low score* — a broken cell and
  a bad score must never look alike, which is the same principle behind
  `assert_suite_usable` refusing to publish a serving failure as 0%.
- Clicking a cell shows `tool%`, `args%`, `status`, and any error text.

### 3. Historical trend

One sparkline per model across every `evals/results/*.json`, plotting mean
`args_rate`.

**Rosters differ between runs** and this view must not lie about that. `2026-07-13`
covered 6 servers and included Qwen3 4B; the current run covers 8 + `all` and drops
it. So:

- each point carries the roster it was computed over, shown on hover;
- a model absent from a run renders as a **gap**, never an interpolated line;
- the mean is over whatever servers that run actually contained, and the point is
  marked when its roster differs from the latest run's.

A trend line that silently averages different task sets is worse than no trend line.

## Error handling

| Failure | Behaviour |
|---|---|
| Results JSON missing | Page renders empty with "no run found for <date>" |
| JSON half-written (the sweep rewrites the whole file per cell) | Parse error caught; last good state retained; `stale` indicator shown |
| Results dir unreadable | Server returns 503 with a plain message; page shows it |
| Request outside the allow-list | 404, logged; never a traversal |
| Sweep not running | Progress shows final state; no ETA |

The page never blanks on a transient read failure — a dashboard that flickers empty
during a long run trains you to distrust it.

## Testing

`pytest`, offline, no server process required — the handler logic is exercised
directly.

**Security (non-negotiable)**
- `.env.defender` is refused
- `../` and `%2e%2e%2f` traversal is refused
- a symlink pointing outside the allow-list is refused
- the server binds `127.0.0.1`, not `0.0.0.0`

**Data shaping**
- progress counts pending/ok/error/unusable correctly
- the "currently running" cell matches `run_matrix`'s iteration order
- ETA is column-weighted: a fixture with slow `all` cells and fast per-server cells
  produces an estimate far above the naive mean
- ETA reports `establishing` below the 3-cell threshold
- trend renders a gap (not an interpolation) for a model missing from a run
- trend marks points whose roster differs from the latest run
- a half-written JSON leaves the last good state intact

**Not tested:** the HTML/JS rendering. It is a view over data that is tested, and a
browser harness would be a disproportionate dependency for one page.

## Out of scope (YAGNI)

- Publishing/sharing a hosted snapshot — the brief is local and live.
- Delta-vs-previous-run view — considered and explicitly dropped.
- Controlling the sweep (start/stop/re-run cells) from the page. A read-only observer
  cannot break a 18-hour run; a controller can.
- Authentication. It is `127.0.0.1`-bound and serves non-secret data.
- Live log streaming.
