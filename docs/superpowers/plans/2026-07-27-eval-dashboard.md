# Eval Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A local, read-only web dashboard over `evals/results/*.json` showing live sweep progress with a column-weighted ETA, a matrix heatmap that fills in cell by cell, and per-model trend across past runs.

**Architecture:** One self-contained script (`scripts/eval_dashboard.py`) holding pure data-shaping functions plus a stdlib HTTP server, and one self-contained HTML page it serves. The server never derives a filesystem path from a URL — routes are a fixed dict — so directory traversal is impossible by construction. `evals/scorecard.py` gains a per-cell `elapsed_s` so future runs have a real basis for an ETA.

**Tech Stack:** Python 3.11 stdlib only (`http.server`, `json`, `time`, `pathlib`). No new dependencies. Vanilla HTML/CSS/JS, no framework, no CDN.

## Global Constraints

- **Read-only observer.** The dashboard never writes to `evals/results/`, never signals the sweep process, never takes a lock. A sweep must behave identically whether or not it is running.
- **Never serve the repo tree.** `python -m http.server` from the repo root would expose `.env.defender` and every other credential file. The server maps no URL to a filesystem path.
- **Bind `127.0.0.1` only** — never `0.0.0.0`.
- **No new dependencies.** stdlib only. The repo uses `uv`; do not add a web framework.
- **Self-contained page.** Inline CSS and JS. No CDN, no external fetch, no telemetry.
- **Tests live in `scripts/tests/`** and load the script with `importlib.util.spec_from_file_location`, because `scripts/` is not a package. Follow `scripts/tests/test_gen_docs.py`.
- **`scripts/` is excluded from strict mypy** (`pyproject.toml:66-72`) — type annotations are welcome but not gated.
- **pytest `testpaths`** already includes `scripts` and `evals`; `pythonpath = ["."]` makes `evals` importable.
- Cell keys are `f"{model_tag}::{server}"`. Parse with `key.rsplit("::", 1)`.
- `run_matrix` iterates **models outer, servers inner**, and skips cells already present.

---

### Task 1: Record per-cell `elapsed_s` in the sweep

**Files:**
- Modify: `evals/scorecard.py` (imports; `run_matrix` cell loop)
- Test: `evals/test_scorecard.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: each `results["cells"][key]` dict gains `"elapsed_s": float` (rounded to 1 dp) for cells that complete in this process — including `error` and `unusable` cells, since a cell that took 9 minutes to fail still consumed 9 minutes. Cells written by earlier runs simply lack the key; every consumer must treat it as optional.

- [ ] **Step 1: Write the failing test**

Add to `evals/test_scorecard.py`:

```python
@pytest.mark.asyncio
async def test_run_matrix_records_elapsed_per_cell(tmp_path, monkeypatch):
    # A cell's duration is the only basis a dashboard has for an ETA, and the
    # results JSON carried no timing at all. Every completed cell records it.
    import evals.scorecard as sc

    ticks = iter([100.0, 130.5, 200.0, 260.0])
    monkeypatch.setattr(sc.time, "monotonic", lambda: next(ticks))

    out = tmp_path / "r.json"
    results = await sc.run_matrix(
        models=[{"tag": "m1", "display": "M1"}],
        servers=["defender", "entra"],
        base_url="http://x/v1",
        runs=1,
        out_path=out,
        date="2026-01-01",
        client_factory=_fake_factory("get_secure_score"),
    )
    assert results["cells"]["m1::defender"]["elapsed_s"] == 30.5
    assert results["cells"]["m1::entra"]["elapsed_s"] == 60.0
    # and it survives the round-trip to disk
    assert json.loads(out.read_text())["cells"]["m1::defender"]["elapsed_s"] == 30.5
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest evals/test_scorecard.py::test_run_matrix_records_elapsed_per_cell -v`
Expected: FAIL — `KeyError: 'elapsed_s'` (or `AttributeError` on `sc.time` until the import is added).

- [ ] **Step 3: Implement**

In `evals/scorecard.py`, add `import time` to the imports (alphabetical order — ruff enforces import sorting; it goes after `import json`).

In `run_matrix`, wrap the cell body. The `started` must be taken **before** the `try`, and the write must record elapsed on every branch:

```python
            started = time.monotonic()
            try:
                tools, tasks = await _tools_and_tasks(server)
                if server == "all":
                    results["tool_total"] = len(tools)
                async with factory(base_url, tag) as client:
                    rep = await run_suite(tools, tasks, client, runs=runs)
                assert_suite_usable(rep, tag)
                results["cells"][key] = {
                    "status": "ok",
                    "tool_rate": rep["overall_tool_rate"],
                    "args_rate": rep["overall_args_rate"],
                }
            except ValueError:
                raise  # e.g. tool-name collision — fail loud
            except SuiteUnusable as e:
                results["cells"][key] = {"status": "unusable", "error": str(e)[:400]}
            except Exception as e:  # noqa: BLE001 - one dead cell must not kill the sweep
                results["cells"][key] = {"status": "error", "error": str(e)[:200]}
            # A cell that took nine minutes to FAIL still consumed nine minutes;
            # timing every terminal branch keeps the ETA honest when cells break.
            results["cells"][key]["elapsed_s"] = round(time.monotonic() - started, 1)
            _write_results(out_path, results)
```

Note the `raise` on `ValueError` deliberately skips the timing line — that path aborts the sweep, so there is nothing left to estimate.

- [ ] **Step 4: Run tests**

Run: `uv run pytest evals/ -q`
Expected: PASS, including the pre-existing resume/persistence tests.

- [ ] **Step 5: Commit**

```bash
git add evals/scorecard.py evals/test_scorecard.py
git commit -m "feat(evals): record elapsed_s per scorecard cell"
```

---

### Task 2: Results loading, progress and matrix shaping

**Files:**
- Create: `scripts/eval_dashboard.py`
- Test: `scripts/tests/test_eval_dashboard.py`

**Interfaces:**
- Consumes: the results JSON shape, including the optional `elapsed_s` from Task 1.
- Produces:
  - `RESULTS_DIR: Path` — `<repo>/evals/results`
  - `load_results(path: Path) -> dict` — parses; raises `ValueError` on malformed JSON
  - `latest_results_path(results_dir: Path) -> Path | None` — newest by filename, ignoring `agentic-*.json`
  - `progress(results: dict) -> dict` with keys `done, total, pending, ok, failed, current`
  - `matrix(results: dict) -> dict` with keys `servers, rows`

- [ ] **Step 1: Write the failing tests**

Create `scripts/tests/test_eval_dashboard.py`:

```python
"""Tests for the local eval dashboard.

Loads the script by path (scripts/ is not a package) — same pattern as
scripts/tests/test_gen_docs.py.
"""
import importlib.util
import json
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "eval_dashboard", Path(__file__).resolve().parents[1] / "eval_dashboard.py"
)
dash = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(dash)


def _results(**over):
    base = {
        "date": "2026-07-28",
        "runs": 3,
        "models": [
            {"tag": "m1", "display": "M1"},
            {"tag": "m2", "display": "M2"},
        ],
        "servers": ["defender", "entra", "all"],
        "cells": {
            "m1::defender": {"status": "ok", "tool_rate": 1.0, "args_rate": 1.0,
                             "elapsed_s": 300.0},
            "m1::entra": {"status": "error", "error": "boom", "elapsed_s": 12.0},
        },
    }
    base.update(over)
    return base


def test_progress_counts_every_state():
    p = dash.progress(_results())
    assert p["total"] == 6          # 2 models x 3 servers
    assert p["done"] == 2
    assert p["pending"] == 4
    assert p["ok"] == 1
    assert [f["key"] for f in p["failed"]] == ["m1::entra"]
    assert p["failed"][0]["error"] == "boom"


def test_progress_current_follows_run_matrix_iteration_order():
    # run_matrix goes models outer, servers inner, skipping present cells —
    # so the next cell to run is the first PENDING one in that order.
    assert dash.progress(_results())["current"] == "m1::all"


def test_progress_current_is_none_when_complete():
    cells = {f"{m}::{s}": {"status": "ok", "tool_rate": 1.0, "args_rate": 1.0}
             for m in ("m1", "m2") for s in ("defender", "entra", "all")}
    assert dash.progress(_results(cells=cells))["current"] is None


def test_matrix_marks_absent_cells_pending_and_keeps_error_text():
    m = dash.matrix(_results())
    assert m["servers"] == ["defender", "entra", "all"]
    row = next(r for r in m["rows"] if r["tag"] == "m1")
    assert row["display"] == "M1"
    by_server = {c["server"]: c for c in row["cells"]}
    assert by_server["defender"]["status"] == "ok"
    assert by_server["defender"]["args_rate"] == 1.0
    assert by_server["entra"]["status"] == "error"
    assert by_server["entra"]["error"] == "boom"
    # A cell never run is PENDING — never a zero score.
    assert by_server["all"]["status"] == "pending"
    assert by_server["all"]["args_rate"] is None


def test_load_results_rejects_a_half_written_file(tmp_path):
    # run_matrix rewrites the whole file each cell, so a read can land mid-write.
    p = tmp_path / "r.json"
    p.write_text('{"cells": {"a": ')
    with pytest.raises(ValueError):
        dash.load_results(p)


def test_latest_results_path_ignores_agentic_runs(tmp_path):
    (tmp_path / "2026-07-11.json").write_text("{}")
    (tmp_path / "2026-07-28.json").write_text("{}")
    (tmp_path / "agentic-2026-07-12.json").write_text("{}")
    assert dash.latest_results_path(tmp_path).name == "2026-07-28.json"


def test_latest_results_path_none_when_empty(tmp_path):
    assert dash.latest_results_path(tmp_path) is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest scripts/tests/test_eval_dashboard.py -v`
Expected: FAIL — `FileNotFoundError` / `ModuleNotFoundError` for `eval_dashboard.py`.

- [ ] **Step 3: Implement**

Create `scripts/eval_dashboard.py`:

```python
#!/usr/bin/env python3
"""Local, read-only dashboard over the eval scorecard.

Serves a single self-contained page plus a small JSON API over
`evals/results/*.json`: live sweep progress with a column-weighted ETA, the
matrix as a heatmap, and per-model trend across past runs.

SECURITY: this server maps NO url to a filesystem path. Routes are a fixed
dict and the page is read from a module constant. Serving this repo with
`python -m http.server` would expose .env.defender and every other credential
file over HTTP — hence no directory handler, ever. Binds 127.0.0.1 only.

Read-only by construction: it opens result files for reading and nothing else,
so it cannot disturb a sweep in flight.

    uv run python scripts/eval_dashboard.py           # http://127.0.0.1:8765
    uv run python scripts/eval_dashboard.py --port 9000
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "evals" / "results"
PAGE = Path(__file__).resolve().parent / "dashboard" / "index.html"

# Agentic runs use a different schema (trajectories, not model x server cells).
_AGENTIC_PREFIX = "agentic-"


def load_results(path: Path) -> dict[str, Any]:
    """Parse a results file. Raises ValueError on malformed/partial JSON."""
    return json.loads(path.read_text(encoding="utf-8"))


def latest_results_path(results_dir: Path) -> Path | None:
    """Newest matrix results file by name (dates sort lexically)."""
    files = sorted(
        p for p in results_dir.glob("*.json") if not p.name.startswith(_AGENTIC_PREFIX)
    )
    return files[-1] if files else None


def _cell_key(tag: str, server: str) -> str:
    return f"{tag}::{server}"


def progress(results: dict[str, Any]) -> dict[str, Any]:
    """Counts by state, the failures worth waking someone for, and what is next."""
    models = results.get("models") or []
    servers = results.get("servers") or []
    cells = results.get("cells") or {}

    failed = [
        {"key": k, "status": c.get("status"), "error": c.get("error", "")}
        for k, c in cells.items()
        if c.get("status") not in ("ok", None)
    ]
    # run_matrix iterates models outer, servers inner and skips present cells,
    # so the next cell to execute is the first pending one in that same order.
    current = None
    for m in models:
        for s in servers:
            key = _cell_key(m["tag"], s)
            if key not in cells:
                current = key
                break
        if current:
            break

    total = len(models) * len(servers)
    return {
        "date": results.get("date"),
        "runs": results.get("runs"),
        "total": total,
        "done": len(cells),
        "pending": total - len(cells),
        "ok": sum(1 for c in cells.values() if c.get("status") == "ok"),
        "failed": sorted(failed, key=lambda f: f["key"]),
        "current": current,
    }


def matrix(results: dict[str, Any]) -> dict[str, Any]:
    """The grid. A cell never run is `pending` — never a zero score."""
    servers = results.get("servers") or []
    cells = results.get("cells") or {}
    rows = []
    for m in results.get("models") or []:
        row_cells = []
        for s in servers:
            c = cells.get(_cell_key(m["tag"], s))
            if c is None:
                row_cells.append({"server": s, "status": "pending",
                                  "tool_rate": None, "args_rate": None, "error": ""})
            else:
                row_cells.append({
                    "server": s,
                    "status": c.get("status", "ok"),
                    "tool_rate": c.get("tool_rate"),
                    "args_rate": c.get("args_rate"),
                    "error": c.get("error", ""),
                })
        rows.append({"tag": m["tag"], "display": m.get("display", m["tag"]),
                     "cells": row_cells})
    return {"servers": servers, "rows": rows}
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest scripts/tests/test_eval_dashboard.py -v`
Expected: PASS (8 tests).

- [ ] **Step 5: Commit**

```bash
git add scripts/eval_dashboard.py scripts/tests/test_eval_dashboard.py
git commit -m "feat(evals): dashboard progress and matrix shaping"
```

---

### Task 3: Column-weighted ETA

**Files:**
- Modify: `scripts/eval_dashboard.py`
- Test: `scripts/tests/test_eval_dashboard.py`

**Interfaces:**
- Consumes: `_cell_key`, and `elapsed_s` from Task 1.
- Produces: `eta(results: dict, observed: dict[str, float] | None = None) -> dict` returning `{"status": "establishing"|"partial"|"ok", "seconds": float|None, "samples": int, "mean_per_server": float|None, "mean_all": float|None}`.
  - `observed` supplies timings the server measured itself, for a sweep that started before Task 1 shipped. Values in `elapsed_s` win over `observed` for the same key.
  - `MIN_ETA_SAMPLES = 3`.

- [ ] **Step 1: Write the failing tests**

Append to `scripts/tests/test_eval_dashboard.py`:

```python
def _timed(cells):
    return {
        "models": [{"tag": f"m{i}", "display": f"M{i}"} for i in (1, 2, 3)],
        "servers": ["defender", "entra", "all"],
        "cells": cells,
    }


def test_eta_is_establishing_below_the_sample_threshold():
    # One data point cannot produce an honest estimate; say so rather than guess.
    r = _timed({"m1::defender": {"status": "ok", "elapsed_s": 300.0}})
    e = dash.eta(r)
    assert e["status"] == "establishing"
    assert e["seconds"] is None
    assert e["samples"] == 1


def test_eta_weights_the_all_column_separately():
    # The `all` column registers 51 tools at once (~32KB schema on every call)
    # and measured 4-15x slower per call. A single pooled mean under-estimates
    # a sweep badly, because `all` cells dominate the remaining time.
    r = _timed({
        "m1::defender": {"status": "ok", "elapsed_s": 100.0},
        "m1::entra": {"status": "ok", "elapsed_s": 100.0},
        "m1::all": {"status": "ok", "elapsed_s": 1000.0},
    })
    e = dash.eta(r)
    assert e["status"] == "ok"
    assert e["mean_per_server"] == 100.0
    assert e["mean_all"] == 1000.0
    # remaining: 4 per-server (m2,m3 x defender,entra) + 2 all (m2,m3)
    assert e["seconds"] == 4 * 100.0 + 2 * 1000.0
    # A naive pooled mean would have said 6 * 400 = 2400s — less than half.
    assert e["seconds"] > 2400


def test_eta_is_a_lower_bound_while_the_all_column_is_unsampled():
    # Per-server cells are timed but no `all` cell has finished, so the
    # slowest part of the sweep is unmeasured. Flag it instead of pretending.
    r = _timed({
        "m1::defender": {"status": "ok", "elapsed_s": 100.0},
        "m1::entra": {"status": "ok", "elapsed_s": 100.0},
        "m2::defender": {"status": "ok", "elapsed_s": 100.0},
    })
    e = dash.eta(r)
    assert e["status"] == "partial"
    assert e["mean_all"] is None
    assert e["seconds"] == 3 * 100.0  # only the per-server remainder


def test_eta_counts_failed_cells_as_time_spent():
    # A cell that took nine minutes to fail still consumed nine minutes.
    r = _timed({
        "m1::defender": {"status": "ok", "elapsed_s": 100.0},
        "m1::entra": {"status": "error", "error": "x", "elapsed_s": 500.0},
        "m1::all": {"status": "unusable", "error": "y", "elapsed_s": 900.0},
    })
    e = dash.eta(r)
    assert e["samples"] == 3
    assert e["mean_per_server"] == 300.0


def test_eta_falls_back_to_server_observed_timings():
    # A sweep started before elapsed_s existed carries no timings; the server
    # supplies what it watched itself.
    r = _timed({
        "m1::defender": {"status": "ok"},
        "m1::entra": {"status": "ok"},
        "m1::all": {"status": "ok"},
    })
    e = dash.eta(r, observed={"m1::defender": 100.0, "m1::entra": 100.0,
                              "m1::all": 1000.0})
    assert e["status"] == "ok"
    assert e["seconds"] == 4 * 100.0 + 2 * 1000.0


def test_eta_is_none_when_nothing_remains():
    cells = {f"m{i}::{s}": {"status": "ok", "elapsed_s": 10.0}
             for i in (1, 2, 3) for s in ("defender", "entra", "all")}
    e = dash.eta(_timed(cells))
    assert e["seconds"] == 0.0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest scripts/tests/test_eval_dashboard.py -k eta -v`
Expected: FAIL — `AttributeError: module 'eval_dashboard' has no attribute 'eta'`.

- [ ] **Step 3: Implement**

Append to `scripts/eval_dashboard.py`:

```python
MIN_ETA_SAMPLES = 3
_ALL = "all"


def _mean(values: list[float]) -> float | None:
    return sum(values) / len(values) if values else None


def eta(
    results: dict[str, Any], observed: dict[str, float] | None = None
) -> dict[str, Any]:
    """Projected seconds remaining, weighted by column.

    The `all` column registers every tool at once — a ~32KB schema prefix on
    each call, measured 4-15x slower than a single server's. Pooling both into
    one mean under-estimates a sweep badly, since the `all` cells dominate
    whatever is left. So: two means, projected against their own remainders.

    `observed` carries timings the server measured itself, for a sweep that
    began before cells recorded their own duration.
    """
    observed = observed or {}
    models = results.get("models") or []
    servers = results.get("servers") or []
    cells = results.get("cells") or {}

    per_server_times: list[float] = []
    all_times: list[float] = []
    for key, cell in cells.items():
        secs = cell.get("elapsed_s")
        if secs is None:
            secs = observed.get(key)
        if secs is None:
            continue
        bucket = all_times if key.rsplit("::", 1)[-1] == _ALL else per_server_times
        bucket.append(float(secs))

    remaining_all = 0
    remaining_per_server = 0
    for m in models:
        for s in servers:
            if _cell_key(m["tag"], s) in cells:
                continue
            if s == _ALL:
                remaining_all += 1
            else:
                remaining_per_server += 1

    samples = len(per_server_times) + len(all_times)
    mean_ps = _mean(per_server_times)
    mean_all = _mean(all_times)
    out = {
        "samples": samples,
        "mean_per_server": mean_ps,
        "mean_all": mean_all,
        "remaining_per_server": remaining_per_server,
        "remaining_all": remaining_all,
    }
    if samples < MIN_ETA_SAMPLES:
        return {**out, "status": "establishing", "seconds": None}

    seconds = (mean_ps or 0.0) * remaining_per_server + (mean_all or 0.0) * remaining_all
    # `all` cells remain but none has been timed: the slowest part of the sweep
    # is unmeasured, so this is a floor, not an estimate.
    status = "partial" if (remaining_all and mean_all is None) else "ok"
    return {**out, "status": status, "seconds": round(seconds, 1)}
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest scripts/tests/test_eval_dashboard.py -v`
Expected: PASS (14 tests).

- [ ] **Step 5: Commit**

```bash
git add scripts/eval_dashboard.py scripts/tests/test_eval_dashboard.py
git commit -m "feat(evals): column-weighted ETA for the dashboard"
```

---

### Task 4: Roster-aware historical trend

**Files:**
- Modify: `scripts/eval_dashboard.py`
- Test: `scripts/tests/test_eval_dashboard.py`

**Interfaces:**
- Consumes: `load_results`, `_AGENTIC_PREFIX`.
- Produces: `trend(results_dir: Path) -> dict` returning
  `{"runs": [{"date": str, "servers": [str]}], "models": {display: [point, ...]}}`
  where a point is `{"date": str, "args_rate": float|None, "servers": [str], "roster_differs": bool}` and `args_rate is None` means the model was absent from that run (render as a gap, never interpolate).

- [ ] **Step 1: Write the failing tests**

Append to `scripts/tests/test_eval_dashboard.py`:

```python
def _write_run(d: Path, date: str, models, servers, rate):
    cells = {f"{m}::{s}": {"status": "ok", "tool_rate": rate, "args_rate": rate}
             for m in models for s in servers}
    (d / f"{date}.json").write_text(json.dumps({
        "date": date,
        "models": [{"tag": m, "display": m.upper()} for m in models],
        "servers": servers,
        "cells": cells,
    }))


def test_trend_renders_a_gap_for_a_model_absent_from_a_run(tmp_path):
    # Rosters really do differ: 2026-07-13 included Qwen3 4B and covered six
    # servers; the current run drops it and covers eight plus `all`. A missing
    # model must be a GAP, never a line interpolated across it.
    _write_run(tmp_path, "2026-01-01", ["m1", "m2"], ["defender"], 0.9)
    _write_run(tmp_path, "2026-01-02", ["m1"], ["defender"], 1.0)
    t = dash.trend(tmp_path)
    m2 = t["models"]["M2"]
    assert [p["args_rate"] for p in m2] == [0.9, None]


def test_trend_marks_points_whose_roster_differs_from_the_latest(tmp_path):
    _write_run(tmp_path, "2026-01-01", ["m1"], ["defender"], 0.9)
    _write_run(tmp_path, "2026-01-02", ["m1"], ["defender", "entra"], 1.0)
    t = dash.trend(tmp_path)
    pts = t["models"]["M1"]
    assert pts[0]["roster_differs"] is True    # 1 server vs the latest 2
    assert pts[1]["roster_differs"] is False
    assert pts[0]["servers"] == ["defender"]


def test_trend_averages_only_ok_cells(tmp_path):
    _write_run(tmp_path, "2026-01-01", ["m1"], ["defender", "entra"], 1.0)
    p = tmp_path / "2026-01-01.json"
    data = json.loads(p.read_text())
    data["cells"]["m1::entra"] = {"status": "error", "error": "x"}
    p.write_text(json.dumps(data))
    # A broken cell is not a zero — averaging it in would invent a decline.
    assert dash.trend(tmp_path)["models"]["M1"][0]["args_rate"] == 1.0


def test_trend_skips_agentic_and_malformed_files(tmp_path):
    _write_run(tmp_path, "2026-01-01", ["m1"], ["defender"], 1.0)
    (tmp_path / "agentic-2026-01-01.json").write_text('{"different": "schema"}')
    (tmp_path / "2026-01-09.json").write_text("{ broken")
    t = dash.trend(tmp_path)
    assert [r["date"] for r in t["runs"]] == ["2026-01-01"]


def test_trend_is_empty_for_an_empty_dir(tmp_path):
    assert dash.trend(tmp_path) == {"runs": [], "models": {}}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest scripts/tests/test_eval_dashboard.py -k trend -v`
Expected: FAIL — `AttributeError: module 'eval_dashboard' has no attribute 'trend'`.

- [ ] **Step 3: Implement**

Append to `scripts/eval_dashboard.py`:

```python
def trend(results_dir: Path) -> dict[str, Any]:
    """Per-model mean args_rate across every matrix run on disk.

    Rosters differ between runs (2026-07-13 covered six servers and included
    Qwen3 4B; the current run covers eight plus `all` and drops it). A trend
    line that silently averages different task sets is worse than none, so a
    model absent from a run yields a GAP and every point carries the roster it
    was computed over.
    """
    runs: list[dict[str, Any]] = []
    for path in sorted(results_dir.glob("*.json")):
        if path.name.startswith(_AGENTIC_PREFIX):
            continue
        try:
            data = load_results(path)
        except ValueError:
            continue  # a half-written or foreign file is skipped, not fatal
        if not data.get("models") or not data.get("servers"):
            continue
        runs.append(data)

    if not runs:
        return {"runs": [], "models": {}}

    latest_roster = set(runs[-1].get("servers") or [])
    names: list[str] = []
    for data in runs:
        for m in data["models"]:
            display = m.get("display", m["tag"])
            if display not in names:
                names.append(display)

    models: dict[str, list[dict[str, Any]]] = {n: [] for n in names}
    for data in runs:
        servers = data.get("servers") or []
        cells = data.get("cells") or {}
        differs = set(servers) != latest_roster
        present = {m.get("display", m["tag"]): m["tag"] for m in data["models"]}
        for name in names:
            tag = present.get(name)
            rate = None
            if tag is not None:
                # Only `ok` cells: a broken cell is not a zero, and averaging
                # one in would invent a decline that never happened.
                rates = [
                    c["args_rate"]
                    for s in servers
                    if (c := cells.get(_cell_key(tag, s))) is not None
                    and c.get("status") == "ok"
                    and c.get("args_rate") is not None
                ]
                rate = _mean(rates)
            models[name].append({
                "date": data.get("date", ""),
                "args_rate": rate,
                "servers": servers,
                "roster_differs": differs,
            })
    return {
        "runs": [{"date": d.get("date", ""), "servers": d.get("servers") or []}
                 for d in runs],
        "models": models,
    }
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest scripts/tests/test_eval_dashboard.py -v`
Expected: PASS (19 tests).

- [ ] **Step 5: Commit**

```bash
git add scripts/eval_dashboard.py scripts/tests/test_eval_dashboard.py
git commit -m "feat(evals): roster-aware trend across scorecard runs"
```

---

### Task 5: HTTP server with no URL-to-path mapping

**Files:**
- Modify: `scripts/eval_dashboard.py`
- Test: `scripts/tests/test_eval_dashboard.py`

**Interfaces:**
- Consumes: `progress`, `matrix`, `eta`, `trend`, `latest_results_path`, `load_results`, `RESULTS_DIR`, `PAGE`.
- Produces:
  - `API_ROUTES: dict[str, str]` — exact URL paths to handler names. `/api/progress`, `/api/matrix`, `/api/trend`.
  - `route(path: str) -> str | None` — returns a route name for an exact match, else `None`. **No filesystem path is ever derived from `path`.**
  - `build_payload(name: str, results_dir: Path, observed: dict[str, float]) -> tuple[int, dict]`
  - `serve(port: int, host: str = "127.0.0.1") -> None`
  - `HOST = "127.0.0.1"`

- [ ] **Step 1: Write the failing tests**

Append to `scripts/tests/test_eval_dashboard.py`:

```python
# --- security: these are non-negotiable -------------------------------------

@pytest.mark.parametrize("path", [
    "/.env.defender",
    "/../.env.defender",
    "/%2e%2e%2f.env.entra",
    "/../../etc/passwd",
    "/evals/results/2026-07-28.json",
    "/scripts/eval_dashboard.py",
    "/static/../../.env.defender",
])
def test_no_url_reaches_the_filesystem(path):
    # Serving this repo with `python -m http.server` would expose
    # .env.defender over HTTP. This server maps NO url to a path: routing is
    # an exact-match dict, so traversal is impossible by construction.
    assert dash.route(path) is None


def test_only_the_three_api_routes_and_root_resolve():
    assert dash.route("/") == "page"
    assert dash.route("/api/progress") == "progress"
    assert dash.route("/api/matrix") == "matrix"
    assert dash.route("/api/trend") == "trend"
    assert dash.route("/api/progress/") is None      # exact match only
    assert dash.route("/api/PROGRESS") is None
    assert dash.route("/api") is None


def test_server_binds_loopback_only():
    # 0.0.0.0 would expose the dashboard to the network.
    assert dash.HOST == "127.0.0.1"


# --- payloads ---------------------------------------------------------------

def test_build_payload_reports_when_no_run_exists(tmp_path):
    status, body = dash.build_payload("progress", tmp_path, {})
    assert status == 200
    assert body["error"] == "no results found"
    assert body["total"] == 0


def test_build_payload_survives_a_half_written_file(tmp_path):
    # run_matrix rewrites the whole file each cell; a poll can land mid-write.
    (tmp_path / "2026-01-01.json").write_text('{"cells": {"a": ')
    status, body = dash.build_payload("progress", tmp_path, {})
    assert status == 200
    assert body["stale"] is True


def test_build_payload_progress_includes_eta(tmp_path):
    _write_run(tmp_path, "2026-01-01", ["m1", "m2"], ["defender", "all"], 1.0)
    p = tmp_path / "2026-01-01.json"
    data = json.loads(p.read_text())
    del data["cells"]["m2::all"]
    del data["cells"]["m2::defender"]
    for k in data["cells"]:
        data["cells"][k]["elapsed_s"] = 100.0
    p.write_text(json.dumps(data))
    status, body = dash.build_payload("progress", tmp_path, {})
    assert status == 200
    assert body["done"] == 2
    assert "eta" in body and body["eta"]["samples"] == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest scripts/tests/test_eval_dashboard.py -k "route or payload or loopback" -v`
Expected: FAIL — `AttributeError: module 'eval_dashboard' has no attribute 'route'`.

- [ ] **Step 3: Implement**

Append to `scripts/eval_dashboard.py`:

```python
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"  # never 0.0.0.0 — this must not be reachable off-box
DEFAULT_PORT = 8765

# Exact-match routing. There is deliberately no directory handler and no
# url->path mapping anywhere in this file: `.env.defender` and friends live in
# this repo, and a traversal bug would hand them out over HTTP. A url that is
# not one of these four keys does not resolve to anything at all.
_ROUTES = {
    "/": "page",
    "/api/progress": "progress",
    "/api/matrix": "matrix",
    "/api/trend": "trend",
}


def route(path: str) -> str | None:
    """Exact-match only. Returns None for anything unrecognised."""
    return _ROUTES.get(path)


def build_payload(
    name: str, results_dir: Path, observed: dict[str, float]
) -> tuple[int, dict[str, Any]]:
    """Shape one API response. Never raises for a bad/absent results file."""
    if name == "trend":
        return 200, trend(results_dir)

    path = latest_results_path(results_dir)
    if path is None:
        empty = {"error": "no results found", "total": 0, "done": 0, "pending": 0,
                 "ok": 0, "failed": [], "current": None, "stale": False}
        return 200, empty if name == "progress" else {"servers": [], "rows": [],
                                                      "error": "no results found"}
    try:
        results = load_results(path)
    except ValueError:
        # Half-written file: report staleness, let the page keep its last good
        # state. A dashboard that blanks during a long run trains distrust.
        return 200, {"stale": True, "total": 0, "done": 0, "pending": 0, "ok": 0,
                     "failed": [], "current": None}

    if name == "matrix":
        return 200, {**matrix(results), "stale": False}
    return 200, {**progress(results), "eta": eta(results, observed), "stale": False}


class _Handler(BaseHTTPRequestHandler):
    results_dir = RESULTS_DIR
    observed: dict[str, float] = {}

    def do_GET(self) -> None:  # noqa: N802 - stdlib API
        name = route(self.path)
        if name is None:
            self.send_error(404, "not found")
            return
        if name == "page":
            self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
            return
        status, body = build_payload(name, self.results_dir, self.observed)
        self._send(status, json.dumps(body).encode(), "application/json")

    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        pass  # a poll every 5s would drown the console


def serve(port: int = DEFAULT_PORT, host: str = HOST) -> None:
    httpd = ThreadingHTTPServer((host, port), _Handler)
    print(f"eval dashboard: http://{host}:{port}  (ctrl-c to stop)")
    print(f"reading {RESULTS_DIR} — read-only, safe to run during a sweep")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    serve(p.parse_args().port)


if __name__ == "__main__":
    main()
```

Move `import argparse` and the `http.server` import up to the module's import block (ruff enforces top-of-file imports and sorting).

- [ ] **Step 4: Run tests**

Run: `uv run pytest scripts/tests/test_eval_dashboard.py -v && uv run ruff check scripts/`
Expected: PASS (29 tests), ruff clean.

- [ ] **Step 5: Commit**

```bash
git add scripts/eval_dashboard.py scripts/tests/test_eval_dashboard.py
git commit -m "feat(evals): dashboard HTTP server with no url-to-path mapping"
```

---

### Task 6: The page, plus docs

**Files:**
- Create: `scripts/dashboard/index.html`
- Modify: `evals/README.md`
- Test: `scripts/tests/test_eval_dashboard.py`

**Interfaces:**
- Consumes: `/api/progress`, `/api/matrix`, `/api/trend` as shaped in Tasks 2–5.
- Produces: nothing other tasks depend on.

- [ ] **Step 1: Write the failing test**

Append to `scripts/tests/test_eval_dashboard.py`:

```python
def test_page_exists_and_is_self_contained():
    html = dash.PAGE.read_text(encoding="utf-8")
    # No CDN, no external anything: the repo ships local-only by policy and the
    # page must render with the network unplugged.
    for forbidden in ("http://", "https://", "//cdn", "integrity="):
        assert forbidden not in html, f"page must not reference {forbidden!r}"
    # It polls the three endpoints the server actually exposes.
    for endpoint in ("/api/progress", "/api/matrix", "/api/trend"):
        assert endpoint in html
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest scripts/tests/test_eval_dashboard.py -k self_contained -v`
Expected: FAIL — `FileNotFoundError` for `scripts/dashboard/index.html`.

- [ ] **Step 3: Implement**

Create `scripts/dashboard/index.html`:

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>f0_sectools — eval scorecard</title>
<style>
  :root {
    --bg:#0f1115; --panel:#171a21; --line:#262b36; --fg:#e6e9ef; --dim:#8b93a7;
    --ok:#3fb950; --mid:#d29922; --bad:#f85149; --pend:#20242e; --accent:#58a6ff;
  }
  @media (prefers-color-scheme: light) {
    :root { --bg:#f6f7f9; --panel:#fff; --line:#e2e5ea; --fg:#1a1d23; --dim:#5c6370;
            --pend:#eceef2; }
  }
  * { box-sizing:border-box; }
  body { margin:0; padding:24px; background:var(--bg); color:var(--fg);
         font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif; }
  h1 { font-size:18px; margin:0 0 4px; }
  .sub { color:var(--dim); font-size:13px; margin-bottom:20px; }
  .panel { background:var(--panel); border:1px solid var(--line); border-radius:10px;
           padding:16px; margin-bottom:16px; }
  .stats { display:flex; flex-wrap:wrap; gap:28px; }
  .stat .v { font-size:22px; font-weight:600; font-variant-numeric:tabular-nums; }
  .stat .k { color:var(--dim); font-size:12px; text-transform:uppercase;
             letter-spacing:.04em; }
  .bar { height:6px; background:var(--pend); border-radius:3px; overflow:hidden;
         margin-top:14px; }
  .bar > i { display:block; height:100%; background:var(--accent); transition:width .4s; }
  .alert { border-left:3px solid var(--bad); background:rgba(248,81,73,.08);
           padding:10px 12px; border-radius:6px; margin-top:14px; }
  .alert b { color:var(--bad); }
  .alert div { color:var(--dim); font-size:12px; margin-top:4px;
               font-family:ui-monospace,monospace; }
  .scroll { overflow-x:auto; }
  table { border-collapse:collapse; width:100%; min-width:760px; }
  th,td { padding:7px 9px; text-align:center; border-bottom:1px solid var(--line);
          font-variant-numeric:tabular-nums; }
  th { color:var(--dim); font-weight:500; font-size:12px; text-align:center; }
  th:first-child, td:first-child { text-align:left; white-space:nowrap; }
  td.cell { cursor:pointer; border-radius:4px; font-size:12px; }
  td.pending { color:var(--dim); background:var(--pend); }
  td.broken { background:rgba(248,81,73,.18); color:var(--bad); font-weight:600; }
  .spark { display:flex; align-items:flex-end; gap:3px; height:34px; }
  .spark i { width:12px; background:var(--accent); border-radius:2px 2px 0 0; }
  .spark i.gap { background:repeating-linear-gradient(45deg,var(--pend),
                 var(--pend) 3px,transparent 3px,transparent 6px); height:100% !important; }
  .spark i.differs { background:var(--mid); }
  .trend-row { display:flex; align-items:center; gap:14px; margin-bottom:8px; }
  .trend-row .name { width:130px; color:var(--dim); font-size:12px; }
  .stale { color:var(--mid); }
</style>
</head>
<body>
<h1>Small-model tool-calling scorecard</h1>
<div class="sub" id="sub">loading…</div>

<div class="panel">
  <div class="stats">
    <div class="stat"><div class="v" id="s-done">–</div><div class="k">cells done</div></div>
    <div class="stat"><div class="v" id="s-ok">–</div><div class="k">ok</div></div>
    <div class="stat"><div class="v" id="s-fail">–</div><div class="k">failed</div></div>
    <div class="stat"><div class="v" id="s-cur">–</div><div class="k">running now</div></div>
    <div class="stat"><div class="v" id="s-eta">–</div><div class="k">est. remaining</div></div>
  </div>
  <div class="bar"><i id="bar" style="width:0"></i></div>
  <div id="alerts"></div>
</div>

<div class="panel scroll"><table id="matrix"></table></div>

<div class="panel">
  <div class="k" style="color:var(--dim);font-size:12px;margin-bottom:10px">
    mean argument-filling per run · striped = model absent · amber = different roster
  </div>
  <div id="trend"></div>
</div>

<script>
const fmtPct = v => v === null || v === undefined ? "–" : Math.round(v * 100) + "%";
function fmtDur(s) {
  if (s === null || s === undefined) return "–";
  if (s < 60) return Math.round(s) + "s";
  const h = Math.floor(s / 3600), m = Math.round((s % 3600) / 60);
  return h ? `${h}h ${m}m` : `${m}m`;
}
function scoreColor(v) {
  if (v === null || v === undefined) return "";
  const hue = 4 + v * 130;                 // red -> green
  return `background:hsla(${hue},62%,45%,${0.18 + v * 0.30})`;
}

async function get(url) {
  const r = await fetch(url, {cache: "no-store"});
  if (!r.ok) throw new Error(url + " -> " + r.status);
  return r.json();
}

function renderProgress(p) {
  document.getElementById("s-done").textContent = `${p.done}/${p.total}`;
  document.getElementById("s-ok").textContent = p.ok ?? "–";
  document.getElementById("s-fail").textContent = (p.failed || []).length;
  document.getElementById("s-cur").textContent =
    p.current ? p.current.replace("::", " · ") : (p.total ? "complete" : "–");
  const e = p.eta || {};
  document.getElementById("s-eta").textContent =
    e.status === "establishing" ? "establishing…"
    : e.status === "partial" ? "> " + fmtDur(e.seconds)
    : fmtDur(e.seconds);
  document.getElementById("bar").style.width =
    (p.total ? (p.done / p.total) * 100 : 0) + "%";
  document.getElementById("sub").innerHTML =
    (p.error ? p.error : `run ${p.date ?? "?"} · runs/task ${p.runs ?? "?"}`)
    + (p.stale ? ' · <span class="stale">stale read</span>' : "");

  document.getElementById("alerts").innerHTML = (p.failed || []).map(f =>
    `<div class="alert"><b>${f.status}</b> — ${f.key}<div>${f.error || ""}</div></div>`
  ).join("");
}

function renderMatrix(m) {
  const head = "<tr><th>Model</th>" +
    (m.servers || []).map(s => `<th>${s}</th>`).join("") + "</tr>";
  const rows = (m.rows || []).map(r => "<tr><td>" + r.display + "</td>" +
    r.cells.map(c => {
      if (c.status === "pending")
        return `<td class="cell pending" title="not run yet">·</td>`;
      if (c.status !== "ok")
        return `<td class="cell broken" title="${(c.error||"").replace(/"/g,"&quot;")}">${c.status === "unusable" ? "ctx!" : "err"}</td>`;
      return `<td class="cell" style="${scoreColor(c.args_rate)}" ` +
             `title="tool ${fmtPct(c.tool_rate)} · args ${fmtPct(c.args_rate)}">` +
             `${fmtPct(c.tool_rate)}/${fmtPct(c.args_rate)}</td>`;
    }).join("") + "</tr>").join("");
  document.getElementById("matrix").innerHTML = head + rows;
}

function renderTrend(t) {
  const names = Object.keys(t.models || {});
  document.getElementById("trend").innerHTML = names.map(n => {
    const bars = t.models[n].map(p => {
      if (p.args_rate === null)
        return `<i class="gap" title="${p.date}: model not in this run"></i>`;
      const cls = p.roster_differs ? "differs" : "";
      const title = `${p.date}: ${fmtPct(p.args_rate)} over ${p.servers.length} server(s)` +
                    (p.roster_differs ? " — different roster" : "");
      return `<i class="${cls}" style="height:${Math.max(4, p.args_rate*34)}px" title="${title}"></i>`;
    }).join("");
    return `<div class="trend-row"><div class="name">${n}</div>
            <div class="spark">${bars}</div></div>`;
  }).join("");
}

async function tick() {
  try {
    const [p, m] = await Promise.all([get("/api/progress"), get("/api/matrix")]);
    renderProgress(p); renderMatrix(m);
  } catch (err) {
    // Keep the last good render: a page that blanks on one failed poll
    // during an 18h run teaches you to stop trusting it.
    document.getElementById("sub").innerHTML =
      '<span class="stale">poll failed — showing last good state</span>';
  }
}

get("/api/trend").then(renderTrend).catch(() => {});
tick();
setInterval(tick, 5000);
setInterval(() => get("/api/trend").then(renderTrend).catch(() => {}), 60000);
</script>
</body>
</html>
```

- [ ] **Step 4: Run the test and check the page by eye**

Run: `uv run pytest scripts/tests/test_eval_dashboard.py -v`
Expected: PASS (30 tests).

Then start it and look at it:

```bash
uv run python scripts/eval_dashboard.py
```

Open `http://127.0.0.1:8765`. Verify: cell counts match `jq '.cells|length' evals/results/*.json`, pending cells are visibly empty, and the ETA shows `establishing…` or a duration. Ctrl-C to stop.

- [ ] **Step 5: Document it**

Append to `evals/README.md`:

```markdown
## Watching a sweep (dashboard)

A full matrix at `runs=3` takes 12–18 hours, and `SCORECARD.md` is only written
at the end. To watch it live:

```bash
uv run python scripts/eval_dashboard.py     # http://127.0.0.1:8765
```

Read-only and safe to start, stop, or restart mid-sweep — it only reads
`evals/results/*.json`, which `run_matrix` rewrites after every cell.

It shows progress with a column-weighted ETA (the `all` column is several times
slower per cell, so a single pooled mean under-estimates badly), the matrix as a
heatmap that fills in live, and each model's trend across past runs. Any
`error`/`unusable` cell is raised as an alert — `unusable` means the model made
no tool call at all on a whole task set, which is a serving problem (context too
small for the schema), not a capability result.

> **Never** serve this repo with `python -m http.server` — it would expose
> `.env.defender` and every other credential file over HTTP. The dashboard maps
> no URL to a filesystem path and binds `127.0.0.1` only.
```

- [ ] **Step 6: Full gates and commit**

```bash
uv run pytest -q && uv run ruff check . && uv run mypy .
git add scripts/dashboard/index.html scripts/tests/test_eval_dashboard.py evals/README.md
git commit -m "feat(evals): local live dashboard page and docs"
```

---

## Self-review

**Spec coverage.** Every spec section maps to a task: security allow-list → Task 5 (strengthened to no-url-mapping); ETA two-means + `establishing` → Task 3; `elapsed_s` → Task 1; progress/alerts → Tasks 2 and 6; heatmap with pending distinct from broken → Tasks 2 and 6; roster-aware trend with gaps → Task 4; half-written JSON → Tasks 2 and 5; `scripts/` home and stdlib-only → throughout; out-of-scope items (publish, delta, sweep control, auth) appear nowhere.

**Placeholders.** None — every step carries the code or command it needs.

**Type consistency.** `_cell_key` (Task 2) is used by Tasks 3 and 4. `_mean` (Task 3) is used by Task 4. `MIN_ETA_SAMPLES`, `HOST`, `_ROUTES`, `PAGE`, `RESULTS_DIR`, `_AGENTIC_PREFIX` are each defined once and referenced consistently. The `eta()` return keys asserted in Task 3's tests match those read by the page in Task 6 (`status`, `seconds`, `samples`). `progress()` keys asserted in Task 2 match what Task 5 wraps and Task 6 renders.

**One deviation from the spec, deliberate:** the spec described an allow-list with path resolution and traversal tests. Task 5 goes further — no URL is ever mapped to a filesystem path, so traversal cannot occur rather than being caught. The traversal tests remain, now asserting `route()` returns `None`.
