# Dashboard Explanatory Detail Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the scorecard legible — a newcomer understands what is measured; a contributor clicks a cell and sees which task failed and what the model called instead.

**Architecture:** `run_matrix` stops discarding the per-task rows `run_suite` already computes. The dashboard gains two endpoints — one for a single cell's detail, one for the task inventory read from YAML — and the page gains a narrative header, per-server cards, and a drill-down panel. Detail comes from two independent sources: YAML (works retroactively) and persisted rows (works from this change onward).

**Tech Stack:** Python 3.11 stdlib + PyYAML (already a project dependency, used by `evals/scorecard.py`). Vanilla HTML/CSS/JS, no framework, no CDN.

## Global Constraints

- **Read-only observer.** No writes to `evals/`, no process control, no locks.
- **Bind `127.0.0.1` only** — never `0.0.0.0`.
- **No URL is ever joined to a filesystem path.** This is the dashboard's core security property. See the traversal note below — it applies to the new query parameters too.
- **The dashboard must not import server packages.** `scripts/eval_dashboard.py` imports nothing from `evals/` or `servers/` today; keep it that way. Tool counts come from persisted data, never from importing a server to count its tools.
- **Poll payloads stay small.** `/api/matrix` keeps returning summary only. Per-task detail is fetched on demand for one cell.
- **Backward compatible.** Results files written before this change lack per-task rows; every view must degrade, never error.
- **Tests live in `scripts/tests/`** and load the script via `importlib.util.spec_from_file_location` (`scripts/` is not a package).
- `scripts/` is excluded from strict mypy (`pyproject.toml:66-72`).
- Cell keys are `f"{model_tag}::{server}"`; parse with `key.rsplit("::", 1)`.

### The traversal rule for query parameters

`/api/cell?server=X` must never become `EVALS / X / "tasks.yaml"`. The server list is built **once, by globbing `evals/*/tasks.yaml`** — a path never derived from input — into a dict keyed by directory name. A query parameter is then only ever a **dict key**. `?server=../../.env.defender` returns "not found" because no such key exists, not because a check rejected it.

---

### Task 1: Persist the per-task rows `run_suite` already computes

**Files:**
- Modify: `evals/scorecard.py` (the `run_matrix` ok-branch)
- Test: `evals/test_scorecard.py`

**Interfaces:**
- Produces: an `ok` cell gains `"tasks": list[dict]`, `"schema_kb": float`, `"tool_count": int`, `"no_call_rate": float`. Each task row is `{"prompt", "expect_tool", "tool_rate", "args_rate", "runs", "calls"}` exactly as `run_suite` returns it. Cells from earlier runs lack these keys; every consumer must treat them as optional.

- [ ] **Step 1: Write the failing test**

Add to `evals/test_scorecard.py`:

```python
@pytest.mark.asyncio
async def test_run_matrix_persists_per_task_detail(tmp_path):
    # run_suite already computes per-task rows including `calls` — the ordered
    # tool names the model actually chose, which NAMES a misroute. Discarding
    # them meant every "which task failed?" question needed a fresh GPU run.
    out = tmp_path / "r.json"
    await run_matrix(
        models=[{"tag": "m1", "display": "M1"}],
        servers=["defender"],
        base_url="http://x/v1",
        runs=2,
        out_path=out,
        date="2026-01-01",
        client_factory=_fake_factory("get_secure_score"),
    )
    cell = json.loads(out.read_text())["cells"]["m1::defender"]
    assert cell["tool_count"] > 0
    assert cell["schema_kb"] > 0
    assert cell["no_call_rate"] == 0.0
    rows = cell["tasks"]
    assert len(rows) == len(yaml.safe_load(Path("evals/defender/tasks.yaml").read_text()))
    first = rows[0]
    assert set(first) >= {"prompt", "expect_tool", "tool_rate", "args_rate", "runs", "calls"}
    assert first["runs"] == 2
    assert len(first["calls"]) == 2          # one entry per run — names the misroute
```

Add `import yaml` and `from pathlib import Path` to the test file's imports if not already present (`json` and `pytest` already are).

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest evals/test_scorecard.py::test_run_matrix_persists_per_task_detail -v`
Expected: FAIL — `KeyError: 'tool_count'`.

- [ ] **Step 3: Implement**

In `evals/scorecard.py`, in `run_matrix`, replace the ok-branch cell assignment:

```python
                results["cells"][key] = {
                    "status": "ok",
                    "tool_rate": rep["overall_tool_rate"],
                    "args_rate": rep["overall_args_rate"],
                    # Kept, not discarded: `tasks` carries each prompt's own rate
                    # and `calls` — the tools the model actually chose, which is
                    # what names a misroute. Recomputing this later costs a GPU
                    # run; storing it costs ~4KB a cell.
                    "tasks": rep["tasks"],
                    "schema_kb": rep["schema_kb"],
                    "tool_count": rep["tool_count"],
                    "no_call_rate": rep["no_call_rate"],
                }
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest evals/ -q && uv run ruff check evals/`
Expected: PASS, ruff clean. The pre-existing resume/persistence tests must still pass.

- [ ] **Step 5: Commit**

```bash
git add evals/scorecard.py evals/test_scorecard.py
git commit -m "feat(evals): persist per-task detail with each scorecard cell"
```

---

### Task 2: Task inventory from YAML, and `/api/servers`

**Files:**
- Modify: `scripts/eval_dashboard.py`
- Test: `scripts/tests/test_eval_dashboard.py`

**Interfaces:**
- Consumes: `RESULTS_DIR`, `load_results`, `latest_results_path` (existing).
- Produces:
  - `TASKS_DIR: Path` — `<repo>/evals`
  - `task_inventory(evals_dir: Path) -> dict[str, list[dict]]` — `{server: [{"prompt", "expect_tool", "expect_args"}]}`, built by globbing `*/tasks.yaml`. **The keys come from the glob, never from input.**
  - `servers_view(evals_dir: Path, results: dict) -> dict` — `{"servers": [{"server", "task_count", "tool_count", "schema_kb", "example"}]}` where `tool_count`/`schema_kb` are `None` when no cell recorded them, and `example` is the first task of that server.

- [ ] **Step 1: Write the failing tests**

Append to `scripts/tests/test_eval_dashboard.py`:

```python
def _write_tasks(d, server, tasks):
    (d / server).mkdir(parents=True, exist_ok=True)
    import yaml
    (d / server / "tasks.yaml").write_text(yaml.safe_dump(tasks))


def test_task_inventory_keys_come_from_the_glob_not_from_input(tmp_path):
    # The inventory is built by globbing the evals dir. A query parameter can
    # then only ever be a dict KEY — it is never joined to a path, so
    # ?server=../../.env.defender simply misses.
    _write_tasks(tmp_path, "defender", [{"prompt": "p1", "expect_tool": "list_incidents"}])
    _write_tasks(tmp_path, "tenable", [{"prompt": "p2", "expect_tool": "list_assets"}])
    inv = dash.task_inventory(tmp_path)
    assert sorted(inv) == ["defender", "tenable"]
    assert inv["defender"][0]["prompt"] == "p1"
    assert "../../.env.defender" not in inv


def test_task_inventory_skips_a_malformed_task_file(tmp_path):
    _write_tasks(tmp_path, "defender", [{"prompt": "p1", "expect_tool": "t"}])
    (tmp_path / "broken").mkdir()
    (tmp_path / "broken" / "tasks.yaml").write_text("{ not: valid: yaml:")
    inv = dash.task_inventory(tmp_path)
    assert "defender" in inv and "broken" not in inv


def test_servers_view_reports_counts_and_an_example(tmp_path):
    _write_tasks(tmp_path, "defender", [
        {"prompt": "List the active high-severity incidents.",
         "expect_tool": "list_incidents", "expect_args": {"severity_min": "high"}},
        {"prompt": "another", "expect_tool": "list_alerts"},
    ])
    results = {"cells": {"m1::defender": {"status": "ok", "tool_count": 7,
                                          "schema_kb": 6.2}}}
    v = dash.servers_view(tmp_path, results)
    row = next(r for r in v["servers"] if r["server"] == "defender")
    assert row["task_count"] == 2
    assert row["tool_count"] == 7 and row["schema_kb"] == 6.2
    assert row["example"]["expect_tool"] == "list_incidents"
    assert row["example"]["expect_args"] == {"severity_min": "high"}


def test_servers_view_leaves_tool_count_unknown_for_an_unrun_server(tmp_path):
    # A server with tasks but no recorded cell: say the count is unknown rather
    # than importing the server package to compute it.
    _write_tasks(tmp_path, "purview", [{"prompt": "p", "expect_tool": "t"}])
    v = dash.servers_view(tmp_path, {"cells": {}})
    row = next(r for r in v["servers"] if r["server"] == "purview")
    assert row["task_count"] == 1
    assert row["tool_count"] is None and row["schema_kb"] is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest scripts/tests/test_eval_dashboard.py -k "inventory or servers_view" -v`
Expected: FAIL — `AttributeError: module 'eval_dashboard' has no attribute 'task_inventory'`.

- [ ] **Step 3: Implement**

Add `import yaml` to the imports in `scripts/eval_dashboard.py` (after `import time`; PyYAML is already a project dependency via `evals/scorecard.py`). Add `TASKS_DIR = ROOT / "evals"` beside `RESULTS_DIR`, then append:

```python
def task_inventory(evals_dir: Path) -> dict[str, list[dict[str, Any]]]:
    """Every server's task set, keyed by directory name.

    Keys come from globbing the evals directory — never from a request. That is
    what lets a query parameter be a dict key rather than a path component, so
    `?server=../../.env.defender` misses instead of traversing.

    Works retroactively: this is the only source of detail for result files
    written before cells carried their own task rows.
    """
    out: dict[str, list[dict[str, Any]]] = {}
    for path in sorted(evals_dir.glob("*/tasks.yaml")):
        try:
            tasks = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError):
            continue  # a malformed task file must not blank the whole page
        if isinstance(tasks, list) and tasks:
            out[path.parent.name] = tasks
    return out


def servers_view(evals_dir: Path, results: dict[str, Any]) -> dict[str, Any]:
    """Per-server cards: how many tasks, how many tools, how big the schema.

    tool_count/schema_kb are read from whichever cell recorded them — never by
    importing the server package. A server with tasks but no cell reports None,
    which the page renders as unknown rather than zero.
    """
    inv = task_inventory(evals_dir)
    measured: dict[str, dict[str, Any]] = {}
    for key, cell in (results.get("cells") or {}).items():
        server = key.rsplit("::", 1)[-1]
        if server not in measured and cell.get("tool_count") is not None:
            measured[server] = cell
    rows = []
    for server, tasks in inv.items():
        cell = measured.get(server, {})
        rows.append({
            "server": server,
            "task_count": len(tasks),
            "tool_count": cell.get("tool_count"),
            "schema_kb": cell.get("schema_kb"),
            "example": tasks[0],
        })
    return {"servers": rows}
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest scripts/tests/test_eval_dashboard.py -q && uv run ruff check scripts/`
Expected: PASS, ruff clean.

- [ ] **Step 5: Commit**

```bash
git add scripts/eval_dashboard.py scripts/tests/test_eval_dashboard.py
git commit -m "feat(evals): dashboard task inventory and per-server view"
```

---

### Task 3: Query-parameter routing and `/api/cell`

**Files:**
- Modify: `scripts/eval_dashboard.py`
- Test: `scripts/tests/test_eval_dashboard.py`

**Interfaces:**
- Consumes: `task_inventory`, `load_results`, `latest_results_path`, `route`, `build_payload`.
- Produces:
  - `route(path: str) -> str | None` now matches the path portion only, ignoring `?query`.
  - `cell_view(evals_dir, results, model, server) -> dict` — `{"found": bool, "model", "server", "status", "tool_rate", "args_rate", "recorded": bool, "tasks": [...]}`. Each task row is `{"prompt", "expect_tool", "expect_args", "tool_rate", "args_rate", "runs", "calls", "recorded"}`, **failures first**. When the cell has no persisted rows, `recorded` is `False` and rates are `None` — the inventory still renders.
  - `build_payload(name, results_dir, observed, params=None)` — gains an optional `params: dict[str, str]`.

- [ ] **Step 1: Write the failing tests**

Append to `scripts/tests/test_eval_dashboard.py`:

```python
def test_route_ignores_the_query_string_but_still_exact_matches_the_path():
    assert dash.route("/api/cell?model=m1&server=defender") == "cell"
    assert dash.route("/api/matrix?anything=1") == "matrix"
    # The path half is still exact-match: a query string does not smuggle a path.
    assert dash.route("/api/cell/extra?model=m1") is None
    assert dash.route("/.env.defender?x=1") is None
    assert dash.route("/../.env.defender?model=m1") is None


def test_cell_view_orders_failures_first_and_names_the_misroute(tmp_path):
    _write_tasks(tmp_path, "defender", [
        {"prompt": "good one", "expect_tool": "list_incidents"},
        {"prompt": "bad one", "expect_tool": "isolate_host"},
    ])
    results = {"cells": {"m1::defender": {
        "status": "ok", "tool_rate": 0.5, "args_rate": 0.5,
        "tasks": [
            {"prompt": "good one", "expect_tool": "list_incidents",
             "tool_rate": 1.0, "args_rate": 1.0, "runs": 2,
             "calls": ["list_incidents", "list_incidents"]},
            {"prompt": "bad one", "expect_tool": "isolate_host",
             "tool_rate": 0.0, "args_rate": 0.0, "runs": 2,
             "calls": ["run_hunting_query", "run_hunting_query"]},
        ]}}}
    v = dash.cell_view(tmp_path, results, "m1", "defender")
    assert v["found"] is True and v["recorded"] is True
    # Failures first — the reason anyone opens this panel.
    assert v["tasks"][0]["prompt"] == "bad one"
    assert v["tasks"][0]["calls"] == ["run_hunting_query", "run_hunting_query"]


def test_cell_view_falls_back_to_inventory_for_a_run_without_task_rows(tmp_path):
    # Cells written before per-task persistence: show WHAT was asked, and be
    # explicit that the outcome was not recorded rather than rendering blank.
    _write_tasks(tmp_path, "defender", [
        {"prompt": "only one", "expect_tool": "list_incidents",
         "expect_args": {"severity_min": "high"}},
    ])
    results = {"cells": {"m1::defender": {"status": "ok", "tool_rate": 1.0,
                                          "args_rate": 1.0}}}
    v = dash.cell_view(tmp_path, results, "m1", "defender")
    assert v["found"] is True
    assert v["recorded"] is False
    assert v["tasks"][0]["prompt"] == "only one"
    assert v["tasks"][0]["tool_rate"] is None
    assert v["tasks"][0]["expect_args"] == {"severity_min": "high"}


def test_cell_view_not_found_for_unknown_model_or_traversal_shaped_server(tmp_path):
    _write_tasks(tmp_path, "defender", [{"prompt": "p", "expect_tool": "t"}])
    results = {"cells": {"m1::defender": {"status": "ok"}}}
    assert dash.cell_view(tmp_path, results, "nope", "defender")["found"] is False
    # The parameter is a dict key. There is no such key, so it misses — no path
    # is ever constructed from it.
    v = dash.cell_view(tmp_path, results, "m1", "../../.env.defender")
    assert v["found"] is False


def test_build_payload_cell_reads_params(tmp_path):
    _write_tasks(tmp_path, "defender", [{"prompt": "p", "expect_tool": "t"}])
    (tmp_path / "2026-01-01.json").write_text(json.dumps(
        {"date": "2026-01-01", "models": [{"tag": "m1", "display": "M1"}],
         "servers": ["defender"],
         "cells": {"m1::defender": {"status": "ok", "tool_rate": 1.0, "args_rate": 1.0}}}))
    status, body = dash.build_payload("cell", tmp_path, {},
                                      {"model": "m1", "server": "defender"})
    assert status == 200 and body["found"] is True
```

Note the results dir and evals dir are the same `tmp_path` in that last test; that is fine because the two readers glob different patterns (`*.json` vs `*/tasks.yaml`).

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest scripts/tests/test_eval_dashboard.py -k "route_ignores or cell_view or payload_cell" -v`
Expected: FAIL — `AttributeError: module 'eval_dashboard' has no attribute 'cell_view'`.

- [ ] **Step 3: Implement**

In `scripts/eval_dashboard.py`, add `"/api/cell": "cell"` and `"/api/servers": "servers"` to `_ROUTES`, then replace `route` and extend `build_payload`:

```python
def route(path: str) -> str | None:
    """Exact-match on the PATH; a query string is ignored, never a path part.

    Splitting here is what lets /api/cell take model/server parameters while
    keeping the property that no url is joined to a filesystem path: the
    parameters are consumed downstream as dict keys only.
    """
    return _ROUTES.get(path.split("?", 1)[0])


def _params(path: str) -> dict[str, str]:
    """Parse a query string into a flat dict. Values are never path components."""
    from urllib.parse import parse_qs, urlsplit

    return {k: v[0] for k, v in parse_qs(urlsplit(path).query).items() if v}


def cell_view(
    evals_dir: Path, results: dict[str, Any], model: str, server: str
) -> dict[str, Any]:
    """One cell, task by task, failures first.

    `model` and `server` are dict keys — into the cells map and the globbed task
    inventory respectively. Neither is ever joined to a path.

    Two sources, deliberately. Persisted rows give outcomes but only exist for
    runs made after cells started carrying them; the YAML inventory gives the
    prompts for every run ever made. A cell without rows still shows WHAT was
    asked, marked unrecorded, rather than an empty panel.
    """
    cell = (results.get("cells") or {}).get(_cell_key(model, server))
    inv = task_inventory(evals_dir).get(server)
    if cell is None or inv is None:
        return {"found": False, "model": model, "server": server}

    rows = cell.get("tasks")
    if rows:
        by_prompt = {t.get("prompt"): t for t in inv}
        tasks = [{
            "prompt": r.get("prompt"),
            "expect_tool": r.get("expect_tool"),
            "expect_args": (by_prompt.get(r.get("prompt")) or {}).get("expect_args"),
            "tool_rate": r.get("tool_rate"),
            "args_rate": r.get("args_rate"),
            "runs": r.get("runs"),
            "calls": r.get("calls") or [],
            "recorded": True,
        } for r in rows]
        # Failures first: the panel exists to answer "why is this cell 86%".
        tasks.sort(key=lambda t: (t["args_rate"] if t["args_rate"] is not None else 1.0,
                                  t["tool_rate"] if t["tool_rate"] is not None else 1.0))
        recorded = True
    else:
        tasks = [{
            "prompt": t.get("prompt"),
            "expect_tool": t.get("expect_tool"),
            "expect_args": t.get("expect_args"),
            "tool_rate": None, "args_rate": None, "runs": None,
            "calls": [], "recorded": False,
        } for t in inv]
        recorded = False

    return {
        "found": True, "model": model, "server": server,
        "status": cell.get("status"),
        "tool_rate": cell.get("tool_rate"), "args_rate": cell.get("args_rate"),
        "schema_kb": cell.get("schema_kb"), "tool_count": cell.get("tool_count"),
        "recorded": recorded, "tasks": tasks,
    }
```

Then extend `build_payload`'s signature and add the two new branches. Change the signature line to:

```python
def build_payload(
    name: str, results_dir: Path, observed: dict[str, float],
    params: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
```

and immediately after the existing `if name == "trend":` block, add:

```python
    if name in ("cell", "servers"):
        path = latest_results_path(results_dir)
        try:
            results = load_results(path) if path else {"cells": {}}
        except ValueError:
            results = {"cells": {}}
        if name == "servers":
            return 200, servers_view(TASKS_DIR, results)
        p = params or {}
        return 200, cell_view(TASKS_DIR, results, p.get("model", ""),
                              p.get("server", ""))
```

Finally, in `_Handler.do_GET`, pass the parsed parameters through:

```python
        observed = self._observed() if name == "progress" else {}
        status, body = build_payload(name, self.results_dir, observed,
                                     _params(self.path))
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest scripts/tests/test_eval_dashboard.py -q && uv run ruff check scripts/`
Expected: PASS — including the pre-existing security suite, which must still show no url resolving to a filesystem path.

- [ ] **Step 5: Commit**

```bash
git add scripts/eval_dashboard.py scripts/tests/test_eval_dashboard.py
git commit -m "feat(evals): per-cell drill-down endpoint with query params"
```

---

### Task 4: The explanatory page — header, server cards, noise band

**Files:**
- Modify: `scripts/dashboard/index.html`
- Test: `scripts/tests/test_eval_dashboard.py`

**Interfaces:**
- Consumes: `/api/servers`, `/api/matrix`, `/api/progress`.
- Produces: nothing other tasks depend on.

- [ ] **Step 1: Write the failing test**

Append to `scripts/tests/test_eval_dashboard.py`:

```python
def test_page_explains_what_is_measured_and_stays_self_contained():
    html = dash.PAGE.read_text(encoding="utf-8")
    for forbidden in ("http://", "https://", "//cdn", "integrity="):
        assert forbidden not in html, f"page must not reference {forbidden!r}"
    for endpoint in ("/api/progress", "/api/matrix", "/api/trend",
                     "/api/servers", "/api/cell"):
        assert endpoint in html
    # The two rates are jargon; the page must define them where they are read.
    assert "tool-selection" in html and "argument-filling" in html
    # And it must state the runs=3 caveat rather than leaving it to a commit log.
    assert "reproduce" in html.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest scripts/tests/test_eval_dashboard.py -k explains -v`
Expected: FAIL — `/api/servers` not found in the page.

- [ ] **Step 3: Implement**

In `scripts/dashboard/index.html`, add these styles inside the existing `<style>` block, before `</style>`:

```css
  .intro { line-height:1.6; max-width:70ch; }
  .intro p { margin:0 0 10px; }
  .example { background:var(--pend); border-radius:8px; padding:12px 14px;
             margin-top:12px; font-size:13px; }
  .example code { font-family:ui-monospace,monospace; color:var(--accent); }
  .example .lbl { color:var(--dim); text-transform:uppercase; font-size:11px;
                  letter-spacing:.04em; display:block; margin-bottom:2px; }
  .example .row { margin-bottom:8px; }
  .cards { display:flex; flex-wrap:wrap; gap:10px; }
  .card { background:var(--pend); border-radius:8px; padding:10px 12px;
          min-width:130px; }
  .card .n { font-size:16px; font-weight:600; font-variant-numeric:tabular-nums; }
  .card .s { color:var(--dim); font-size:12px; }
  .warn { border-left:3px solid var(--mid); background:rgba(210,153,34,.08);
          padding:10px 12px; border-radius:6px; margin-top:12px; font-size:13px;
          line-height:1.55; }
```

Then insert these two panels immediately after the `<div class="sub" id="sub">loading…</div>` line:

```html
<div class="panel intro">
  <p><b>What this measures.</b> Each MCP server exposes a handful of tools. A
  <i>task</i> is a natural-language ask plus the tool that should answer it and the
  arguments that must be filled. Every task is replayed against a locally-served
  small model, several times.</p>
  <p><b>tool-selection</b> is how often the model picked the right tool.
  <b>argument-filling</b> is how often it also filled the arguments correctly — so
  argument-filling can never exceed tool-selection. 100%/100% means every task, every
  run. A tool that scores badly is a <i>tool design</i> problem, not a model problem:
  the fix is to simplify the tool, not lower the bar.</p>
  <div class="example" id="example">loading an example task…</div>
  <div class="warn">
    <b>Reading the numbers.</b> A cell is a small number of runs per task, so a
    sub-100% score is a noisy estimate rather than a precise measurement — the same
    cell can land several points apart on consecutive runs. Treat a failure as real
    only when it <b>reproduces</b>. Cells at 100% have proven stable on re-run.
  </div>
</div>

<div class="panel">
  <div class="legend">servers under test — tools registered, schema size, tasks</div>
  <div class="cards" id="cards">…</div>
</div>
```

Then add these two render functions inside the `<script>` block, just before `async function tick()`:

```javascript
function renderServers(s) {
  const rows = s.servers || [];
  document.getElementById("cards").innerHTML = rows.map(r =>
    '<div class="card"><div class="n">' + esc(r.server) + '</div>' +
    '<div class="s">' + (r.tool_count === null ? "? tools" : r.tool_count + " tools") +
    " · " + (r.schema_kb === null ? "? KB" : r.schema_kb + " KB") +
    " · " + r.task_count + " tasks</div></div>"
  ).join("");

  // One real task, end to end. A concrete example teaches more than definitions,
  // and reading it from the live task set means it cannot drift from reality.
  const first = rows.find(r => r.example);
  if (!first) return;
  const ex = first.example;
  const args = ex.expect_args
    ? '<div class="row"><span class="lbl">must fill</span><code>' +
      esc(JSON.stringify(ex.expect_args)) + "</code></div>"
    : "";
  document.getElementById("example").innerHTML =
    '<div class="row"><span class="lbl">example task · ' + esc(first.server) +
    '</span></div>' +
    '<div class="row"><span class="lbl">someone asks</span>“' + esc(ex.prompt) + '”</div>' +
    '<div class="row"><span class="lbl">right answer</span>call <code>' +
    esc(ex.expect_tool) + "</code></div>" + args;
}
```

And register it alongside the existing trend fetch, replacing the two trailing `get("/api/trend")` lines at the end of the script with:

```javascript
get("/api/trend").then(renderTrend).catch(() => {});
get("/api/servers").then(renderServers).catch(() => {});
tick();
setInterval(tick, 5000);
setInterval(() => get("/api/trend").then(renderTrend).catch(() => {}), 60000);
```

- [ ] **Step 4: Run tests and look at it**

Run: `uv run pytest scripts/tests/test_eval_dashboard.py -q`
Expected: PASS.

Then: `uv run python scripts/eval_dashboard.py` and open `http://127.0.0.1:8765`. Verify the example task shows a real prompt from `evals/defender/tasks.yaml`, and each server card shows tool/schema/task counts (tools and KB show `?` for servers whose cells predate Task 1). Ctrl-C.

- [ ] **Step 5: Commit**

```bash
git add scripts/dashboard/index.html scripts/tests/test_eval_dashboard.py
git commit -m "feat(evals): dashboard explains what it measures"
```

---

### Task 5: Drill-down panel

**Files:**
- Modify: `scripts/dashboard/index.html`
- Test: `scripts/tests/test_eval_dashboard.py`

**Interfaces:**
- Consumes: `/api/cell?model=<tag>&server=<name>`, and the `tag` already present on each matrix row.
- Produces: nothing other tasks depend on.

- [ ] **Step 1: Write the failing test**

Append to `scripts/tests/test_eval_dashboard.py`:

```python
def test_page_wires_cell_drilldown():
    html = dash.PAGE.read_text(encoding="utf-8")
    assert "/api/cell?model=" in html
    assert "openCell" in html          # the click handler exists
    assert "not recorded" in html      # the honest fallback for older runs
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest scripts/tests/test_eval_dashboard.py -k drilldown -v`
Expected: FAIL — `/api/cell?model=` not in the page.

- [ ] **Step 3: Implement**

Add these styles before `</style>`:

```css
  .drill { margin-top:14px; border-top:1px solid var(--line); padding-top:12px; }
  .drill h3 { font-size:14px; margin:0 0 2px; }
  .drill .meta { color:var(--dim); font-size:12px; margin-bottom:10px; }
  .task { border-bottom:1px solid var(--line); padding:8px 0; font-size:13px; }
  .task:last-child { border-bottom:0; }
  .task .p { margin-bottom:3px; }
  .task .d { color:var(--dim); font-size:12px; font-family:ui-monospace,monospace; }
  .task .bad { color:var(--bad); }
  .task .rate { float:right; font-variant-numeric:tabular-nums; color:var(--dim); }
  td.cell { cursor:pointer; }
```

Add a container for the panel — put it immediately after the matrix table, inside the same panel div, replacing `<div class="panel scroll"><table id="matrix"></table></div>` with:

```html
<div class="panel">
  <div class="scroll"><table id="matrix"></table></div>
  <div class="drill" id="drill" style="display:none"></div>
</div>
```

Then add the handler in the `<script>` block, before `async function tick()`:

```javascript
async function openCell(model, server) {
  const el = document.getElementById("drill");
  el.style.display = "block";
  el.innerHTML = "loading…";
  let d;
  try {
    d = await get("/api/cell?model=" + encodeURIComponent(model) +
                  "&server=" + encodeURIComponent(server));
  } catch (e) { el.innerHTML = "could not load that cell"; return; }
  if (!d.found) { el.innerHTML = "no result recorded for that cell"; return; }

  const meta = [
    d.tool_count == null ? null : d.tool_count + " tools",
    d.schema_kb == null ? null : d.schema_kb + " KB schema",
    d.tasks.length + " tasks",
    d.recorded ? null : "outcomes not recorded for this run",
  ].filter(Boolean).join(" · ");

  const rows = d.tasks.map(t => {
    const failed = t.recorded && (t.args_rate === 0 || t.tool_rate === 0 ||
                                  t.args_rate < 1);
    // `calls` is what the model ACTUALLY chose — the misroute, by name.
    const wrong = (t.calls || []).filter(c => c && c !== t.expect_tool);
    const detail = !t.recorded
      ? "expects " + esc(t.expect_tool) + " · not recorded"
      : "expects " + esc(t.expect_tool) +
        (wrong.length ? ' · <span class="bad">called ' +
          esc([...new Set(wrong)].join(", ")) + "</span>" : "");
    const rate = t.recorded
      ? '<span class="rate">' + fmtPct(t.tool_rate) + "/" + fmtPct(t.args_rate) + "</span>"
      : "";
    return '<div class="task">' + rate + '<div class="p">' +
           (failed ? "✗ " : t.recorded ? "✓ " : "· ") + esc(t.prompt) +
           '</div><div class="d">' + detail + "</div></div>";
  }).join("");

  el.innerHTML = "<h3>" + esc(model) + " · " + esc(server) + "</h3>" +
                 '<div class="meta">' + esc(meta) + "</div>" + rows;
}
```

Finally, make cells clickable — in `renderMatrix`, change the row-building line so each `<td>` carries its coordinates. Replace:

```javascript
  const rows = (m.rows || []).map(r => "<tr><td>" + esc(r.display) + "</td>" +
    r.cells.map(c => {
```

with:

```javascript
  const rows = (m.rows || []).map(r => "<tr><td>" + esc(r.display) + "</td>" +
    r.cells.map(c => {
      const click = ' onclick="openCell(\'' + esc(r.tag) + "','" + esc(c.server) + "')\"";
```

and append `click` to each returned `<td` — i.e. change the three return lines to open with
`'<td' + click + ' class="cell pending"…'`, `'<td' + click + ' class="cell broken"…'`, and
`'<td' + click + ' class="cell"…'` respectively.

- [ ] **Step 4: Run tests and click through it**

Run: `uv run pytest scripts/tests/test_eval_dashboard.py -q && uv run ruff check . && uv run mypy .`
Expected: PASS, both linters clean.

Then start the dashboard and click a cell that scored below 100% — for the current data that is `Granite 4 Tiny × projectachilles`. The panel must list every task with failures first. Because that run predates Task 1, it will read "outcomes not recorded for this run" and show the prompts only; that is the correct backward-compatible behaviour.

- [ ] **Step 5: Commit**

```bash
git add scripts/dashboard/index.html scripts/tests/test_eval_dashboard.py
git commit -m "feat(evals): click a cell to see which task failed"
```

---

### Task 6: Re-sweep to populate the detail

**Files:** none — this is an operational step producing `evals/results/<date>.json`.

**Interfaces:**
- Consumes: Task 1's persistence.

- [ ] **Step 1: Confirm the GPU is free**

```bash
nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv,noheader
ollama ps
```

Expected: no compute processes, no loaded model. **Do not start while another sweep is running** — two models contending for VRAM produces CPU spill, which invalidates every timing and slows the run roughly 8×.

- [ ] **Step 2: Run the per-server sweep with force**

```bash
nohup uv run python -m evals.scorecard --runs 3 --force \
  --servers "defender,entra,intune,limacharlie,projectachilles,projectachilles-actions,purview,tenable" \
  > /tmp/resweep.log 2>&1 & disown
```

`--force` re-runs cells already present, which is the point: the existing cells carry no task detail. Expect roughly 2 hours at ~4 min/cell.

- [ ] **Step 3: Verify detail landed**

```bash
python3 -c "
import json; d=json.load(open('evals/results/2026-07-28.json'))
c=d['cells']['granite4:tiny-h-c128k::projectachilles']
print('tasks:', len(c['tasks']), 'tools:', c['tool_count'], 'schema_kb:', c['schema_kb'])
bad=[t for t in c['tasks'] if t['args_rate'] < 1]
for t in bad: print(' ', round(t['args_rate'],2), t['prompt'][:50], '->', set(t['calls']))
"
```

Expected: task count matching `evals/projectachilles/tasks.yaml`, and each failing task printing the tools actually called.

- [ ] **Step 4: Compare against the first sweep**

The re-sweep is a second independent sample of every cell. Record which cells reproduce and which move — that is the direct evidence for the reproduces-vs-noise question the published table currently can only raise. Update the "How to read the sub-100 cells" table in `evals/SCORECARD.md` with the second sample.

- [ ] **Step 5: Commit the results**

```bash
git add evals/results/ evals/SCORECARD.md
git commit -m "chore(evals): re-sweep with per-task detail; second sample of every cell"
```

---

## Self-review

**Spec coverage.** Persist per-task rows → Task 1. Task inventory from YAML, works retroactively → Task 2. `/api/servers` + per-server cards → Tasks 2 and 4. Query-parameter routing with the traversal invariant preserved → Task 3. `/api/cell` drill-down with failures first and misroute names → Tasks 3 and 5. Narrative header with a live example task → Task 4. Signal-vs-noise band → Task 4. Backward compatibility for cells without rows → Tasks 3 and 5. Re-sweep → Task 6. Out-of-scope items (PR annotations, write actions, per-task history) appear in no task.

**Placeholders.** None — every step carries its code or command.

**Type consistency.** `task_inventory` (Task 2) is consumed by `servers_view` (Task 2) and `cell_view` (Task 3). `_cell_key` and `latest_results_path`/`load_results` are pre-existing and used unchanged. `build_payload`'s new `params` argument is optional, so the existing three-argument calls in the test suite keep working. The `cell_view` keys asserted in Task 3's tests (`found`, `recorded`, `tasks`, `calls`, `expect_args`) are exactly those read by the page in Task 5. `renderServers` (Task 4) reads `server`/`task_count`/`tool_count`/`schema_kb`/`example`, matching `servers_view`'s output.

**One risk worth naming.** Task 5 edits `renderMatrix` by describing a change to three return lines rather than restating the whole function. That is the one place a fresh implementer could mis-apply the edit; if in doubt, open the file and confirm all three `<td` returns carry `click` before committing.
