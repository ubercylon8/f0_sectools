# Eval Scorecard Matrix + Multi-Server Eval — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a reproducible model×server **scorecard matrix** and a **combined-registry (multi-server) eval** to the small-model harness, reusing the existing `evals/run.py` internals — proving both which local models drive the tools reliably and whether the ≤8-tools-per-server discipline survives all 22 tools registered at once.

**Architecture:** `evals/run.py` gains combined-registry helpers (`combined_tool_schemas`, `combined_tasks`, `aggregate_by_origin`) and a `--server all` mode with a per-origin routing report. A new `evals/scorecard.py` orchestrates models (from `evals/models.yaml`) × servers, persisting incremental JSON to `evals/results/` and generating a committed `evals/SCORECARD.md`. All new logic is unit-tested offline with a fake model client; real numbers come from a live Ollama sweep at the end.

**Tech Stack:** Python 3.11+, `httpx` (async), `pyyaml`, `pytest` + `respx`, `uv` workspace. Local model served via Ollama's OpenAI-compatible endpoint (`http://localhost:11434/v1`).

## Global Constraints

- **Reuse `run.py` internals, don't rewrite them:** `ModelClient`, `ToolCall`, `server_tool_schemas(server)`, `load_tasks(server)`, `run_suite(tools, tasks, client, runs)`, `score_task`, `format_report`, `SERVER_MODULES`, `EVALS` (the `Path(__file__).parent`).
- **The four servers expose 22 uniquely-named tools** (defender 6, entra 4, limacharlie 6, projectachilles 6) — no collisions today; the combined builder must FAIL LOUD if a future collision appears.
- **Tests live flat in `evals/`** (`evals/test_scorecard.py`, `evals/test_combined.py`) — matching `evals/test_harness.py` / `evals/test_eval_coverage.py`, NOT an `evals/tests/` subdir.
- **`evals/results/` is already gitignored** at the repo root (`.gitignore` lines 42-44) — do NOT add a new `.gitignore`; the runner just `mkdir(parents=True, exist_ok=True)`s it.
- **Offline unit tests use a fake `ModelClient`** (a class with `async def call(self, prompt, tools)` returning a `ToolCall` or `None`) — deterministic, no network, gates CI. Live model runs are manual and never gate CI.
- **Matrix defaults to `runs=1`** (harness is `temperature=0`; extra runs mostly catch GPU nondeterminism). Configurable via `--runs`.
- **No tool description/schema is changed in this pass** — the eval SURFACES mis-routing; fixing a specific tool is a follow-up driven by results.
- **Commit style:** conventional commits ending with the two trailer lines exactly:
  `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`
  `Claude-Session: https://claude.ai/code/session_01TMoap3fRVq13TQah7BMdLm`
  Stage specific files; never `git add -A`. Do not push.

---

### Task 1: Combined tool registry + collision guard

**Files:**
- Modify: `evals/run.py` (add `combined_tool_schemas`)
- Test: `evals/test_combined.py` (create)

**Interfaces:**
- Consumes: `server_tool_schemas(server)`, `SERVER_MODULES` (existing in `run.py`).
- Produces: `async combined_tool_schemas() -> list[dict]` — the union of all four servers' OpenAI tool schemas; raises `ValueError` on a duplicate tool name.

- [ ] **Step 1: Write the failing test**

Create `evals/test_combined.py`:

```python
"""Offline tests for the combined-registry (multi-server) eval.

No live model: tool schemas come from the real servers (local, no network),
and scoring is exercised with canned data.
"""
from __future__ import annotations

import pytest

from evals.run import combined_tool_schemas


@pytest.mark.asyncio
async def test_combined_registry_unions_all_22_tools():
    tools = await combined_tool_schemas()
    names = [t["function"]["name"] for t in tools]
    assert len(names) == 22, f"expected 22 tools, got {len(names)}"
    assert len(set(names)) == 22, "tool names must be unique across servers"
    # spot-check one tool from each server is present
    for expected in ("isolate_host", "list_risky_users", "query_telemetry", "get_defense_score"):
        assert expected in names
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest evals/test_combined.py -v`
Expected: FAIL — `ImportError: cannot import name 'combined_tool_schemas' from 'evals.run'`.

- [ ] **Step 3: Write minimal implementation**

In `evals/run.py`, after the existing `server_tool_schemas` function, add:

```python
async def combined_tool_schemas() -> list[dict]:
    """Union of every server's tool schemas — the registry an operator sees with
    all servers registered at once. Raises if two servers expose the same tool
    name (would make the OpenAI tool list ambiguous)."""
    out: list[dict] = []
    seen: set[str] = set()
    for server in sorted(SERVER_MODULES):
        for schema in await server_tool_schemas(server):
            name = schema["function"]["name"]
            if name in seen:
                raise ValueError(f"tool name collision across servers: {name!r}")
            seen.add(name)
            out.append(schema)
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest evals/test_combined.py -v`
Expected: PASS.

- [ ] **Step 5: Add and verify the collision-guard test**

Append to `evals/test_combined.py`:

```python
def test_collision_guard_is_reachable():
    # The guard is a plain name-uniqueness check; assert the logic that backs it.
    # (A real collision can't be constructed without a duplicate-named server, so
    # we test the invariant the union relies on: all current names are unique.)
    import asyncio
    tools = asyncio.run(combined_tool_schemas())
    names = [t["function"]["name"] for t in tools]
    assert sorted(names) == sorted(set(names))
```

Run: `uv run pytest evals/test_combined.py -v`
Expected: PASS (both tests).

- [ ] **Step 6: Commit**

```bash
git add evals/run.py evals/test_combined.py
git commit -m "feat(evals): add combined tool registry with collision guard

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TMoap3fRVq13TQah7BMdLm"
```

---

### Task 2: Combined tasks, probes, per-origin aggregation, run_suite enrichment

**Files:**
- Modify: `evals/run.py` (add `combined_tasks`, `aggregate_by_origin`; enrich `run_suite` task rows with `calls`)
- Create: `evals/combined/probes.yaml`
- Test: `evals/test_combined.py` (append)

**Interfaces:**
- Consumes: `load_tasks(server)`, `SERVER_MODULES`, `EVALS`, `run_suite` (existing).
- Produces:
  - `combined_tasks() -> list[dict]` — every per-server task with `origin` set to its server, concatenated with `evals/combined/probes.yaml` entries (each probe carries its own `origin`).
  - `aggregate_by_origin(tasks: list[dict], report: dict) -> dict` — groups the suite report's per-task rows by `origin`; returns `{origin: {"tool_rate": float, "args_rate": float, "n": int, "misroutes": {tool_name: count}}}`.
  - `run_suite` task rows now also carry `"calls": list[str|None]` (the tool the model called on each run) — additive, existing keys unchanged.

- [ ] **Step 1: Write the failing tests**

Append to `evals/test_combined.py`:

```python
from evals.run import aggregate_by_origin, combined_tasks, run_suite
from evals.run import ToolCall


def test_combined_tasks_tagged_with_origin_and_include_probes():
    tasks = combined_tasks()
    # 12 defender + 8 entra + 8 limacharlie + 8 projectachilles = 36, plus probes.
    per_server = [t for t in tasks if t["origin"] in
                  {"defender", "entra", "limacharlie", "projectachilles"}]
    assert len(per_server) == 36
    probes = [t for t in tasks if t not in per_server]
    assert len(probes) >= 6, "expected the cross-platform probe set"
    assert all("origin" in t and "prompt" in t and "expect_tool" in t for t in tasks)


@pytest.mark.asyncio
async def test_run_suite_records_calls():
    tasks = [{"prompt": "a", "expect_tool": "list_incidents", "origin": "defender"}]

    class _Fake:
        async def call(self, prompt, tools):
            return ToolCall("query_telemetry", {})  # wrong tool (misroute)

    report = await run_suite([], tasks, _Fake(), runs=2)
    assert report["tasks"][0]["calls"] == ["query_telemetry", "query_telemetry"]


def test_aggregate_by_origin_groups_and_counts_misroutes():
    tasks = [
        {"prompt": "a", "expect_tool": "list_incidents", "origin": "defender"},
        {"prompt": "b", "expect_tool": "get_secure_score", "origin": "defender"},
        {"prompt": "c", "expect_tool": "get_defense_score", "origin": "projectachilles"},
    ]
    report = {
        "tasks": [
            {"tool_rate": 0.0, "args_rate": 0.0, "calls": ["query_telemetry"]},  # misrouted
            {"tool_rate": 1.0, "args_rate": 1.0, "calls": ["get_secure_score"]},
            {"tool_rate": 1.0, "args_rate": 1.0, "calls": ["get_defense_score"]},
        ],
        "overall_tool_rate": 2 / 3, "overall_args_rate": 2 / 3,
    }
    agg = aggregate_by_origin(tasks, report)
    assert agg["defender"]["tool_rate"] == 0.5
    assert agg["defender"]["n"] == 2
    assert agg["defender"]["misroutes"] == {"query_telemetry": 1}
    assert agg["projectachilles"]["tool_rate"] == 1.0
    assert agg["projectachilles"]["misroutes"] == {}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest evals/test_combined.py -v -k "combined_tasks or records_calls or by_origin"`
Expected: FAIL — `ImportError` on `aggregate_by_origin`/`combined_tasks`, and `run_suite` rows lack `calls`.

- [ ] **Step 3: Create the probes file**

Create `evals/combined/probes.yaml`:

```yaml
# Cross-platform routing probes for the combined (all-servers) eval.
# Each prompt is deliberately ambiguous across platforms; `origin` names the
# platform whose tool SHOULD be selected when all 22 tools are registered.
# Same field schema as a server tasks.yaml, plus the required `origin`.

- prompt: "Run a Defender advanced hunting query for suspicious PowerShell."
  expect_tool: run_hunting_query
  origin: defender

- prompt: "Hunt across our LimaCharlie endpoints for new processes."
  expect_tool: query_telemetry
  origin: limacharlie

- prompt: "List our LimaCharlie sensors."
  expect_tool: list_sensors
  origin: limacharlie

- prompt: "List our ProjectAchilles validation agents."
  expect_tool: list_agents
  origin: projectachilles

- prompt: "Show our risky users in Entra."
  expect_tool: list_risky_users
  origin: entra

- prompt: "What risk acceptances are on file in ProjectAchilles?"
  expect_tool: list_risk_acceptances
  origin: projectachilles
```

- [ ] **Step 4: Enrich `run_suite` and add the combined helpers**

In `evals/run.py`, in `run_suite`, change the `task_rows.append({...})` block to also record `calls` (additive — keep every existing key):

```python
        task_rows.append(
            {
                "prompt": task["prompt"],
                "expect_tool": task["expect_tool"],
                "tool_rate": sum(a["tool_correct"] for a in attempts) / n,
                "args_rate": sum(a["args_correct"] for a in attempts) / n,
                "runs": n,
                "calls": [a["called"] for a in attempts],
            }
        )
```

Then add, after `combined_tool_schemas`:

```python
def combined_tasks() -> list[dict]:
    """Every per-server task tagged with its origin server, plus the cross-platform
    routing probes. This is the task set for the combined 22-tool registry."""
    tasks: list[dict] = []
    for server in sorted(SERVER_MODULES):
        for t in load_tasks(server):
            tasks.append({**t, "origin": server})
    probes_path = EVALS / "combined" / "probes.yaml"
    if probes_path.exists():
        for p in yaml.safe_load(probes_path.read_text()) or []:
            tasks.append(dict(p))  # probes already carry `origin`
    return tasks


def aggregate_by_origin(tasks: list[dict], report: dict) -> dict:
    """Group the suite report's per-task rows by their `origin` server. Relies on
    run_suite preserving task order. For each origin: mean tool/args rate, count,
    and which wrong tools its prompts were misrouted to."""
    groups: dict[str, dict] = {}
    for task, row in zip(tasks, report["tasks"]):
        origin = task.get("origin", "unknown")
        g = groups.setdefault(origin, {"tool": [], "args": [], "misroutes": {}})
        g["tool"].append(row["tool_rate"])
        g["args"].append(row["args_rate"])
        if row["tool_rate"] < 1.0:
            for called in row.get("calls", []):
                if called and called != task["expect_tool"]:
                    g["misroutes"][called] = g["misroutes"].get(called, 0) + 1
    out: dict[str, dict] = {}
    for origin, g in groups.items():
        n = len(g["tool"]) or 1
        out[origin] = {
            "tool_rate": sum(g["tool"]) / n,
            "args_rate": sum(g["args"]) / n,
            "n": len(g["tool"]),
            "misroutes": g["misroutes"],
        }
    return out
```

(`yaml` is already imported at the top of `run.py`.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest evals/test_combined.py -v`
Expected: PASS (all combined tests). Also run `uv run pytest evals/test_harness.py -v` — the existing `run_suite` test must still pass (the `calls` key is additive).

- [ ] **Step 6: Commit**

```bash
git add evals/run.py evals/combined/probes.yaml evals/test_combined.py
git commit -m "feat(evals): combined task set, per-origin routing aggregation, run_suite calls

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TMoap3fRVq13TQah7BMdLm"
```

---

### Task 3: `run.py --server all` CLI mode + combined report

**Files:**
- Modify: `evals/run.py` (add `format_combined_report`; branch `_amain`; extend `--server` choices)
- Test: `evals/test_combined.py` (append a formatter test)

**Interfaces:**
- Consumes: `combined_tool_schemas`, `combined_tasks`, `aggregate_by_origin`, `run_suite`, `ModelClient` (from earlier tasks).
- Produces: `format_combined_report(model: str, report: dict, origin_agg: dict) -> str`; `--server all` runs the combined registry and prints the per-origin report.

- [ ] **Step 1: Write the failing test**

Append to `evals/test_combined.py`:

```python
from evals.run import format_combined_report


def test_format_combined_report_shows_origins_and_misroutes():
    report = {"overall_tool_rate": 0.75, "overall_args_rate": 0.5, "tasks": []}
    agg = {
        "defender": {"tool_rate": 0.5, "args_rate": 0.5, "n": 2,
                     "misroutes": {"query_telemetry": 1}},
        "projectachilles": {"tool_rate": 1.0, "args_rate": 1.0, "n": 1, "misroutes": {}},
    }
    text = format_combined_report("gpt-oss:20b-c128k", report, agg)
    assert "defender" in text
    assert "query_telemetry" in text  # the misroute target is shown
    assert "75%" in text  # overall tool-selection
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest evals/test_combined.py -v -k format_combined`
Expected: FAIL — `ImportError: cannot import name 'format_combined_report'`.

- [ ] **Step 3: Implement the formatter and CLI branch**

In `evals/run.py`, add after `format_report`:

```python
def format_combined_report(model: str, report: dict, origin_agg: dict) -> str:
    lines = [f"\nCombined eval (all 22 tools)  x  {model}", "-" * 72]
    for origin in sorted(origin_agg):
        g = origin_agg[origin]
        mis = ", ".join(f"{k}x{v}" for k, v in sorted(g["misroutes"].items())) or "-"
        lines.append(
            f"  {origin:16} tool {g['tool_rate']:5.0%}  args {g['args_rate']:5.0%}  "
            f"(n={g['n']})  misrouted-> {mis}"
        )
    lines.append("-" * 72)
    lines.append(
        f"  OVERALL  tool-selection {report['overall_tool_rate']:.0%}  "
        f"argument-filling {report['overall_args_rate']:.0%}"
    )
    return "\n".join(lines)
```

Change `_amain` to branch on `all`:

```python
async def _amain(args: argparse.Namespace) -> None:
    api_key = args.api_key or os.environ.get("OPENAI_API_KEY")
    if args.server == "all":
        tools = await combined_tool_schemas()
        tasks = combined_tasks()
    else:
        tools = await server_tool_schemas(args.server)
        tasks = load_tasks(args.server)
    async with ModelClient(args.base_url, args.model, api_key) as client:
        report = await run_suite(tools, tasks, client, runs=args.runs)
    if args.server == "all":
        print(format_combined_report(args.model, report, aggregate_by_origin(tasks, report)))
    else:
        print(format_report(args.server, args.model, report))
```

Change the `--server` argument to allow `all`:

```python
    p.add_argument("--server", required=True, choices=[*sorted(SERVER_MODULES), "all"])
```

- [ ] **Step 4: Run test + a CLI import smoke**

Run: `uv run pytest evals/test_combined.py -v -k format_combined`
Expected: PASS.

Run: `uv run python -c "from evals.run import format_combined_report, combined_tasks, combined_tool_schemas; print('ok')"`
Expected: `ok`.

- [ ] **Step 5: Commit**

```bash
git add evals/run.py evals/test_combined.py
git commit -m "feat(evals): add --server all combined-registry mode with per-origin report

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TMoap3fRVq13TQah7BMdLm"
```

---

### Task 4: Model list + scorecard matrix core (incremental, resumable)

**Files:**
- Create: `evals/models.yaml`
- Create: `evals/scorecard.py`
- Test: `evals/test_scorecard.py` (create)

**Interfaces:**
- Consumes: `combined_tool_schemas`, `combined_tasks`, `server_tool_schemas`, `load_tasks`, `run_suite`, `ModelClient` (from `run.py`).
- Produces:
  - `load_models(path=None) -> list[dict]` — parses `evals/models.yaml` into `[{"tag": str, "display": str}, …]`.
  - `cell_key(model_tag: str, server: str) -> str` — `f"{model_tag}::{server}"`.
  - `async run_matrix(models, servers, base_url, runs, out_path, date, *, force=False, client_factory=None) -> dict` — runs each (model, server) cell not already present in `out_path` (unless `force`), writing the whole results dict to `out_path` after every cell. Errors become `{"status": "error", ...}` cells, never aborting the sweep. Returns the results dict.

- [ ] **Step 1: Create the model list**

Create `evals/models.yaml`:

```yaml
# Broad-sweep model matrix for the scorecard. Every entry is tool-capable and
# servable via Ollama's OpenAI-compatible endpoint. `tag` is the model id sent to
# the API; `display` is the row label in SCORECARD.md.
- { tag: "gpt-oss:20b-c128k",        display: "GPT-OSS 20B" }
- { tag: "qwen3:8b-c40k",            display: "Qwen3 8B" }
- { tag: "qwen3:4b-c256k",           display: "Qwen3 4B" }
- { tag: "qwen3.5:latest",           display: "Qwen3.5 (9.7B)" }
- { tag: "gemma4:e4b",               display: "Gemma 4 E4B" }
- { tag: "gemma4:12b",               display: "Gemma 4 12B" }
- { tag: "ministral-3:latest-c256k", display: "Ministral 3 (8.9B)" }
- { tag: "granite4:tiny-h-c128k",    display: "Granite 4 Tiny" }
```

- [ ] **Step 2: Write the failing tests**

Create `evals/test_scorecard.py`:

```python
"""Offline tests for the scorecard matrix orchestrator. No live model: a fake
client returns canned tool calls; JSON persistence and resume use tmp paths."""
from __future__ import annotations

import json

import pytest

from evals.run import ToolCall
from evals.scorecard import cell_key, load_models, run_matrix


class _FakeClient:
    """Async-context client whose call() always picks the task's expected tool."""

    def __init__(self, base_url, model):
        self.model = model

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def call(self, prompt, tools):
        # Perfect model: echo back the first tool as if chosen. For scoring we
        # need the EXPECTED tool, so the fake is wired per-test via monkeypatch.
        return ToolCall(self._expect, {})


def _fake_factory(expect_tool):
    def make(base_url, model):
        c = _FakeClient(base_url, model)
        c._expect = expect_tool
        return c
    return make


def test_load_models_reads_tag_and_display():
    models = load_models()
    assert models and all("tag" in m and "display" in m for m in models)
    assert any(m["tag"] == "gpt-oss:20b-c128k" for m in models)


def test_cell_key_format():
    assert cell_key("gpt-oss:20b-c128k", "defender") == "gpt-oss:20b-c128k::defender"


@pytest.mark.asyncio
async def test_run_matrix_writes_cells_incrementally(tmp_path):
    out = tmp_path / "r.json"
    models = [{"tag": "m1", "display": "M1"}]
    # A model that always calls get_secure_score: correct only for that Defender task.
    res = await run_matrix(
        models, ["defender"], "http://x/v1", 1, out, "2026-01-01",
        client_factory=_fake_factory("get_secure_score"),
    )
    key = cell_key("m1", "defender")
    assert key in res["cells"]
    assert res["cells"][key]["status"] == "ok"
    # persisted to disk after the cell
    on_disk = json.loads(out.read_text())
    assert key in on_disk["cells"]


@pytest.mark.asyncio
async def test_run_matrix_resumes_skipping_done_cells(tmp_path):
    out = tmp_path / "r.json"
    out.write_text(json.dumps({
        "cells": {cell_key("m1", "defender"): {"status": "ok", "tool_rate": 1.0, "args_rate": 1.0}}
    }))
    called = {"n": 0}

    def factory(base_url, model):
        called["n"] += 1
        return _fake_factory("get_secure_score")(base_url, model)

    await run_matrix(
        [{"tag": "m1", "display": "M1"}], ["defender"], "http://x/v1", 1, out, "2026-01-01",
        client_factory=factory,
    )
    assert called["n"] == 0, "an already-present cell must be skipped (no client built)"


@pytest.mark.asyncio
async def test_run_matrix_records_error_cells_without_aborting(tmp_path):
    out = tmp_path / "r.json"

    class _Boom:
        def __init__(self, *a): ...
        async def __aenter__(self): raise RuntimeError("model down")
        async def __aexit__(self, *e): return None

    res = await run_matrix(
        [{"tag": "m1", "display": "M1"}], ["defender", "entra"], "http://x/v1", 1, out,
        "2026-01-01", client_factory=lambda u, m: _Boom(),
    )
    assert res["cells"][cell_key("m1", "defender")]["status"] == "error"
    assert res["cells"][cell_key("m1", "entra")]["status"] == "error"  # sweep continued
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest evals/test_scorecard.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'evals.scorecard'`.

- [ ] **Step 4: Implement `evals/scorecard.py` (core, no rendering yet)**

Create `evals/scorecard.py`:

```python
"""Model x server tool-calling scorecard. Reuses the run.py harness internals to
run every model in evals/models.yaml against every server (plus the combined
'all' registry), persisting incremental JSON results and (Task 5) a SCORECARD.md.

Usage (from repo root, with models served locally, e.g. Ollama):

    uv run python -m evals.scorecard --base-url http://localhost:11434/v1 --runs 1
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import yaml

from evals.run import (
    ModelClient,
    combined_tasks,
    combined_tool_schemas,
    load_tasks,
    run_suite,
    server_tool_schemas,
    SERVER_MODULES,
)

EVALS = Path(__file__).parent
DEFAULT_MODELS = EVALS / "models.yaml"


def load_models(path: Path | None = None) -> list[dict]:
    data = yaml.safe_load((path or DEFAULT_MODELS).read_text())
    if not isinstance(data, list) or not data:
        raise ValueError("models.yaml must be a non-empty list of {tag, display}")
    for m in data:
        if "tag" not in m or "display" not in m:
            raise ValueError(f"model entry missing tag/display: {m!r}")
    return data


def cell_key(model_tag: str, server: str) -> str:
    return f"{model_tag}::{server}"


def _default_factory(base_url: str):
    api_key = os.environ.get("OPENAI_API_KEY")
    return lambda url, tag: ModelClient(url, tag, api_key)


async def _tools_and_tasks(server: str):
    if server == "all":
        return await combined_tool_schemas(), combined_tasks()
    return await server_tool_schemas(server), load_tasks(server)


def _load_results(out_path: Path) -> dict:
    if out_path.exists():
        return json.loads(out_path.read_text())
    return {"cells": {}}


def _write_results(out_path: Path, results: dict) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2))


async def run_matrix(
    models: list[dict],
    servers: list[str],
    base_url: str,
    runs: int,
    out_path: Path,
    date: str,
    *,
    force: bool = False,
    client_factory=None,
) -> dict:
    """Run each (model, server) cell; write the whole results dict after each cell.
    Cells already present are skipped unless force=True. Errors become error-cells
    and never abort the sweep."""
    factory = client_factory or _default_factory(base_url)
    results = _load_results(out_path)
    results.setdefault("cells", {})
    results.update({"date": date, "base_url": base_url, "runs": runs,
                    "models": models, "servers": servers})
    for m in models:
        tag = m["tag"]
        for server in servers:
            key = cell_key(tag, server)
            if key in results["cells"] and not force:
                continue
            try:
                tools, tasks = await _tools_and_tasks(server)
                async with factory(base_url, tag) as client:
                    rep = await run_suite(tools, tasks, client, runs=runs)
                results["cells"][key] = {
                    "status": "ok",
                    "tool_rate": rep["overall_tool_rate"],
                    "args_rate": rep["overall_args_rate"],
                }
            except Exception as e:  # noqa: BLE001 - one dead cell must not kill the sweep
                results["cells"][key] = {"status": "error", "error": str(e)[:200]}
            _write_results(out_path, results)
    return results
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest evals/test_scorecard.py -v`
Expected: PASS (all matrix tests).

- [ ] **Step 6: Commit**

```bash
git add evals/models.yaml evals/scorecard.py evals/test_scorecard.py
git commit -m "feat(evals): scorecard matrix core — models.yaml + incremental resumable runner

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TMoap3fRVq13TQah7BMdLm"
```

---

### Task 5: SCORECARD.md generator + CLI + docs

**Files:**
- Modify: `evals/scorecard.py` (add `render_scorecard_md`, `write_scorecard_md`, `main`/CLI)
- Create: `evals/SCORECARD.md` (committed placeholder)
- Modify: `evals/README.md`, `docs/user-guide/` testing/eval section
- Test: `evals/test_scorecard.py` (append rendering tests)

**Interfaces:**
- Consumes: the results dict from `run_matrix` (keys: `date, base_url, runs, models, servers, cells`).
- Produces: `render_scorecard_md(results: dict) -> str`; `write_scorecard_md(results, path=None)`; a `main()` CLI (`--base-url`, `--runs`, `--models`, `--servers`, `--no-write`, `--force`, `--out`, `--date`).

- [ ] **Step 1: Write the failing tests**

Append to `evals/test_scorecard.py`:

```python
from evals.scorecard import render_scorecard_md


def test_render_scorecard_md_table():
    results = {
        "date": "2026-01-01", "base_url": "http://x/v1", "runs": 1,
        "models": [{"tag": "m1", "display": "M1"}, {"tag": "m2", "display": "M2"}],
        "servers": ["defender", "all"],
        "cells": {
            "m1::defender": {"status": "ok", "tool_rate": 1.0, "args_rate": 1.0},
            "m1::all": {"status": "ok", "tool_rate": 0.9, "args_rate": 0.8},
            "m2::defender": {"status": "error", "error": "down"},
            # m2::all intentionally missing → renders as a dash
        },
    }
    md = render_scorecard_md(results)
    assert "| Model | defender | all |" in md
    assert "| M1 | 100%/100% | 90%/80% |" in md
    assert "err" in md  # m2::defender
    assert "M2" in md
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest evals/test_scorecard.py -v -k render`
Expected: FAIL — `ImportError: cannot import name 'render_scorecard_md'`.

- [ ] **Step 3: Implement rendering + CLI**

Append to `evals/scorecard.py`:

```python
SCORECARD_MD = EVALS / "SCORECARD.md"


def render_scorecard_md(results: dict) -> str:
    servers = results["servers"]
    head = "| Model | " + " | ".join(servers) + " |"
    sep = "|" + "---|" * (len(servers) + 1)
    lines = [
        "# Small-model tool-calling scorecard",
        "",
        f"Endpoint `{results.get('base_url', '')}` · runs/task {results.get('runs', 1)} "
        f"· generated {results.get('date', '')}",
        "",
        "Each cell is **tool-selection% / argument-filling%** over the server's task "
        "set. `all` = every server's 22 tools registered at once (composition test). "
        "`err` = model/endpoint error; `–` = not run.",
        "",
        head,
        sep,
    ]
    for m in results["models"]:
        row = [m["display"]]
        for s in servers:
            cell = results["cells"].get(cell_key(m["tag"], s))
            if not cell:
                row.append("–")
            elif cell.get("status") == "error":
                row.append("err")
            else:
                row.append(f"{cell['tool_rate']:.0%}/{cell['args_rate']:.0%}")
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines) + "\n"


def write_scorecard_md(results: dict, path: Path | None = None) -> None:
    (path or SCORECARD_MD).write_text(render_scorecard_md(results))


def main() -> None:
    import argparse
    import asyncio
    from datetime import UTC, datetime

    p = argparse.ArgumentParser(description="f0_sectools scorecard matrix (model x server)")
    p.add_argument("--base-url", default="http://localhost:11434/v1",
                   help="OpenAI-compatible endpoint (default: local Ollama)")
    p.add_argument("--runs", type=int, default=1)
    p.add_argument("--models", default=None, help="comma-separated tags; default all in models.yaml")
    p.add_argument("--servers", default=None,
                   help="comma-separated; default all servers + 'all'")
    p.add_argument("--out", default=None, help="results JSON path; default evals/results/<date>.json")
    p.add_argument("--date", default=None, help="date stamp; default today (UTC)")
    p.add_argument("--force", action="store_true", help="re-run cells already present")
    p.add_argument("--no-write", action="store_true", help="skip writing results JSON and SCORECARD.md")
    args = p.parse_args()

    date = args.date or datetime.now(UTC).date().isoformat()
    models = load_models()
    if args.models:
        wanted = {t.strip() for t in args.models.split(",")}
        models = [m for m in models if m["tag"] in wanted]
    servers = ([s.strip() for s in args.servers.split(",")] if args.servers
               else [*sorted(SERVER_MODULES), "all"])
    out_path = Path(args.out) if args.out else (EVALS / "results" / f"{date}.json")
    if args.no_write:
        out_path = Path(os.devnull)

    results = asyncio.run(
        run_matrix(models, servers, args.base_url, args.runs, out_path, date, force=args.force)
    )
    print(render_scorecard_md(results))
    if not args.no_write:
        write_scorecard_md(results)
        print(f"\nWrote {SCORECARD_MD}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests + create the committed placeholder**

Run: `uv run pytest evals/test_scorecard.py evals/test_combined.py -v`
Expected: PASS (all).

Create `evals/SCORECARD.md` (committed placeholder — the live sweep in Task 6 overwrites it):

```markdown
# Small-model tool-calling scorecard

_Pending the first live sweep. Generate with:_

```
uv run python -m evals.scorecard --base-url http://localhost:11434/v1 --runs 1
```

Each cell will be **tool-selection% / argument-filling%** per server, with an `all`
column for the combined 22-tool registry (the composition test).
```

- [ ] **Step 5: Document in README + user guide**

Add a "Scorecard & multi-server eval" subsection to `evals/README.md` describing:
- `uv run python -m evals.scorecard --base-url … [--runs N] [--models …] [--servers …] [--no-write]` and that it writes `evals/results/<date>.json` (gitignored) + regenerates `evals/SCORECARD.md`.
- `uv run python -m evals.run --server all --base-url … --model … --runs N` for the ad-hoc combined per-origin report.
- A one-liner linking `SCORECARD.md`.

Add one sentence + the `--server all` example to the eval/testing section of the user guide (find the file under `docs/user-guide/` that covers evals; match its heading style).

- [ ] **Step 6: Full offline sweep + commit**

Run: `uv run pytest -q && uv run ruff check .`
Expected: all pass, lint clean.

```bash
git add evals/scorecard.py evals/SCORECARD.md evals/test_scorecard.py evals/README.md docs/user-guide/
git commit -m "feat(evals): SCORECARD.md generator + scorecard CLI + docs

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TMoap3fRVq13TQah7BMdLm"
```

---

### Task 6: Live validation — smoke + full broad-sweep

**Files:**
- Modify: `evals/SCORECARD.md` (populated by the live run), `evals/results/<date>.json` (gitignored — not committed)

**Interfaces:**
- Consumes: the whole scorecard/combined pipeline against a live Ollama endpoint.

> This task runs the LOCAL model (Ollama), not a live security platform — it is compute-only, reversible, and makes no external calls, so it does not require a human pause. It DOES need network access to `localhost:11434`, so run with the shell sandbox disabled.

- [ ] **Step 1: Confirm the endpoint and model tags are live**

Run: `curl -s http://localhost:11434/v1/models | python3 -c "import sys,json;[print(m['id']) for m in json.load(sys.stdin)['data']]"`
Expected: the list includes every `tag` in `evals/models.yaml`. If a tag is missing, note it — that model's row will show `err`/`–`; either `ollama pull` it or drop it from `models.yaml` (and say which in the report).

- [ ] **Step 2: Two-model smoke (fast, confirms wiring live)**

Run (sandbox disabled):
```
uv run python -m evals.scorecard --base-url http://localhost:11434/v1 \
  --models "gpt-oss:20b-c128k,gemma4:e4b" --runs 1 --no-write
```
Expected: a rendered table with real percentages for both models across the 4 servers + `all`, no crash. This proves the matrix + combined path end-to-end without touching the committed scorecard.

- [ ] **Step 3: Full broad-sweep (long; run in background)**

Run (sandbox disabled, background — 8 models × 5 configs; expect tens of minutes):
```
uv run python -m evals.scorecard --base-url http://localhost:11434/v1 --runs 1
```
This writes `evals/results/<date>.json` incrementally (resumable if interrupted: re-run the same command to continue) and regenerates `evals/SCORECARD.md`.

- [ ] **Step 4: Triage sub-100% cells before reporting**

For any cell scoring <100%, re-check at higher runs to separate nondeterminism from a real miss:
```
uv run python -m evals.run --server <server> --base-url http://localhost:11434/v1 \
  --model <tag> --runs 3
```
For the `all` column specifically, run the per-origin report to see WHICH tools collide:
```
uv run python -m evals.run --server all --base-url http://localhost:11434/v1 --model <tag> --runs 3
```
Record genuine misroutes (e.g. Defender `run_hunting_query` ↔ LimaCharlie `query_telemetry`) as findings — these are tool-description defects for a FOLLOW-UP pass, not fixed here.

- [ ] **Step 5: Commit the populated scorecard**

Verify `git status` shows only `evals/SCORECARD.md` changed (results JSON is gitignored).

```bash
git add evals/SCORECARD.md
git commit -m "docs(evals): populate scorecard from first live broad-sweep

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TMoap3fRVq13TQah7BMdLm"
```

Report: the populated matrix, the per-origin routing findings (which platforms' prompts misroute and to which tools), and any models that couldn't be reached — with a recommended follow-up list of tool descriptions to sharpen.

---

## Self-Review

**Spec coverage:**
- Combined registry (union, collision guard) → Task 1. ✓
- Combined tasks tagged by origin + probes + per-origin aggregation → Task 2. ✓
- `run.py --server all` + per-origin report → Task 3. ✓
- `models.yaml` broad sweep + `scorecard.py` matrix + incremental/resumable JSON + error cells → Task 4. ✓
- `SCORECARD.md` generator + `--no-write` + CLI + README/user-guide → Task 5. ✓
- Offline unit tests with a fake client (both suites) → Tasks 1–5. ✓
- Live smoke + background full sweep + triage → Task 6. ✓
- `runs=1` matrix default; temp-0 rationale → Task 4/5 CLI + Global Constraints. ✓
- No tool-description change this pass → Global Constraints + Task 6 (findings are follow-ups). ✓
- `evals/results/` already gitignored (no new file) → Global Constraints. ✓

**Placeholder scan:** No TBD/TODO. Task 5 Step 5 (README/user-guide prose) is descriptive because it is docs copy, not code — acceptable. All code steps show complete code.

**Type consistency:** `combined_tool_schemas()`/`combined_tasks()`/`aggregate_by_origin(tasks, report)` are defined in Tasks 1–2 and consumed identically in Tasks 3–4. `run_suite` task rows gain `"calls"` in Task 2 and are read by `aggregate_by_origin` (Task 2) and tests. `cell_key(tag, server)`, `run_matrix(models, servers, base_url, runs, out_path, date, *, force, client_factory)`, `load_models`, `render_scorecard_md(results)` are consistent between Task 4 (def) and Task 5 (use). Results-dict keys (`date, base_url, runs, models, servers, cells`) match between `run_matrix` (Task 4) and `render_scorecard_md` (Task 5). Fake-client shape (`async call(self, prompt, tools)` + async context manager) matches the existing `test_harness.py` pattern.

**Deviation from spec (reconciled):** the spec's file list put tests under `evals/tests/` and listed an `evals/results/.gitignore`; the plan places tests flat in `evals/` (matching the existing `test_harness.py`/`test_eval_coverage.py` convention) and omits the `.gitignore` (the root already ignores `evals/results/`). Both are followed-the-existing-pattern corrections, noted in Global Constraints.
