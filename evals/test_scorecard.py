"""Offline tests for the scorecard matrix orchestrator. No live model: a fake
client returns canned tool calls; JSON persistence and resume use tmp paths."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from evals.run import ToolCall
from evals.scorecard import cell_key, load_models, render_scorecard_md, run_matrix


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


def test_render_scorecard_md_unions_cells_with_narrowed_metadata():
    """A resumed sweep invoked with --models/--servers narrower than what was
    already persisted must not drop rows/columns for cells that are still
    present on disk. render_scorecard_md must derive the displayed models and
    servers from the UNION of results['models']/['servers'] and the keys
    actually present in results['cells'], never dropping a present cell."""
    results = {
        "date": "2026-01-01", "base_url": "http://x/v1", "runs": 1,
        # metadata narrowed to a single model/server by a resumed --models run
        "models": [{"tag": "m1", "display": "M1"}],
        "servers": ["defender"],
        "cells": {
            "m1::defender": {"status": "ok", "tool_rate": 1.0, "args_rate": 1.0},
            "m2::defender": {"status": "ok", "tool_rate": 0.5, "args_rate": 0.5},
            "m2::entra": {"status": "ok", "tool_rate": 0.4, "args_rate": 0.4},
        },
    }
    md = render_scorecard_md(results)
    assert "M1" in md
    assert "| m2 |" in md  # tag-only fallback display since not in results["models"]
    assert "defender" in md
    assert "entra" in md
    # both model rows must render both server columns' data
    assert "100%/100%" in md
    assert "50%/50%" in md
    assert "40%/40%" in md


@pytest.mark.asyncio
async def test_run_matrix_with_devnull_out_path_does_not_crash():
    """CLI --no-write points out_path at os.devnull. /dev/null exists and reads
    back as an empty string, so a naive json.loads() of its content raises
    JSONDecodeError. run_matrix must treat a pre-existing but empty/unreadable
    results file as "no prior results" instead of crashing, so --no-write can
    still compute and print a scorecard without writing anything real."""
    out = Path(os.devnull)
    res = await run_matrix(
        [{"tag": "m1", "display": "M1"}], ["defender"], "http://x/v1", 1, out,
        "2026-01-01", client_factory=_fake_factory("get_secure_score"),
    )
    assert res["cells"][cell_key("m1", "defender")]["status"] == "ok"
