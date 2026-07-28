"""Offline tests for the scorecard matrix orchestrator. No live model: a fake
client returns canned tool calls; JSON persistence and resume use tmp paths."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from evals.run import ToolCall
from evals.scorecard import (
    _FINDINGS_MARKER,
    cell_key,
    load_models,
    render_scorecard_md,
    run_matrix,
    write_scorecard_md,
)


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


def test_every_roster_model_declares_a_context():
    # The invariant, not a literal tag: a BASE tag is served with Ollama's
    # 4096-token default, and the 51-tool composition schema is ~32 KB, so the
    # model receives no usable tool list and calls nothing — which the scorecard
    # would otherwise have published as 0%. Every row must be a context-capped
    # derive. Proven by A/B: gemma4:e4b returns None on 51 tools where
    # gemma4:e4b-ctx16k returns the correct tool.
    for m in load_models():
        tag = m["tag"]
        assert any(mark in tag for mark in ("ctx", "-c")), (
            f"{tag} looks like a base tag; roster models must declare a context "
            "(see the recipe at the top of evals/models.yaml)"
        )


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
        "tool_total": 51,
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
        "tool_total": 51,
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


def test_write_scorecard_preserves_findings_below_marker(tmp_path):
    """write_scorecard_md must regenerate only the table and preserve everything
    from the hand-annotated findings marker onward, even when called with a
    different results dict than produced the existing file."""
    path = tmp_path / "SCORECARD.md"
    custom_findings = (
        f"{_FINDINGS_MARKER}\n\n"
        "> Some accurate note.\n\n"
        "## Findings\n\n"
        "**Totally custom hand-annotated text that must survive regeneration.**\n"
    )
    path.write_text("# Old stale table\n\nstale content\n\n" + custom_findings)

    results = {
        "date": "2026-02-02", "base_url": "http://x/v1", "runs": 1,
        "models": [{"tag": "m1", "display": "M1"}],
        "servers": ["defender"],
        "tool_total": 51,
        "cells": {
            "m1::defender": {"status": "ok", "tool_rate": 1.0, "args_rate": 1.0},
        },
    }
    write_scorecard_md(results, path=path)

    written = path.read_text()
    assert "| M1 | 100%/100% |" in written
    assert "stale content" not in written
    assert "Totally custom hand-annotated text that must survive regeneration." in written
    assert _FINDINGS_MARKER in written


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


def test_an_unusable_cell_renders_as_ctx_not_a_number():
    # The whole point: a serving problem must be visibly distinct from a score.
    results = {
        "base_url": "http://x/v1", "runs": 1, "date": "2026-07-26",
        "models": [{"tag": "m1", "display": "M1"}],
        "servers": ["all"],
        "tool_total": 51,
        "cells": {
            "m1::all": {"status": "unusable", "error": "no tool call on ANY of 97 tasks"},
        },
    }
    md = render_scorecard_md(results)
    assert "| M1 | ctx! |" in md
    assert "0%" not in md
    assert "NOT a score of zero" in md      # the legend explains the marker


def test_the_legend_reports_the_real_registry_size():
    # This read "28 tools" while the registry had grown to 51 — the document
    # misdescribed the very test it reports.
    results = {
        "base_url": "", "runs": 1, "date": "d", "models": [], "servers": ["all"],
        "tool_total": 51, "cells": {},
    }
    assert "51 tools registered at once" in render_scorecard_md(results)
    assert "28 tools" not in render_scorecard_md(results)


def test_rendering_a_table_does_not_import_the_servers(monkeypatch):
    # This file's contract is "offline tests, no live model". A tool-count
    # fallback that re-derives the registry by importing all eight server
    # packages quietly broke that: formatting markdown became a live dependency
    # on every server importing cleanly, so an unrelated break in (say) the
    # Purview package would fail scorecard-RENDERING tests. run_matrix records
    # `tool_total` where it is already known, and the fallback must not fire.
    def _explode() -> int:
        raise AssertionError("render must not re-derive the registry")

    monkeypatch.setattr("evals.scorecard._combined_tool_count", _explode)
    md = render_scorecard_md({
        "base_url": "", "runs": 1, "date": "d", "models": [], "servers": ["all"],
        "tool_total": 51, "cells": {},
    })
    assert "51 tools registered at once" in md


@pytest.mark.asyncio
async def test_run_matrix_records_the_registry_size_for_the_renderer(tmp_path):
    async def fake_tools_and_tasks(server):
        n = 51 if server == "all" else 6
        tools = [{"type": "function", "function": {"name": f"t{i}"}} for i in range(n)]
        return tools, [{"prompt": "p", "expect_tool": "t0"}]

    import unittest.mock as mock
    with mock.patch("evals.scorecard._tools_and_tasks", fake_tools_and_tasks):
        results = await run_matrix(
            base_url="http://x/v1",
            models=[{"tag": "m1", "display": "M1"}],
            servers=["all"],
            runs=1,
            out_path=tmp_path / "r.json",
            date="2026-07-26",
            client_factory=_fake_factory("t0"),
        )
    assert results["tool_total"] == 51


@pytest.mark.asyncio
async def test_run_matrix_records_elapsed_per_cell(tmp_path, monkeypatch):
    # A cell's duration is the only basis a dashboard has for an ETA, and the
    # results JSON carried no timing at all. Every completed cell records it.
    import evals.scorecard as sc

    ticks = iter([100.0, 130.5, 200.0, 260.0])
    monkeypatch.setattr(sc, "_now", lambda: next(ticks))

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
