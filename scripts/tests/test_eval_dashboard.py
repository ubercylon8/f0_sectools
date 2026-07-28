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
    # The sampled mix must differ from the REMAINING mix for the weighting to
    # bite: here 4 per-server + 1 all are done, leaving a remainder that is half
    # `all`. (A fixture where both mixes match makes pooled and weighted means
    # coincide and proves nothing — the first version of this test did that.)
    r = _timed({
        "m1::defender": {"status": "ok", "elapsed_s": 100.0},
        "m1::entra": {"status": "ok", "elapsed_s": 100.0},
        "m1::all": {"status": "ok", "elapsed_s": 1000.0},
        "m2::defender": {"status": "ok", "elapsed_s": 100.0},
        "m2::entra": {"status": "ok", "elapsed_s": 100.0},
    })
    e = dash.eta(r)
    assert e["status"] == "ok"
    assert e["mean_per_server"] == 100.0
    assert e["mean_all"] == 1000.0
    # remaining: 2 per-server (m3 x defender,entra) + 2 all (m2,m3)
    assert e["seconds"] == 2 * 100.0 + 2 * 1000.0 == 2200.0
    # A naive pooled mean would say ((4*100 + 1000)/5) * 4 = 1120s — half the
    # truth, because it dilutes the slow `all` cells with fast per-server ones.
    assert e["seconds"] > 2 * 1120.0 * 0.9


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
