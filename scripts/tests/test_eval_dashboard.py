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


def test_page_exists_and_is_self_contained():
    html = dash.PAGE.read_text(encoding="utf-8")
    # No CDN, no external anything: the repo ships local-only by policy and the
    # page must render with the network unplugged.
    for forbidden in ("http://", "https://", "//cdn", "integrity="):
        assert forbidden not in html, f"page must not reference {forbidden!r}"
    # It polls the three endpoints the server actually exposes.
    for endpoint in ("/api/progress", "/api/matrix", "/api/trend"):
        assert endpoint in html


def test_observer_times_cells_that_appear_while_it_watches():
    # A sweep started before elapsed_s existed carries no timing. We cannot know
    # how long a cell took if it finished before we looked — but the gap between
    # successive appearances is a fair estimate for cells we DO watch land.
    clock = iter([0.0, 100.0, 400.0])
    obs = dash.Observer(clock=lambda: next(clock))
    assert obs.observe({"a::defender"}) == {}          # first look: baseline only
    assert obs.observe({"a::defender", "a::entra"}) == {"a::entra": 100.0}
    t = obs.observe({"a::defender", "a::entra", "a::all", "b::defender"})
    # two cells appeared across a 300s gap -> 150s each
    assert t["a::all"] == 150.0 and t["b::defender"] == 150.0


def test_observer_ignores_a_poll_with_no_new_cells():
    clock = iter([0.0, 10.0, 20.0])
    obs = dash.Observer(clock=lambda: next(clock))
    obs.observe({"a::defender"})
    obs.observe({"a::defender"})
    assert obs.observe({"a::defender", "a::entra"}) == {"a::entra": 20.0}


def test_trend_distinguishes_absent_from_not_yet_run(tmp_path):
    # A model dropped from the roster and a model still queued in a live sweep
    # both have no data — but they are not the same fact, and a tooltip saying
    # "not in this run" is simply false for the second.
    _write_run(tmp_path, "2026-01-01", ["m1", "m2"], ["defender"], 1.0)
    _write_run(tmp_path, "2026-01-02", ["m1", "m3"], ["defender"], 1.0)
    p = tmp_path / "2026-01-02.json"
    data = json.loads(p.read_text())
    del data["cells"]["m3::defender"]      # in the roster, not yet reached
    p.write_text(json.dumps(data))

    t = dash.trend(tmp_path)
    assert t["models"]["M2"][1]["reason"] == "absent"     # dropped from roster
    assert t["models"]["M3"][1]["reason"] == "pending"    # queued, not run yet
    assert t["models"]["M1"][1]["reason"] is None         # has data


def test_eta_reports_how_many_samples_it_still_needs():
    # "establishing…" with no sense of progress is indistinguishable from
    # broken. The payload carries the threshold so the page need not hardcode it.
    r = _timed({"m1::defender": {"status": "ok", "elapsed_s": 300.0}})
    e = dash.eta(r)
    assert e["needed"] == dash.MIN_ETA_SAMPLES == 3
    assert e["samples"] == 1


def test_observer_is_thread_safe():
    # ThreadingHTTPServer gives every request its own thread and the Observer is
    # a shared singleton, so observe() must not corrupt its own state under
    # concurrent calls. (Flagged in review on PR #86.)
    import threading

    obs = dash.Observer()
    keys, errors = set(), []

    def worker(n):
        try:
            for i in range(20):
                keys.add(f"m{n}::s{i}")
                obs.observe(set(keys))
        except Exception as exc:  # noqa: BLE001 - the assertion is "no exception"
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    # Every key observed after the baseline poll carries a non-negative timing.
    assert all(v >= 0 for v in obs.timings.values())


def test_matrix_still_shows_a_server_dropped_from_the_run_metadata():
    # run_matrix OVERWRITES results["servers"] with whatever --servers was
    # passed, so resuming a sweep with a narrower list erases the wider one from
    # metadata while its cells remain on disk. render_scorecard_md already
    # unions the two for this reason; the dashboard must too, or it silently
    # hides a completed result.
    r = _results(servers=["defender", "entra"])          # `all` no longer in metadata
    r["cells"]["m1::all"] = {"status": "ok", "tool_rate": 0.92, "args_rate": 0.90}
    m = dash.matrix(r)
    assert m["servers"] == ["defender", "entra", "all"]  # union, metadata order first
    row = next(x for x in m["rows"] if x["tag"] == "m1")
    by = {c["server"]: c for c in row["cells"]}
    assert by["all"]["args_rate"] == 0.90
    # m2 has no `all` cell and `all` is not in this run — that is "skipped",
    # not "pending": this sweep is never going to fill it.
    row2 = next(x for x in m["rows"] if x["tag"] == "m2")
    by2 = {c["server"]: c for c in row2["cells"]}
    assert by2["all"]["status"] == "skipped"
    assert by2["defender"]["status"] == "pending"


def test_progress_counts_only_cells_in_this_run_scope():
    # A carried-over cell from a wider earlier run must not inflate this run's
    # done count, or the progress bar reports work this sweep never did.
    r = _results(servers=["defender", "entra"])
    r["cells"]["m1::all"] = {"status": "ok", "tool_rate": 0.92, "args_rate": 0.90}
    p = dash.progress(r)
    assert p["total"] == 4          # 2 models x 2 in-scope servers
    assert p["done"] == 2           # m1::defender, m1::entra — not m1::all


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
    # tasks_dir is passed explicitly: otherwise this reads the REAL evals/
    # inventory and passes by accident rather than by test.
    status, body = dash.build_payload("cell", tmp_path, {},
                                      {"model": "m1", "server": "defender"},
                                      tasks_dir=tmp_path)
    assert status == 200 and body["found"] is True
    assert body["tasks"][0]["prompt"] == "p"


def test_no_definitions_after_the_entrypoint():
    # Running as a script executes top-to-bottom: main() blocks in serve_forever(),
    # so anything defined BELOW `if __name__ == "__main__"` never exists at request
    # time. Appending a function to the end of this file put task_inventory after
    # the entrypoint — every unit test passed (pytest imports, never runs main)
    # while the live server raised NameError on the first /api/cell request.
    src = (Path(__file__).resolve().parents[1] / "eval_dashboard.py").read_text()
    lines = src.splitlines()
    entry = next(i for i, ln in enumerate(lines) if ln.startswith('if __name__'))
    after = [ln for ln in lines[entry:] if ln.startswith(("def ", "class "))]
    assert not after, f"defined after the entrypoint, unreachable as a script: {after}"


def test_page_explains_what_is_measured_and_stays_self_contained():
    html = dash.PAGE.read_text(encoding="utf-8")
    for forbidden in ("http://", "https://", "//cdn", "integrity="):
        assert forbidden not in html, f"page must not reference {forbidden!r}"
    # /api/cell is asserted by the drill-down test, which owns that feature.
    for endpoint in ("/api/progress", "/api/matrix", "/api/trend", "/api/servers"):
        assert endpoint in html
    # The two rates are jargon; the page must define them where they are read.
    assert "tool-selection" in html and "argument-filling" in html
    # And it must state the runs=3 caveat rather than leaving it to a commit log.
    assert "reproduce" in html.lower()


def test_servers_view_prefers_an_example_that_asserts_arguments(tmp_path):
    # The example teaches what "argument-filling" means; one with no asserted
    # args shows only half the story.
    _write_tasks(tmp_path, "defender", [
        {"prompt": "no args here", "expect_tool": "get_secure_score"},
        {"prompt": "this one has args", "expect_tool": "list_incidents",
         "expect_args": {"severity_min": "high"}},
    ])
    v = dash.servers_view(tmp_path, {"cells": {}})
    row = next(r for r in v["servers"] if r["server"] == "defender")
    assert row["example"]["prompt"] == "this one has args"
