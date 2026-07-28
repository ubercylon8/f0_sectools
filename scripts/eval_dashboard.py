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

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "evals" / "results"
TASKS_DIR = ROOT / "evals"
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


def _all_servers(results: dict[str, Any]) -> list[str]:
    """Metadata servers PLUS any server that only appears in cells.

    run_matrix overwrites results["servers"] with whatever --servers it was
    given, so resuming a sweep with a narrower list erases the wider one from
    metadata while its cells stay on disk. render_scorecard_md unions the two
    for exactly this reason; rendering metadata alone silently hides a
    completed result.
    """
    servers = list(results.get("servers") or [])
    for key in results.get("cells") or {}:
        server = key.rsplit("::", 1)[-1]
        if server not in servers:
            servers.append(server)
    return servers


def progress(results: dict[str, Any]) -> dict[str, Any]:
    """Counts by state, the failures worth waking someone for, and what is next.

    Scoped to THIS run's servers: a cell carried over from a wider earlier run
    must not inflate the done count with work this sweep never did.
    """
    models = results.get("models") or []
    servers = results.get("servers") or []
    cells = results.get("cells") or {}
    in_scope = {k: v for k, v in cells.items() if k.rsplit("::", 1)[-1] in servers}

    failed = [
        {"key": k, "status": c.get("status"), "error": c.get("error", "")}
        for k, c in cells.items()
        if c.get("status") not in ("ok", None)
    ]  # failures are reported wherever they are, in scope or not
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
        "done": len(in_scope),
        "pending": total - len(in_scope),
        "ok": sum(1 for c in in_scope.values() if c.get("status") == "ok"),
        "failed": sorted(failed, key=lambda f: f["key"]),
        "current": current,
    }


def matrix(results: dict[str, Any]) -> dict[str, Any]:
    """The grid. A cell never run is `pending` — never a zero score.

    Columns are the UNION of metadata and cells, so a server dropped from a
    resumed run keeps showing the results it already has. Within such a column
    an empty cell is `skipped` rather than `pending`: this sweep is never going
    to fill it, and saying "pending" would promise work that is not queued.
    """
    scope = set(results.get("servers") or [])
    servers = _all_servers(results)
    cells = results.get("cells") or {}
    rows = []
    for m in results.get("models") or []:
        row_cells = []
        for s in servers:
            c = cells.get(_cell_key(m["tag"], s))
            if c is None:
                row_cells.append({"server": s,
                                  "status": "pending" if s in scope else "skipped",
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
        # Carried so the page can say "establishing (1/3)" rather than a bare
        # "establishing…", which reads the same as broken.
        "needed": MIN_ETA_SAMPLES,
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
            # Two different facts look identical as "no data": a model dropped
            # from the roster, and one still queued in a sweep that is running.
            # Labelling the second "not in this run" would be a plain untruth.
            reason = None
            if rate is None:
                reason = "pending" if tag is not None else "absent"
            models[name].append({
                "date": data.get("date", ""),
                "args_rate": rate,
                "servers": servers,
                "roster_differs": differs,
                "reason": reason,
            })
    return {
        "runs": [{"date": d.get("date", ""), "servers": d.get("servers") or []}
                 for d in runs],
        "models": models,
    }


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
        if name == "progress":
            return 200, {"error": "no results found", "total": 0, "done": 0,
                         "pending": 0, "ok": 0, "failed": [], "current": None,
                         "stale": False}
        return 200, {"servers": [], "rows": [], "error": "no results found"}
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


class Observer:
    """Times cells by watching them appear.

    A sweep that started before cells recorded their own `elapsed_s` carries no
    timing at all, which would leave the ETA stuck at `establishing` forever. We
    cannot know how long a cell took if it finished before we started looking —
    but for cells that land WHILE we watch, the gap between successive
    appearances is a fair estimate. When several appear between two polls the
    gap is split evenly across them.
    """

    def __init__(self, clock: Any = time.monotonic) -> None:
        self._clock = clock
        self._seen: set[str] = set()
        self._mark: float | None = None
        self._lock = threading.Lock()
        self.timings: dict[str, float] = {}

    def observe(self, keys: Any) -> dict[str, float]:
        # Locked because this is a shared singleton and ThreadingHTTPServer
        # gives every request its own thread; correctness should not depend on
        # callers happening to be serialised.
        with self._lock:
            now = self._clock()
            keys = set(keys)
            if self._mark is None:      # first look: baseline, time nothing
                self._seen, self._mark = keys, now
                return self.timings
            new = keys - self._seen
            if new:
                per = (now - self._mark) / len(new)
                for k in new:
                    self.timings[k] = per
                self._seen, self._mark = keys, now
            return self.timings


class _Handler(BaseHTTPRequestHandler):
    results_dir = RESULTS_DIR
    observer = Observer()

    def do_GET(self) -> None:  # noqa: N802 - stdlib API
        name = route(self.path)
        if name is None:
            self.send_error(404, "not found")
            return
        if name == "page":
            self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
            return
        # Only `progress` consumes timings, so only it pays for the observation.
        # Observing on `matrix` too meant a second file read AND two threads
        # racing the shared Observer every five seconds, for data matrix ignores.
        observed = self._observed() if name == "progress" else {}
        status, body = build_payload(name, self.results_dir, observed)
        self._send(status, json.dumps(body).encode(), "application/json")

    def _observed(self) -> dict[str, float]:
        """Feed the observer the current cell set so it can time new arrivals.

        A second read of the results file, deliberately: it keeps build_payload's
        signature a plain dict (easy to test) and the file is small enough that
        re-reading it every five seconds costs nothing.
        """
        path = latest_results_path(self.results_dir)
        if path is None:
            return self.observer.timings
        try:
            return self.observer.observe((load_results(path).get("cells") or {}).keys())
        except (ValueError, OSError):
            return self.observer.timings

    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
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
