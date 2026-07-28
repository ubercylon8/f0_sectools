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
