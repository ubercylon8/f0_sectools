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
