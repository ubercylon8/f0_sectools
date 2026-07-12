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
    SERVER_MODULES,
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
    # size check (not just exists()) matters for --no-write, which points
    # out_path at os.devnull: that path exists and reads back as "", which
    # would otherwise blow up json.loads with a JSONDecodeError.
    if out_path.exists() and out_path.stat().st_size > 0:
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
            except ValueError:
                raise  # e.g. tool-name collision in the combined registry — fail loud
            except Exception as e:  # noqa: BLE001 - one dead cell must not kill the sweep
                results["cells"][key] = {"status": "error", "error": str(e)[:200]}
            _write_results(out_path, results)
    return results


SCORECARD_MD = EVALS / "SCORECARD.md"
_FINDINGS_MARKER = (
    "<!-- findings below: hand-annotated, preserved when the table is regenerated -->"
)


def render_scorecard_md(results: dict) -> str:
    """Render the model x server matrix as a markdown table.

    Renders the UNION of results["models"]/["servers"] and whatever tags/servers
    actually appear in results["cells"]. A resumed sweep invoked with a narrower
    --models/--servers subset only overwrites those two metadata lists (see
    run_matrix), so a cell persisted by an earlier, wider sweep can still be
    present on disk even though the metadata no longer mentions its model/server.
    Deriving the displayed rows/columns from the union — rather than trusting
    the metadata alone — guarantees no present cell is ever silently dropped
    from the table. Tags found only in cell keys fall back to the tag itself
    as their display name (no display name was ever recorded for them here).
    """
    cells = results.get("cells", {})
    cell_pairs = [k.split("::", 1) for k in cells if "::" in k]

    servers = list(results.get("servers", []))
    for _, server in cell_pairs:
        if server not in servers:
            servers.append(server)

    models = list(results.get("models", []))
    known_tags = {m["tag"] for m in models}
    for tag, _ in cell_pairs:
        if tag not in known_tags:
            models.append({"tag": tag, "display": tag})
            known_tags.add(tag)

    head = "| Model | " + " | ".join(servers) + " |"
    sep = "|" + "---|" * (len(servers) + 1)
    lines = [
        "# Small-model tool-calling scorecard",
        "",
        f"Endpoint `{results.get('base_url', '')}` · runs/task {results.get('runs', 1)} "
        f"· generated {results.get('date', '')}",
        "",
        "Each cell is **tool-selection% / argument-filling%** over the server's task "
        "set. `all` = every server's 28 tools registered at once (composition test). "
        "`err` = model/endpoint error; `–` = not run.",
        "",
        head,
        sep,
    ]
    for m in models:
        row = [m["display"]]
        for s in servers:
            cell = cells.get(cell_key(m["tag"], s))
            if not cell:
                row.append("–")
            elif cell.get("status") == "error":
                row.append("err")
            else:
                row.append(f"{cell['tool_rate']:.0%}/{cell['args_rate']:.0%}")
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines) + "\n"


def write_scorecard_md(results: dict, path: Path | None = None) -> None:
    """Regenerate the table and rewrite the file, but preserve everything from
    the hand-annotated findings marker onward (see _FINDINGS_MARKER). This is a
    full-file overwrite ONLY of the table portion — the findings/notes a human
    appended below the marker survive a plain re-run."""
    path = path or SCORECARD_MD
    table = render_scorecard_md(results)
    existing = path.read_text() if path.exists() else ""
    if _FINDINGS_MARKER in existing:
        tail = _FINDINGS_MARKER + existing.split(_FINDINGS_MARKER, 1)[1]
    else:
        tail = _FINDINGS_MARKER + "\n"
    path.write_text(table + "\n" + tail)


def main() -> None:
    import argparse
    import asyncio
    from datetime import UTC, datetime

    p = argparse.ArgumentParser(description="f0_sectools scorecard matrix (model x server)")
    p.add_argument("--base-url", default="http://localhost:11434/v1",
                   help="OpenAI-compatible endpoint (default: local Ollama)")
    p.add_argument("--runs", type=int, default=1)
    p.add_argument("--models", default=None,
                   help="comma-separated tags; default all in models.yaml")
    p.add_argument("--servers", default=None,
                   help="comma-separated; default all servers + 'all'")
    p.add_argument("--out", default=None,
                   help="results JSON path; default evals/results/<date>.json")
    p.add_argument("--date", default=None, help="date stamp; default today (UTC)")
    p.add_argument("--force", action="store_true", help="re-run cells already present")
    p.add_argument("--no-write", action="store_true",
                   help="skip writing results JSON and SCORECARD.md")
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
