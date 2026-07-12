"""Skill x model matrix for the agentic (multi-step) eval — sibling of scorecard.py.

Runs every scenario in evals/scenarios/ against every model in evals/models.yaml,
scoring coverage% + goal-rate, and renders evals/AGENTIC.md. Resumable, date-stamped
JSON in evals/results/. Local-only (needs Ollama); never run in CI. Evict models
between runs on a memory-constrained box (see evals/README.md), as with scorecard.py.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx

from .agentic import SCENARIOS_DIR, load_scenario, run_scenario
from .run import ModelClient
from .scorecard import load_models  # reuse the models.yaml loader


async def _query_vram_gb(base_url: str, tag: str) -> float | None:
    """Read the resident VRAM footprint of `tag` from Ollama's /api/ps (in GB).
    Call this while the model is still loaded. Returns None if unavailable."""
    ps_url = base_url.rstrip("/").removesuffix("/v1") + "/api/ps"
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            resp = await c.get(ps_url)
            for m in resp.json().get("models", []):
                if m.get("name") == tag:
                    return round(m.get("size_vram", 0) / 1e9, 1)
    except (httpx.HTTPError, ValueError, KeyError):
        return None
    return None

EVALS = Path(__file__).resolve().parent
RESULTS_DIR = EVALS / "results"
AGENTIC_MD = EVALS / "AGENTIC.md"
_FINDINGS_MARKER = (
    "<!-- findings below: hand-annotated, "
    "preserved when the table is regenerated -->"
)


def cell_key(tag: str, skill: str) -> str:
    return f"{tag}::{skill}"


def render_agentic_md(results: dict) -> str:
    cells = results.get("cells", {})
    cell_pairs = [k.split("::", 1) for k in cells if "::" in k]

    skills = list(results.get("skills", []))
    for _, skill in cell_pairs:
        if skill not in skills:
            skills.append(skill)

    models = list(results.get("models", []))
    known = {m["tag"] for m in models}
    for tag, _ in cell_pairs:
        if tag not in known:
            models.append({"tag": tag, "display": tag})
            known.add(tag)

    head = "| Skill | " + " | ".join(m["display"] for m in models) + " |"
    sep = "|" + "---|" * (len(models) + 1)
    lines = [
        "# Multi-step (agentic) skill scorecard",
        "",
        f"Endpoint `{results.get('base_url', '')}` · runs/scenario {results.get('runs', 1)} "
        f"· generated {results.get('date', '')}",
        "",
        "Each cell is **tool-coverage% / goal-reached%** for a model driving that skill's "
        "full procedure against deterministic mock tools. `err` = model/endpoint error; "
        "`–` = not run.",
        "",
        head,
        sep,
    ]
    for skill in skills:
        row = [skill]
        for m in models:
            cell = cells.get(cell_key(m["tag"], skill))
            if not cell:
                row.append("–")
            elif cell.get("error"):
                row.append("err")
            else:
                row.append(f"{cell['coverage']:.0%} / {cell['goal_rate']:.0%}")
        lines.append("| " + " | ".join(row) + " |")
    lines.extend(_perf_lines(results, models))
    return "\n".join(lines) + "\n"


def _perf_lines(results: dict, models: list[dict]) -> list[str]:
    """A companion 'Speed & footprint' table: median wall-clock to drive one skill
    end-to-end, and resident VRAM. Kept separate from the correctness matrix above —
    orthogonal concern. Rows show '–' where a metric wasn't captured."""
    cells = results.get("cells", {})
    perf = results.get("perf", {})
    lat: dict[str, list[float]] = {}
    for k, c in cells.items():
        if c and c.get("latency_s") is not None:
            lat.setdefault(k.split("::", 1)[0], []).append(c["latency_s"])
    lines = [
        "",
        "## Speed & footprint",
        "",
        "Median wall-clock to drive **one whole skill** end-to-end (multi-step loop "
        "against mock tools) and resident **VRAM** (Ollama `size_vram`). Local box, one "
        "model resident at a time — an operator's guide to picking a model for their "
        "hardware. Orthogonal to the correctness matrix above.",
        "",
        "| Model | median s / skill | VRAM |",
        "|---|---|---|",
    ]
    for m in models:
        tag = m["tag"]
        med = statistics.median(lat[tag]) if lat.get(tag) else None
        vram = perf.get(tag, {}).get("vram_gb")
        med_s = f"{med:.1f}s" if med is not None else "–"
        vram_s = f"{vram:.1f} GB" if vram is not None else "–"
        lines.append(f"| {m['display']} | {med_s} | {vram_s} |")
    return lines


def write_agentic_md(results: dict, path: Path | None = None) -> None:
    path = path or AGENTIC_MD
    table = render_agentic_md(results)
    existing = path.read_text() if path.exists() else ""
    if _FINDINGS_MARKER in existing:
        tail = _FINDINGS_MARKER + existing.split(_FINDINGS_MARKER, 1)[1]
    else:
        tail = _FINDINGS_MARKER + "\n"
    path.write_text(table + "\n" + tail)


async def _amain(args: argparse.Namespace) -> None:
    models = load_models()
    if args.models:
        wanted = {t.strip() for t in args.models.split(",")}
        models = [m for m in models if m["tag"] in wanted]
    scenarios = [(p.stem, load_scenario(p)) for p in sorted(SCENARIOS_DIR.glob("*.yaml"))]

    RESULTS_DIR.mkdir(exist_ok=True)
    results_path = RESULTS_DIR / f"agentic-{args.date}.json"
    results = json.loads(results_path.read_text()) if results_path.exists() else {}
    results.update({"base_url": args.base_url, "runs": args.runs, "date": args.date,
                    "models": models, "skills": [name for name, _ in scenarios]})
    cells = results.setdefault("cells", {})

    perf = results.setdefault("perf", {})
    for m in models:
        async with ModelClient(args.base_url, m["tag"]) as client:
            for name, scenario in scenarios:
                key = cell_key(m["tag"], name)
                if key in cells and not args.force:
                    continue
                cov_sum = goal_sum = lat_sum = 0.0
                err_count = 0
                last_err = None
                for _ in range(args.runs):
                    t0 = time.monotonic()
                    scored = await run_scenario(client, scenario)
                    lat_sum += time.monotonic() - t0
                    cov_sum += scored["coverage"]
                    goal_sum += 1.0 if scored["goal_reached"] else 0.0
                    if scored["error"]:
                        err_count += 1
                        last_err = scored["error"]
                cells[key] = {"coverage": cov_sum / args.runs,
                              "goal_rate": goal_sum / args.runs,
                              "runs": args.runs,
                              "latency_s": lat_sum / args.runs,
                              "error": last_err if err_count == args.runs else None}
            # while the model is still resident, capture its VRAM footprint
            vram = await _query_vram_gb(args.base_url, m["tag"])
            if vram is not None:
                perf[m["tag"]] = {"vram_gb": vram}
        results_path.write_text(json.dumps(results, indent=2, default=str))
        write_agentic_md(results)
        print(f"scored {m['tag']}")
    print(f"Wrote {AGENTIC_MD}")


def main() -> None:
    p = argparse.ArgumentParser(
        description="f0_sectools agentic skill scorecard (skill x model)"
    )
    p.add_argument("--base-url", default="http://localhost:11434/v1")
    p.add_argument("--runs", type=int, default=1)
    p.add_argument(
        "--models",
        default=None,
        help="comma-separated tags; default all in models.yaml",
    )
    p.add_argument("--date", default=None, help="date stamp; default today (UTC)")
    p.add_argument("--force", action="store_true", help="re-run cells already present")
    args = p.parse_args()
    if not args.date:
        args.date = datetime.now(UTC).date().isoformat()
    asyncio.run(_amain(args))


if __name__ == "__main__":
    main()
