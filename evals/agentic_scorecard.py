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
from datetime import UTC, datetime
from pathlib import Path

from .agentic import SCENARIOS_DIR, load_scenario, run_scenario
from .run import ModelClient
from .scorecard import load_models  # reuse the models.yaml loader

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
    return "\n".join(lines) + "\n"


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

    for m in models:
        async with ModelClient(args.base_url, m["tag"]) as client:
            for name, scenario in scenarios:
                key = cell_key(m["tag"], name)
                if key in cells and not args.force:
                    continue
                cov_sum = goal_sum = 0.0
                err_count = 0
                last_err = None
                for _ in range(args.runs):
                    scored = await run_scenario(client, scenario)
                    cov_sum += scored["coverage"]
                    goal_sum += 1.0 if scored["goal_reached"] else 0.0
                    if scored["error"]:
                        err_count += 1
                        last_err = scored["error"]
                cells[key] = {"coverage": cov_sum / args.runs,
                              "goal_rate": goal_sum / args.runs,
                              "runs": args.runs,
                              "error": last_err if err_count == args.runs else None}
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
