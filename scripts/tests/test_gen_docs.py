"""Drift guard: the generated reference docs must match the code.

Regenerates docs/reference/tools/*.md and docs/reference/skills.md in memory
and diffs against the committed files. Fails CI when a tool or skill changes
without `uv run python scripts/gen_docs.py` being re-run — the same pattern
integrations/test_integrations_valid.py uses for runtime templates.
"""
import importlib.util
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "gen_docs", Path(__file__).resolve().parents[1] / "gen_docs.py"
)
gen_docs = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(gen_docs)


async def test_generated_reference_docs_are_fresh():
    outputs = await gen_docs.build_outputs()
    stale = []
    for path, expected in outputs.items():
        actual = path.read_text(encoding="utf-8") if path.is_file() else "<missing>"
        if actual != expected:
            stale.append(path.relative_to(gen_docs.ROOT).as_posix())
    assert not stale, (
        "Generated reference docs are stale — run `uv run python scripts/gen_docs.py` "
        f"and commit the result. Stale: {stale}"
    )


def test_every_server_module_produces_a_page():
    # The generator derives its server list from evals.run.SERVER_MODULES —
    # a page must exist on disk for each entry (guards deleted-but-committed pages).
    for server in gen_docs.SERVER_MODULES:
        page = gen_docs.TOOLS_DIR / f"{server}.md"
        assert page.is_file(), f"missing generated page for server '{server}': {page}"
