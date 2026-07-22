"""Generate the reference docs that must never drift from code.

Outputs (all committed, so they read fine on GitHub without a build step):

- ``docs/reference/tools/<server>.md`` — one page per MCP server, harvested
  from the live FastMCP registry: tool names, descriptions (written for the
  model, perfect for humans), parameter types/enums/defaults, gated-write
  badges, and which skills reference each tool.
- ``docs/reference/tools/README.md`` — the index: server x tool-count table.
- ``docs/reference/skills.md`` — the skills catalog, from SKILL.md frontmatter.

Run after adding/changing a tool or skill:

    uv run python scripts/gen_docs.py

CI enforces freshness via ``scripts/tests/test_gen_docs.py`` (regenerates and
diffs). ``--check`` exits 1 listing stale files instead of writing.
"""
from __future__ import annotations

import argparse
import asyncio
import importlib
import re
import sys
import textwrap
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from evals.run import SERVER_MODULES  # noqa: E402  (single source of the server list)

TOOLS_DIR = ROOT / "docs" / "reference" / "tools"
SKILLS_MD = ROOT / "docs" / "reference" / "skills.md"
SKILLS_ROOT = ROOT / "skills"

GENERATED_NOTE = (
    "<!-- GENERATED FILE - do not edit. "
    "Regenerate with: uv run python scripts/gen_docs.py -->"
)


# ── skills ──────────────────────────────────────────────────────────────


def load_skills() -> list[dict[str, Any]]:
    """Parse every SKILL.md's YAML frontmatter + remember its body for tool xrefs."""
    skills = []
    for path in sorted(SKILLS_ROOT.glob("*/*/SKILL.md")):
        text = path.read_text(encoding="utf-8")
        m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.DOTALL)
        if not m:
            continue
        meta = yaml.safe_load(m.group(1))
        hermes = (meta.get("metadata") or {}).get("hermes") or {}
        skills.append(
            {
                "category": path.parent.parent.name,
                "dir": path.parent.name,
                "path": path.relative_to(ROOT).as_posix(),
                "name": meta.get("name", path.parent.name),
                "description": meta.get("description", ""),
                "version": meta.get("version", ""),
                "tags": hermes.get("tags") or [],
                "body": m.group(2),
            }
        )
    return skills


def render_skills_catalog(skills: list[dict[str, Any]]) -> str:
    lines = [
        GENERATED_NOTE,
        "",
        "# Skills catalog",
        "",
        f"**{len(skills)} portable [agentskills.io](https://agentskills.io) skills** — "
        "one set, loaded unmodified by every skills-aware runtime (Hermes, Claude Code, "
        "pi, opencode). Each links to its `SKILL.md` playbook. See "
        "[using skills & personas](../user-guide/using-skills-and-personas.md) for how "
        "to invoke them.",
        "",
    ]
    by_cat: dict[str, list[dict[str, Any]]] = {}
    for s in skills:
        by_cat.setdefault(s["category"], []).append(s)
    for cat in sorted(by_cat):
        lines += [f"## {cat}", "", "| Skill | Description | Version | Tags |", "|---|---|---|---|"]
        for s in by_cat[cat]:
            link = f"[`{s['name']}`](../../{s['path']})"
            tags = ", ".join(s["tags"])
            lines.append(f"| {link} | {s['description']} | {s['version']} | {tags} |")
        lines.append("")
    return "\n".join(lines)


# ── tools ───────────────────────────────────────────────────────────────


def _clean_desc(desc: str) -> str:
    """PEP-257-style trim: dedent continuation lines so markdown doesn't treat
    indented docstring bodies as code blocks."""
    lines = desc.strip().splitlines()
    if len(lines) <= 1:
        return lines[0] if lines else ""
    rest = textwrap.dedent("\n".join(lines[1:]))
    return "\n".join([lines[0].strip(), rest]).strip()


def _fmt_type(prop: dict[str, Any]) -> str:
    if "enum" in prop:
        return " \\| ".join(f'`"{v}"`' for v in prop["enum"])
    if "anyOf" in prop:
        return " \\| ".join(_fmt_type(p) for p in prop["anyOf"])
    return f"`{prop.get('type', 'any')}`"


def _fmt_default(name: str, prop: dict[str, Any], required: set[str]) -> str:
    if name in required:
        return "*(required)*"
    if "default" in prop:
        d = prop["default"]
        return f'`"{d}"`' if isinstance(d, str) else f"`{d}`"
    return "—"


def _skills_using(tool_name: str, skills: list[dict[str, Any]]) -> list[dict[str, Any]]:
    pat = re.compile(rf"\b{re.escape(tool_name)}\b")
    return [s for s in skills if pat.search(s["body"])]


def _is_gated(tool: Any) -> bool:
    return "confirmation_token" in (tool.inputSchema or {}).get("properties", {})


def render_server_page(
    server: str, mcp: Any, tools: list[Any], skills: list[dict[str, Any]]
) -> str:
    gated = [t for t in tools if _is_gated(t)]
    lines = [
        GENERATED_NOTE,
        "",
        f"# `{mcp.name}` tool reference",
        "",
        f"Module `{SERVER_MODULES[server]}` · **{len(tools)} tools**"
        + (
            f" ({len(tools) - len(gated)} read + {len(gated)} gated write)"
            if gated
            else " (all read-only)"
        )
        + f" · [server README](../../../servers/{_server_dir(server)}/README.md)",
        "",
    ]
    if gated:
        lines += [
            "> 🔒 Gated write tools require the platform write flag **and** a per-action "
            "human confirmation — see the "
            "[security model](../../explanation/security-model.md#gated-write-actions).",
            "",
        ]
    for t in tools:
        badge = " 🔒 *(gated write)*" if t in gated else ""
        lines += [f"## `{t.name}`{badge}", ""]
        desc = _clean_desc(t.description or "")
        if desc:
            lines += [desc, ""]
        schema = t.inputSchema or {}
        props = schema.get("properties", {})
        required = set(schema.get("required", []))
        if props:
            lines += ["| Parameter | Type | Default |", "|---|---|---|"]
            for name, prop in props.items():
                default = _fmt_default(name, prop, required)
                lines.append(f"| `{name}` | {_fmt_type(prop)} | {default} |")
            lines.append("")
        else:
            lines += ["*No parameters.*", ""]
        users = _skills_using(t.name, skills)
        if users:
            refs = ", ".join(f"[`{s['name']}`](../../../{s['path']})" for s in users)
            lines += [f"Used by skills: {refs}", ""]
    return "\n".join(lines)


def _server_dir(server: str) -> str:
    return f"{server}-mcp"


def render_tools_index(pages: dict[str, tuple[Any, list[Any]]]) -> str:
    total = sum(len(t) for _, t in pages.values())
    lines = [
        GENERATED_NOTE,
        "",
        "# Tool reference",
        "",
        f"**{total} tools across {len(pages)} MCP servers**, harvested from the live "
        "FastMCP registries. Every tool returns the normalized "
        "[findings schema](../../explanation/findings-schema.md); every server follows "
        "the [thin-server pattern](../../explanation/architecture.md#the-server-pattern).",
        "",
        "Skills refer to tools by base name (`list_incidents`); runtimes prefix them "
        "(Hermes `mcp_f0-defender_list_incidents`, Claude Code "
        "`mcp__f0-defender__list_incidents`).",
        "",
        "| Server | Platform module | Tools | Gated writes |",
        "|---|---|---|---|",
    ]
    for server in sorted(pages):
        mcp, tools = pages[server]
        gated = sum(1 for t in tools if _is_gated(t))
        lines.append(
            f"| [`{mcp.name}`]({server}.md) | `{SERVER_MODULES[server]}` | {len(tools)} | "
            f"{gated or '—'} |"
        )
    lines.append("")
    return "\n".join(lines)


# ── driver ──────────────────────────────────────────────────────────────


async def build_outputs() -> dict[Path, str]:
    skills = load_skills()
    pages: dict[str, tuple[Any, list[Any]]] = {}
    for server, module_name in SERVER_MODULES.items():
        module = importlib.import_module(module_name)
        pages[server] = (module.mcp, await module.mcp.list_tools())
    out: dict[Path, str] = {SKILLS_MD: render_skills_catalog(skills)}
    out[TOOLS_DIR / "README.md"] = render_tools_index(pages)
    for server, (mcp, tools) in pages.items():
        out[TOOLS_DIR / f"{server}.md"] = render_server_page(server, mcp, tools, skills)
    return {p: s.rstrip("\n") + "\n" for p, s in out.items()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="exit 1 if any committed file is stale"
    )
    args = parser.parse_args()
    outputs = asyncio.run(build_outputs())
    stale = []
    for path, content in outputs.items():
        current = path.read_text(encoding="utf-8") if path.is_file() else None
        if current == content:
            continue
        stale.append(path.relative_to(ROOT).as_posix())
        if not args.check:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
    if args.check and stale:
        print("STALE generated docs (run: uv run python scripts/gen_docs.py):")
        for s in stale:
            print(f"  {s}")
        return 1
    print(f"{'stale' if args.check else 'wrote'}: {len(stale)} file(s); "
          f"up-to-date: {len(outputs) - len(stale)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
