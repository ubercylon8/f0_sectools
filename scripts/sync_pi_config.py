"""Sync the local pi runtime config from this repo's templates.

Renders integrations/pi/mcp.json into ~/.pi/agent/mcp.json (placeholder path
-> this checkout, "uv" -> its absolute path) and symlinks ~/.pi/agent/AGENTS.md
to the repo copy so it can never drift. Idempotent — run it after every
`git pull`, or wire it as a local post-merge hook:

    echo 'uv run python scripts/sync_pi_config.py' >> .git/hooks/post-merge
    chmod +x .git/hooks/post-merge

Skills and persona prompts need no syncing: ~/.pi/agent/settings.json points
at the repo's skills/ and integrations/pi/prompts/ directories in place.

Usage (from the repo root):
    uv run python scripts/sync_pi_config.py [--pi-home ~/.pi/agent] [--check]

--check: exit 1 if anything would change, without writing (for scripts/CI-like
use on your own machine; the repo's CI never touches a live pi install).
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TEMPLATE = REPO / "integrations" / "pi" / "mcp.json"
AGENTS_MD = REPO / "integrations" / "pi" / "AGENTS.md"
PLACEHOLDER = "/ABSOLUTE/PATH/TO/sec-tools"


def render_mcp_json(template_text: str, repo_root: Path, uv_path: str) -> str:
    """Fill the template's placeholders for this machine. Must stay valid JSON."""
    text = template_text.replace(PLACEHOLDER, str(repo_root))
    text = text.replace('"command": "uv"', f'"command": "{uv_path}"')
    json.loads(text)  # fail loudly on a broken template, never install garbage
    return text


def merge_into_existing(rendered: str, target: Path) -> str:
    """Keep servers the live config has that this repo does not ship.

    A pi install is shared: this machine also carries `f0-library` from the
    sibling offensive-testing repo. Writing the rendered template wholesale
    deletes any such entry — the operator adds a server and silently loses a
    different one, the only trace being a .bak file they have no reason to read.

    Ownership is decided by whether an entry references this checkout, not by
    whether the template still names it. "Absent from the template" would keep a
    server we renamed or removed alive forever, pointing at a command that no
    longer exists — the same silent drift in the opposite direction.
    """
    if not target.is_file():
        return rendered
    try:
        existing = json.loads(target.read_text(encoding="utf-8")).get("mcpServers", {})
    except (ValueError, OSError):
        return rendered  # unreadable or not JSON: replace it rather than guess
    if not isinstance(existing, dict):
        return rendered
    config = json.loads(rendered)
    ours = config.get("mcpServers", {})
    marker = str(REPO)
    foreign = {
        name: entry
        for name, entry in existing.items()
        if name not in ours and marker not in json.dumps(entry)
    }
    if not foreign:
        return rendered
    config["mcpServers"] = {**foreign, **ours}
    return json.dumps(config, indent=2) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pi-home", default=str(Path.home() / ".pi" / "agent"))
    parser.add_argument("--check", action="store_true", help="report drift, write nothing")
    args = parser.parse_args(argv)

    pi_home = Path(args.pi_home).expanduser()
    if not pi_home.is_dir():
        print(f"pi home not found: {pi_home} — is pi installed?", file=sys.stderr)
        return 1

    uv_path = shutil.which("uv") or "uv"
    rendered = render_mcp_json(TEMPLATE.read_text(encoding="utf-8"), REPO, uv_path)
    changed = False

    target = pi_home / "mcp.json"
    rendered = merge_into_existing(rendered, target)
    if target.is_file() and target.read_text(encoding="utf-8") == rendered:
        print(f"mcp.json    up to date  ({target})")
    else:
        changed = True
        if args.check:
            print(f"mcp.json    WOULD UPDATE ({target})")
        else:
            if target.is_file():
                shutil.copy2(target, target.with_suffix(".json.bak"))
            target.write_text(rendered, encoding="utf-8")
            print(f"mcp.json    updated     ({target}, previous saved as .bak)")

    link = pi_home / "AGENTS.md"
    if link.is_symlink() and link.resolve() == AGENTS_MD.resolve():
        print(f"AGENTS.md   up to date  (symlink -> {AGENTS_MD})")
    else:
        changed = True
        if args.check:
            print(f"AGENTS.md   WOULD SYMLINK -> {AGENTS_MD}")
        else:
            if link.is_symlink():
                link.unlink()
            elif link.exists():
                backup = link.with_suffix(".md.bak")
                link.rename(backup)
                print(f"AGENTS.md   previous copy saved as {backup}")
            link.symlink_to(AGENTS_MD)
            print(f"AGENTS.md   symlinked   -> {AGENTS_MD}")

    if changed and not args.check:
        print("Restart pi (new session) to pick up the changes.")
    return 1 if (changed and args.check) else 0


if __name__ == "__main__":
    raise SystemExit(main())
