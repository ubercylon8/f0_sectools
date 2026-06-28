"""Validate every SKILL.md so the skill set stays portable as it grows.

Checks the agentskills.io essentials plus the Hermes constraint (description
≤ 60 chars), so a malformed or oversized skill fails CI instead of silently
breaking discovery in a runtime.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

SKILLS_DIR = Path(__file__).parent
SKILL_FILES = sorted(SKILLS_DIR.glob("**/SKILL.md"))
NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


def test_skills_exist():
    assert SKILL_FILES, "no SKILL.md files found under skills/"


@pytest.mark.parametrize("path", SKILL_FILES, ids=lambda p: str(p.relative_to(SKILLS_DIR)))
def test_skill_frontmatter_valid(path: Path):
    text = path.read_text()
    assert text.startswith("---\n"), f"{path}: missing YAML frontmatter"
    parts = text.split("---\n", 2)
    assert len(parts) == 3, f"{path}: malformed frontmatter delimiters"
    meta = yaml.safe_load(parts[1])

    # Required agentskills.io fields.
    assert isinstance(meta.get("name"), str) and NAME_RE.match(meta["name"]), (
        f"{path}: name must be lowercase kebab-case"
    )
    desc = meta.get("description")
    assert isinstance(desc, str) and desc, f"{path}: description required"
    # Hermes lists skills by description; keep it short enough to display.
    assert len(desc) <= 60, f"{path}: description is {len(desc)} chars (>60, Hermes limit)"
    assert isinstance(meta.get("version"), str), f"{path}: version required"

    # Body must carry the standard guidance sections.
    body = parts[2]
    for heading in ("## When to Use", "## Procedure", "## Verification"):
        assert heading in body, f"{path}: missing section '{heading}'"
