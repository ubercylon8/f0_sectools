"""Load the packaged report CSS and select a tier.

The CSS is a package data file read via importlib.resources so it works from an
installed wheel. Inlining it into the HTML keeps the PDF self-contained (no
external asset fetch — the local-only guarantee).
"""
from __future__ import annotations

from importlib.resources import files

TIERS: tuple[str, str] = ("executive", "operational")


def inline_css(tier: str) -> str:
    if tier not in TIERS:
        raise ValueError(f"Unknown tier '{tier}'. Valid tiers: {', '.join(TIERS)}")
    css = (files("f0_sectools_core.reports.assets") / "report.css").read_text(encoding="utf-8")
    tier_block = f":root {{ --tier: \"{tier}\"; }}\n"
    return tier_block + css
