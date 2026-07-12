"""Persona renderers: SOC analyst, security engineer, CISO, threat hunter, detection engineer.

Public API — a deterministic, model-free presentation layer that turns the shared
Finding schema into audience-shaped Markdown text, one shape per audience. The
structured finding is always the source of truth; this is optional polish rendered
from it, never a different data contract.
"""
from __future__ import annotations

from f0_sectools_core.schema.findings import Finding

from .base import Persona, Renderer
from .personas import REGISTRY, get_renderer

__all__ = ["Persona", "Renderer", "get_renderer", "render_finding", "render_findings", "REGISTRY"]


def render_finding(finding: Finding, persona: Persona | str = Persona.soc_analyst) -> str:
    """Render one finding as Markdown text for the given persona."""
    return get_renderer(persona).render_finding(finding)


def render_findings(findings: list[Finding], persona: Persona | str = Persona.soc_analyst) -> str:
    """Render a list of findings as Markdown text for the given persona."""
    return get_renderer(persona).render_findings(findings)
