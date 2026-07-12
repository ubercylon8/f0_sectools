"""Persona renderers: turn a Finding (or list) into audience-shaped Markdown text.

Deterministic and model-free — the same input yields the same output. Every
rendered string passes through core redaction as a defense-in-depth net before
it is returned (Critical Rule 3).
"""
from __future__ import annotations

from enum import StrEnum

from f0_sectools_core.redaction.redact import redact_text
from f0_sectools_core.schema.findings import Finding, Reference


class Persona(StrEnum):
    soc_analyst = "soc_analyst"
    security_engineer = "security_engineer"
    ciso = "ciso"
    threat_hunter = "threat_hunter"
    detection_engineer = "detection_engineer"


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_NO_FINDINGS = "No findings."


class Renderer:
    """Base renderer with generic defaults. Personas override the two hooks."""

    persona: Persona = Persona.soc_analyst

    # ── public template methods ──────────────────────────────────────
    def render_finding(self, finding: Finding) -> str:
        return redact_text(self._finding_body(finding))

    def render_findings(self, findings: list[Finding]) -> str:
        if not findings:
            return redact_text(_NO_FINDINGS)
        return redact_text(self._aggregate(findings))

    # ── overridable hooks (generic defaults) ─────────────────────────
    def _finding_body(self, f: Finding) -> str:
        lines = [f"**[{self._severity_tag(f)}] {f.title}**", f"Target: {self._entity_str(f)}"]
        ev = self._evidence_lines(f)
        if ev:
            lines.append("Evidence:")
            lines.extend(ev)
        if f.recommended_action is not None:
            lines.append(f"Recommended: {f.recommended_action.summary}")
        refs = self._reference_lines(f)
        if refs:
            lines.append("References: " + ", ".join(refs))
        return "\n".join(lines)

    def _aggregate(self, findings: list[Finding]) -> str:
        return "\n\n".join(self._finding_body(f) for f in self._sort_by_severity(findings))

    # ── shared helpers ───────────────────────────────────────────────
    @staticmethod
    def _severity_tag(f: Finding) -> str:
        return f.severity.value.upper()

    @staticmethod
    def _entity_str(f: Finding) -> str:
        e = f.entity
        if e is None:
            return "unspecified target"
        if e.name:
            return f"{e.kind.value}: {e.name} ({e.id})"
        return f"{e.kind.value}: {e.id}"

    @staticmethod
    def _evidence_lines(f: Finding) -> list[str]:
        return [f"- {ev.key}: {ev.value}" for ev in f.evidence]

    @staticmethod
    def _reference_str(ref: Reference) -> str:
        if ref.url:
            return f"[{ref.type}:{ref.id}]({ref.url})"
        return f"{ref.type}:{ref.id}"

    def _reference_lines(self, f: Finding) -> list[str]:
        return [self._reference_str(r) for r in f.references]

    @staticmethod
    def _mitre_refs(f: Finding) -> list[Reference]:
        return [r for r in f.references if r.type == "mitre"]

    @staticmethod
    def _sort_by_severity(findings: list[Finding]) -> list[Finding]:
        return sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.severity.value, 99))

    @staticmethod
    def _sort_by_severity_then_time(findings: list[Finding]) -> list[Finding]:
        return sorted(findings, key=lambda f: (
            _SEVERITY_ORDER.get(f.severity.value, 99),
            f.observed_at is None,
            f.observed_at or "",
        ))

    @staticmethod
    def _sort_by_time(findings: list[Finding]) -> list[Finding]:
        return sorted(findings, key=lambda f: (f.observed_at is None, f.observed_at or ""))

    @staticmethod
    def _severity_counts(findings: list[Finding]) -> str:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        ordered = sorted(counts.items(), key=lambda kv: _SEVERITY_ORDER.get(kv[0], 99))
        return ", ".join(f"{n} {sev}" for sev, n in ordered)

    @staticmethod
    def _source_counts(findings: list[Finding]) -> str:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.source] = counts.get(f.source, 0) + 1
        return ", ".join(f"{n} {src}" for src, n in sorted(counts.items()))
