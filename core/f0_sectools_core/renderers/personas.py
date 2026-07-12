"""The five concrete persona renderers plus the registry and lookup."""
from __future__ import annotations

from f0_sectools_core.schema.findings import Finding

from .base import Persona, Renderer


class SocAnalystRenderer(Renderer):
    """Tactical, per-incident: what happened + the next triage step."""

    persona = Persona.soc_analyst

    def _finding_body(self, f: Finding) -> str:
        lines = [f"**[{self._severity_tag(f)}] {f.title}**", f"Target: {self._entity_str(f)}"]
        ev = self._evidence_lines(f)
        if ev:
            lines.append("What happened:")
            lines.extend(ev)
        if f.recommended_action is not None:
            step = f"Next step: {f.recommended_action.summary}"
            if f.recommended_action.gated_action:
                step += f" (gated action: {f.recommended_action.gated_action})"
            lines.append(step)
        return "\n".join(lines)

    def _aggregate(self, findings: list[Finding]) -> str:
        ordered = self._sort_by_severity_then_time(findings)
        header = f"{len(ordered)} findings ({self._severity_counts(ordered)})"
        return header + "\n\n" + "\n\n".join(self._finding_body(f) for f in ordered)


class SecurityEngineerRenderer(Renderer):
    """Config & hardening: a remediation checklist grouped by platform."""

    persona = Persona.security_engineer

    def _finding_body(self, f: Finding) -> str:
        fix = f.recommended_action.summary if f.recommended_action else f.title
        return f"- [ ] {fix} ({f.source}/{f.finding_type.value})"

    def _aggregate(self, findings: list[Finding]) -> str:
        groups: dict[str, list[Finding]] = {}
        for f in self._sort_by_severity(findings):
            groups.setdefault(f.source, []).append(f)
        lines = ["## Remediation checklist"]
        for source in sorted(groups):
            lines.append(f"### {source}")
            lines.extend(self._finding_body(f) for f in groups[source])
        return "\n".join(lines)


class CisoRenderer(Renderer):
    """Aggregate, business-framed: a severity/source rollup, no raw evidence."""

    persona = Persona.ciso

    def _finding_body(self, f: Finding) -> str:
        return f"- [{self._severity_tag(f)}] {f.title} — {self._entity_str(f)}"

    def _aggregate(self, findings: list[Finding]) -> str:
        top = self._sort_by_severity(findings)[:5]
        crit_high = sum(1 for f in findings if f.severity.value in ("critical", "high"))
        lines = [
            "## Security posture rollup",
            f"Total findings: {len(findings)}",
            f"By severity: {self._severity_counts(findings)}",
            f"By source: {self._source_counts(findings)}",
            "Top findings:",
        ]
        lines.extend(self._finding_body(f) for f in top)
        lines.append(f"Risk posture: {crit_high} critical/high finding(s) require attention.")
        return "\n".join(lines)


class ThreatHunterRenderer(Renderer):
    """Timeline & pivots: chronological, entities as pivots, IOCs + ATT&CK."""

    persona = Persona.threat_hunter

    def _finding_body(self, f: Finding) -> str:
        ts = f.observed_at or "unknown time"
        lines = [f"{ts} — [{self._severity_tag(f)}] {f.title}", f"Pivot: {self._entity_str(f)}"]
        ev = self._evidence_lines(f)
        if ev:
            lines.append("IOCs:")
            lines.extend(ev)
        mitre = self._mitre_refs(f)
        if mitre:
            lines.append("ATT&CK: " + ", ".join(self._reference_str(r) for r in mitre))
        return "\n".join(lines)

    def _aggregate(self, findings: list[Finding]) -> str:
        lines = ["## Timeline"]
        lines.extend(self._finding_body(f) for f in self._sort_by_time(findings))
        return "\n".join(lines)


class DetectionEngineerRenderer(Renderer):
    """Alert quality & coverage: grouped by ATT&CK technique; unmapped flagged."""

    persona = Persona.detection_engineer

    def _finding_body(self, f: Finding) -> str:
        mitre = self._mitre_refs(f)
        tag = ", ".join(self._reference_str(r) for r in mitre) if mitre else "unmapped"
        return f"- [{tag}] {f.title} ({self._severity_tag(f)}, source: {f.source})"

    def _aggregate(self, findings: list[Finding]) -> str:
        mapped: dict[str, list[Finding]] = {}
        unmapped: list[Finding] = []
        for f in self._sort_by_severity(findings):
            refs = self._mitre_refs(f)
            if refs:
                for r in refs:
                    mapped.setdefault(r.id, []).append(f)
            else:
                unmapped.append(f)
        lines = ["## Detection coverage by technique"]
        for tech_id in sorted(mapped):
            lines.append(f"### {tech_id}")
            lines.extend(f"- {f.title} ({self._severity_tag(f)})" for f in mapped[tech_id])
        if unmapped:
            lines.append("### unmapped (no ATT&CK reference)")
            lines.extend(f"- {f.title} ({self._severity_tag(f)})" for f in unmapped)
        return "\n".join(lines)


REGISTRY: dict[Persona, Renderer] = {
    Persona.soc_analyst: SocAnalystRenderer(),
    Persona.security_engineer: SecurityEngineerRenderer(),
    Persona.ciso: CisoRenderer(),
    Persona.threat_hunter: ThreatHunterRenderer(),
    Persona.detection_engineer: DetectionEngineerRenderer(),
}


def get_renderer(persona: Persona | str) -> Renderer:
    """Return the renderer for a persona, coercing a str; ValueError if unknown."""
    try:
        key = Persona(persona)
    except ValueError as e:
        valid = ", ".join(p.value for p in Persona)
        raise ValueError(f"Unknown persona '{persona}'. Valid personas: {valid}") from e
    return REGISTRY[key]
