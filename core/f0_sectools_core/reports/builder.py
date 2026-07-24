"""Assemble a ReportContent from gathered findings + parsed narrative, and emit.

Deterministic and platform-free. The persona's SECTION_MAPS drives section order
and tier; each data section is filled from grouped findings; narrative sections
carry the agent's prose. build_report is the package's single public entry point.
"""
from __future__ import annotations

from f0_sectools_core.schema.findings import Finding

from . import emit
from .content import BlockKind, ReportContent, ReportOutput, ScopeMeta, Section
from .i18n import label
from .narrative import parse_narrative
from .sections import SECTION_MAPS, TIER, group_findings

_PERSONAS = set(SECTION_MAPS)


def _normalize_persona(persona: str) -> str:
    key = persona.replace("-", "_")
    if key not in _PERSONAS:
        valid = ", ".join(sorted(_PERSONAS))
        raise ValueError(f"Unknown persona '{persona}'. Valid: {valid}")
    return key


def _title(lang: str, tier: str) -> str:
    key = "report_title_executive" if tier == "executive" else "report_title_operational"
    return label(lang, key)


def _subtitle(lang: str, persona: str, meta: ScopeMeta) -> str:
    prepared = label(lang, f"prepared_for_{persona}")
    generated = label(lang, "generated_locally")
    return f"{prepared} · {meta.tenant_label} · {meta.window_label} · {generated}"


def _coverage_items(lang: str, meta: ScopeMeta) -> list[str]:
    items: list[str] = []
    if meta.assessed:
        items.append(f"{label(lang, 'assessed')}: {', '.join(meta.assessed)}")
    if meta.not_assessed:
        items.append(f"{label(lang, 'not_assessed')}: {', '.join(meta.not_assessed)}")
    return items


def _provenance_text(lang: str, meta: ScopeMeta) -> str:
    n_platforms = len(meta.platforms_queried)
    return (
        f"{meta.generated_at} · {n_platforms} {label(lang, 'provenance_platforms')} · "
        f"{meta.findings_count} {label(lang, 'provenance_findings')} · "
        f"{label(lang, 'provenance_redacted')}"
    )


def build_report(
    persona: str,
    language: str,
    narrative: str,
    findings: list[Finding],
    scope_meta: ScopeMeta,
) -> ReportOutput:
    persona = _normalize_persona(persona)
    tier = TIER[persona]
    parsed = parse_narrative(narrative)
    grouped = group_findings(findings, persona)

    sections: list[Section] = []
    for spec in SECTION_MAPS[persona]:
        title = label(language, spec.title_key)
        if spec.kind is BlockKind.narrative:
            text = parsed.executive_summary or label(language, "no_findings")
            sections.append(Section(spec.kind, title, spec.tier, text=text))
        elif spec.kind is BlockKind.metric_grid:
            metrics = list(scope_meta.pillar_metrics)
            sections.append(Section(spec.kind, title, spec.tier, metrics=metrics))
        elif spec.kind in (BlockKind.finding_rollup, BlockKind.finding_table):
            group = grouped[spec.group] if spec.group is not None else []
            sections.append(Section(spec.kind, title, spec.tier,
                                    text=parsed.risk_framing, findings=list(group)))
        elif spec.kind is BlockKind.coverage:
            items = _coverage_items(language, scope_meta)
            sections.append(Section(spec.kind, title, spec.tier, items=items))
        elif spec.kind is BlockKind.open_questions:
            items = parsed.open_questions or [label(language, "open_questions_intro")]
            sections.append(Section(spec.kind, title, spec.tier, items=items))
        elif spec.kind is BlockKind.provenance:
            text = _provenance_text(language, scope_meta)
            sections.append(Section(spec.kind, title, spec.tier, text=text))

    content = ReportContent(
        persona=persona,
        language=language,
        tier=tier,
        title=_title(language, tier),
        subtitle=_subtitle(language, persona, scope_meta),
        sections=sections,
    )
    return ReportOutput(markdown=emit.to_markdown(content), html=emit.to_html(content))
