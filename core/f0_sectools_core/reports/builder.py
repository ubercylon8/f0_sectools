"""Assemble a ReportContent from gathered findings + parsed narrative, and emit.

Deterministic and platform-free. The persona's SECTION_MAPS drives section order
and tier; each data section is filled from grouped findings; narrative sections
carry the agent's prose. build_report is the package's single public entry point.
"""
from __future__ import annotations

from f0_sectools_core.schema.findings import Finding

from . import emit
from .content import BlockKind, MetricCard, ReportContent, ReportOutput, ScopeMeta, Section
from .i18n import group_label, label, state_label
from .narrative import parse_narrative
from .sections import SECTION_MAPS, TIER, group_findings

_PERSONAS = set(SECTION_MAPS)


def _normalize_persona(persona: str) -> str:
    key = persona.replace("-", "_")
    if key not in _PERSONAS:
        valid = ", ".join(sorted(_PERSONAS))
        raise ValueError(f"Unknown persona '{persona}'. Valid: {valid}")
    return key


def _title(lang: str, persona: str) -> str:
    return label(lang, f"report_title_{persona}")


def _subtitle(lang: str, persona: str, meta: ScopeMeta) -> str:
    prepared = label(lang, f"prepared_for_{persona}")
    generated = label(lang, "generated_locally")
    return f"{prepared} · {meta.tenant_label} · {meta.window_label} · {generated}"


def _localize_metric(lang: str, m: MetricCard) -> MetricCard:
    """Render a gather-produced card in the report's language.

    `label`/`state` arrive as identifiers from the gather layer; translate them
    for display while keeping `state` itself stable (emit derives the CSS class
    from it). `severity_counts`, when present, becomes the translated detail line.
    """
    detail = m.detail
    if m.severity_counts:
        detail = " · ".join(
            f"{count} {label(lang, f'sev_{sev}')}" for sev, count in m.severity_counts
        )
    elif detail:
        detail = _lookup_or_raw(lang, detail)
    return MetricCard(
        label=group_label(lang, m.label),
        value=m.value,
        state=m.state,
        detail=detail,
        state_label=state_label(lang, m.state),
        severity_counts=m.severity_counts,
    )


def _lookup_or_raw(lang: str, text: str) -> str:
    """Translate a detail that is exactly an i18n key; otherwise pass it through.

    Exact-match only — a CISO tile's detail is a finding title and must never be
    partially rewritten.
    """
    try:
        return label(lang, text)
    except KeyError:
        return text


def _coverage_items(lang: str, meta: ScopeMeta) -> list[str]:
    items: list[str] = []
    if meta.assessed:
        names = ", ".join(group_label(lang, g) for g in meta.assessed)
        items.append(f"{label(lang, 'assessed')}: {names}")
    if meta.not_assessed:
        names = ", ".join(group_label(lang, g) for g in meta.not_assessed)
        items.append(f"{label(lang, 'not_assessed')}: {names}")
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
            metrics = [_localize_metric(language, m) for m in scope_meta.pillar_metrics]
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
        title=_title(language, persona),
        subtitle=_subtitle(language, persona, scope_meta),
        sections=sections,
    )
    return ReportOutput(markdown=emit.to_markdown(content), html=emit.to_html(content))
