"""Emit a ReportContent as Markdown or self-contained HTML.

Every string written passes through redact_text (narrative prose included).
Finding rows are report-owned and tier-aware, so Markdown and HTML stay in step.
The HTML inlines the theme CSS so the page — and the PDF WeasyPrint renders from
it — has no external dependencies (the local-only guarantee).
"""
from __future__ import annotations

import html as _html

from f0_sectools_core.redaction.redact import redact_finding, redact_text
from f0_sectools_core.schema.findings import Evidence, Finding

from .content import BlockKind, MetricCard, ReportContent, Section
from .theme import inline_css

_SEV_CLASS = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
}


def _r(text: str) -> str:
    return redact_text(text)


# ── Markdown ─────────────────────────────────────────────────────────
def to_markdown(content: ReportContent) -> str:
    lines: list[str] = [f"# {_r(content.title)}", "", f"*{_r(content.subtitle)}*", ""]
    for s in content.sections:
        lines.append(f"## {_r(s.title)}")
        lines.append("")
        lines.extend(_md_body(s))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _md_body(s: Section) -> list[str]:
    if s.kind is BlockKind.metric_grid:
        return [_md_metric(m) for m in s.metrics]
    if s.kind in (BlockKind.finding_rollup, BlockKind.finding_table):
        lines: list[str] = []
        if s.text.strip():
            lines.append(_r(s.text))
            lines.append("")
        if not s.findings:
            lines.append("_No findings in this window._")
        else:
            lines.extend(_md_findings(s.findings, s.tier))
        return lines
    if s.kind is BlockKind.open_questions:
        return [f"{i}. {_r(q)}" for i, q in enumerate(s.items, 1)]
    if s.kind is BlockKind.coverage:
        return [f"- {_r(item)}" for item in s.items] or [_r(s.text)]
    # narrative / provenance
    return [_r(s.text)]


def _md_metric(m: MetricCard) -> str:
    line = f"- **{_r(m.value)}** — {_r(m.label)} ({_r(m.state)})"
    if m.detail:
        line += f" · {_r(m.detail)}"
    return line


# ── HTML ─────────────────────────────────────────────────────────────
def to_html(content: ReportContent) -> str:
    tier_class = f"report--{content.tier}"
    body: list[str] = [
        '<div class="report__cover">',
        '<div class="report__kicker">F0RT1KA · SECURITY POSTURE</div>',
        f'<div class="report__title">{_e(content.title)}</div>',
        f'<div class="report__subtitle">{_e(content.subtitle)}</div>',
        "</div>",
    ]
    for s in content.sections:
        body.append('<section class="report__section">')
        body.append(f'<div class="report__h">{_e(s.title)}</div>')
        body.extend(_html_body(s))
        body.append("</section>")
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<style>{inline_css(content.tier)}</style></head>"
        f"<body class='{tier_class}'>{''.join(body)}</body></html>"
    )


def _e(text: str) -> str:
    """Redact then HTML-escape."""
    return _html.escape(_r(text))


def _html_body(s: Section) -> list[str]:
    if s.kind is BlockKind.metric_grid:
        cards = "".join(_metric_card(m) for m in s.metrics)
        return [f'<div class="metric-grid">{cards}</div>']
    if s.kind in (BlockKind.finding_rollup, BlockKind.finding_table):
        out: list[str] = []
        if s.text.strip():
            out.append(f"<p>{_e(s.text)}</p>")
        if not s.findings:
            out.append('<p><em>No findings in this window.</em></p>')
        else:
            out.extend(_html_findings(s.findings, s.tier))
        return out
    if s.kind is BlockKind.open_questions:
        return [f'<div class="oq"><b>{i}.</b> {_e(q)}</div>' for i, q in enumerate(s.items, 1)]
    if s.kind is BlockKind.coverage:
        inner = "".join(f"<p>{_e(item)}</p>" for item in s.items) or f"<p>{_e(s.text)}</p>"
        return [f'<div class="coverage">{inner}</div>']
    if s.kind is BlockKind.provenance:
        return [f'<div class="provenance">{_e(s.text)}</div>']
    return [f"<p>{_e(s.text)}</p>"]


def _metric_card(m: MetricCard) -> str:
    state = _e(m.state).replace(" ", "-")
    detail = f'<div class="metric__detail">{_e(m.detail)}</div>' if m.detail else ""
    return (
        '<div class="metric">'
        f'<div class="metric__label">{_e(m.label)}</div>'
        f'<div class="metric__value">{_e(m.value)}</div>'
        f'<div class="metric__state metric__state--{state}">{_e(m.state)}</div>'
        f'{detail}</div>'
    )


_TIERS = ("executive", "operational")


def _sorted(findings: list[Finding]) -> list[Finding]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(findings, key=lambda f: order.get(f.severity.value, 99))


def _prepare(findings: list[Finding], tier: str) -> list[Finding]:
    """Key-hint-redact each finding (the report is a shared artifact — the render
    path self-guarantees redaction regardless of what the caller did; redact_finding
    is idempotent), then severity-sort. Fail loud on an unknown tier so a mismatch
    never silently falls through to the dense (evidence + MITRE) render path."""
    if tier not in _TIERS:
        raise ValueError(f"unknown report tier: {tier!r}")
    return _sorted([redact_finding(f) for f in findings])


def _sev_tag(f: Finding) -> str:
    return f.severity.value.upper()


def _mitre_ids(f: Finding) -> list[str]:
    return [r.id for r in f.references if r.type == "mitre"]


def _headline(f: Finding) -> str:
    return next((e.value for e in f.evidence if e.key == "headline"), "")


def _display_evidence(f: Finding) -> list[Evidence]:
    """Evidence to show in operational rows — the 'headline' key is a tile hint, not detail."""
    return [e for e in f.evidence if e.key != "headline"]


def _grounding_clause(f: Finding) -> str:
    """One short grounding phrase for an executive row: the headline (unless
    already folded into the title), else entity name, else the first
    (non-headline) evidence key: value, else empty."""
    hl = _headline(f)
    if hl and hl not in f.title:
        return hl
    if f.entity is not None and f.entity.name:
        return f.entity.name
    for e in _display_evidence(f):
        return f"{e.key}: {e.value}"
    return ""


def _md_findings(findings: list[Finding], tier: str) -> list[str]:
    lines: list[str] = []
    for f in _prepare(findings, tier):
        if tier == "executive":
            clause = _grounding_clause(f)
            suffix = f" — {clause}" if clause else ""
            lines.append(_r(f"- **[{_sev_tag(f)}]** {f.title}{suffix}"))
        else:
            mitre = _mitre_ids(f)
            meta = f.source + (f" · ATT&CK: {', '.join(mitre)}" if mitre else "")
            lines.append(_r(f"- **[{_sev_tag(f)}]** {f.title} — {meta}"))
            lines.extend(_r(f"  - {ev.key}: {ev.value}") for ev in _display_evidence(f))
    return lines


def _html_findings(findings: list[Finding], tier: str) -> list[str]:
    out: list[str] = []
    for f in _prepare(findings, tier):
        sev = _SEV_CLASS.get(f.severity.value, "info")
        parts = [
            f'<div class="finding finding--{sev}">',
            f'<div class="finding__title">[{_e(_sev_tag(f))}] {_e(f.title)}</div>',
        ]
        if tier == "executive":
            clause = _grounding_clause(f)
            if clause:
                parts.append(f'<div class="finding__meta">{_e(clause)}</div>')
        else:
            mitre = _mitre_ids(f)
            meta = f.source + (f" · ATT&CK: {', '.join(mitre)}" if mitre else "")
            parts.append(f'<div class="finding__meta">{_e(meta)}</div>')
            parts.extend(
                f'<div class="finding__evidence">{_e(f"{ev.key}: {ev.value}")}</div>'
                for ev in _display_evidence(f)
            )
        parts.append("</div>")
        out.append("".join(parts))
    return out
