"""Emit a ReportContent as Markdown or self-contained HTML.

Every string written passes through redact_text (narrative prose included).
Finding bodies reuse the persona renderers so presentation stays DRY. The HTML
inlines the theme CSS so the page — and the PDF WeasyPrint renders from it — has
no external dependencies (the local-only guarantee).
"""
from __future__ import annotations

import html as _html

from f0_sectools_core.redaction.redact import redact_text
from f0_sectools_core.renderers import Persona, render_findings
from f0_sectools_core.schema.findings import Finding

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


def _persona(content: ReportContent) -> Persona:
    return Persona(content.persona)


# ── Markdown ─────────────────────────────────────────────────────────
def to_markdown(content: ReportContent) -> str:
    lines: list[str] = [f"# {_r(content.title)}", "", f"*{_r(content.subtitle)}*", ""]
    for s in content.sections:
        lines.append(f"## {_r(s.title)}")
        lines.append("")
        lines.extend(_md_body(s, content))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _md_body(s: Section, content: ReportContent) -> list[str]:
    if s.kind is BlockKind.metric_grid:
        return [f"- **{_r(m.label)}:** {_r(m.value)} ({_r(m.state)})" for m in s.metrics]
    if s.kind in (BlockKind.finding_rollup, BlockKind.finding_table):
        lines: list[str] = []
        if s.text.strip():
            lines.append(_r(s.text))
            lines.append("")
        if not s.findings:
            lines.append("_No findings in this window._")
        else:
            lines.append(render_findings(s.findings, _persona(content)))
        return lines
    if s.kind is BlockKind.open_questions:
        return [f"{i}. {_r(q)}" for i, q in enumerate(s.items, 1)]
    if s.kind is BlockKind.coverage:
        return [f"- {_r(item)}" for item in s.items] or [_r(s.text)]
    # narrative / provenance
    return [_r(s.text)]


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
        body.extend(_html_body(s, content))
        body.append("</section>")
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<style>{inline_css(content.tier)}</style></head>"
        f"<body class='{tier_class}'>{''.join(body)}</body></html>"
    )


def _e(text: str) -> str:
    """Redact then HTML-escape."""
    return _html.escape(_r(text))


def _html_body(s: Section, content: ReportContent) -> list[str]:
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
            out.extend(_finding_row(f) for f in _sorted(s.findings))
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
    return (
        f'<div><div class="metric__value">{_e(m.value)}</div>'
        f'<div class="metric__label">{_e(m.label)} · '
        f'<span class="metric__state--{state}">{_e(m.state)}</span></div></div>'
    )


def _finding_row(f: Finding) -> str:
    sev = _SEV_CLASS.get(f.severity.value, "info")
    meta = f"{f.source} · {f.severity.value}"
    return (
        f'<div class="finding finding--{sev}">'
        f'<div class="finding__title">{_e(f.title)}</div>'
        f'<div class="finding__meta">{_e(meta)}</div></div>'
    )


def _sorted(findings: list[Finding]) -> list[Finding]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(findings, key=lambda f: order.get(f.severity.value, 99))
