from f0_sectools_core.reports.content import (
    BlockKind,
    MetricCard,
    ReportContent,
    Section,
)
from f0_sectools_core.reports.emit import to_html, to_markdown
from f0_sectools_core.schema.findings import Finding, FindingType, Severity


def _content() -> ReportContent:
    finding = Finding(source="tenable", finding_type=FindingType.risk,
                      severity=Severity.critical, title="3 critical vulns exposed")
    return ReportContent(
        persona="ciso", language="en", tier="executive",
        title="Executive Risk Briefing", subtitle="Prepared for the CISO · Contoso",
        sections=[
            Section(BlockKind.narrative, "Executive summary", "executive",
                    text="Posture is moderate. Token: eyJhbGSECRETPAYLOAD0123456789abcdef."),
            Section(BlockKind.metric_grid, "Posture at a glance", "executive",
                    metrics=[MetricCard("Config hardening", "62%", "needs-work")]),
            Section(BlockKind.finding_rollup, "Top risks", "executive", findings=[finding]),
            Section(BlockKind.open_questions, "Open questions", "executive",
                    items=["Is 61% device compliance acceptable?"]),
            Section(BlockKind.provenance, "Provenance", "executive",
                    text="Generated 2026-07-24 · 8 platforms · 3 findings"),
        ],
    )


def test_markdown_has_title_sections_and_findings():
    md = to_markdown(_content())
    assert md.startswith("# Executive Risk Briefing")
    assert "## Posture at a glance" in md
    assert "62%" in md
    assert "3 critical vulns exposed" in md
    assert "Is 61% device compliance acceptable?" in md


def test_html_is_self_contained_and_has_severity_class():
    html = to_html(_content())
    assert "<style>" in html and "@page" in html          # inlined CSS
    assert "report--executive" in html
    assert "metric__value" in html
    head = html.split("</style>")[0].replace("https://", "")
    assert "http" not in head  # no external URLs in head


def test_planted_secret_is_redacted_in_both_emitters():
    c = _content()
    md = to_markdown(c)
    html = to_html(c)
    assert "SECRETPAYLOAD" not in md
    assert "SECRETPAYLOAD" not in html
