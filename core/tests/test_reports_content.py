from f0_sectools_core.reports.content import (
    BlockKind,
    MetricCard,
    ReportContent,
    ReportOutput,
    ScopeMeta,
    Section,
)


def test_section_defaults_are_independent():
    a = Section(kind=BlockKind.coverage, title="Scope", tier="executive")
    b = Section(kind=BlockKind.coverage, title="Scope", tier="executive")
    assert a.items == [] and a.metrics == [] and a.findings == []
    # frozen dataclass with default_factory: mutating one must not leak to the other
    assert a.items is not b.items


def test_metric_card_and_report_output_shapes():
    card = MetricCard(label="Config hardening", value="62%", state="needs-work")
    assert (card.label, card.value, card.state) == ("Config hardening", "62%", "needs-work")
    out = ReportOutput(markdown="# hi", html="<h1>hi</h1>")
    assert out.markdown == "# hi" and out.html == "<h1>hi</h1>"


def test_report_content_carries_ordered_sections():
    s1 = Section(kind=BlockKind.narrative, title="Summary", tier="executive", text="ok")
    content = ReportContent(
        persona="ciso", language="en", tier="executive",
        title="Executive Risk Briefing", subtitle="Prepared for the CISO",
        sections=[s1],
    )
    assert content.sections[0].kind is BlockKind.narrative
    assert [s.title for s in content.sections] == ["Summary"]


def test_scope_meta_fields():
    meta = ScopeMeta(
        generated_at="2026-07-24 14:22", tenant_label="Contoso",
        window_label="Trailing 7 days", platforms_queried=["defender"],
        findings_count=3, assessed=["Config hardening"], not_assessed=["Data risk"],
    )
    assert meta.findings_count == 3
    assert meta.pillar_metrics == []
