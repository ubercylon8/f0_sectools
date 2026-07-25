from f0_sectools_core.reports.content import (
    BlockKind,
    MetricCard,
    ReportContent,
    Section,
)
from f0_sectools_core.reports.emit import to_html, to_markdown
from f0_sectools_core.schema.findings import (
    Entity,
    EntityKind,
    Evidence,
    Finding,
    FindingType,
    Reference,
    Severity,
)


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


def test_md_metric_line_leads_with_compact_value_and_carries_detail():
    m = MetricCard("Config hardening", "62%", "needs-work",
                    detail="Microsoft Secure Score 1130/1816")
    content = ReportContent(
        persona="ciso", language="en", tier="executive",
        title="Report", subtitle="Sub",
        sections=[Section(BlockKind.metric_grid, "Posture at a glance", "executive",
                          metrics=[m])],
    )
    md = to_markdown(content)
    assert "- **62%** — Config hardening (needs-work) · Microsoft Secure Score 1130/1816" in md


def test_html_metric_tile_has_value_and_detail():
    m = MetricCard("Config hardening", "62%", "needs-work",
                    detail="Microsoft Secure Score 1130/1816")
    content = ReportContent(
        persona="ciso", language="en", tier="executive",
        title="Report", subtitle="Sub",
        sections=[Section(BlockKind.metric_grid, "Posture at a glance", "executive",
                          metrics=[m])],
    )
    html = to_html(content)
    assert '<div class="metric__value">62%</div>' in html
    assert '<div class="metric__detail">Microsoft Secure Score 1130/1816</div>' in html


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


def test_metric_state_is_redacted_and_escaped_in_html_class_attr():
    """A MetricCard.state is used to build a CSS class name in _metric_card.

    That copy must go through the same redact-then-escape path as every other
    emitted string — an unredacted/unescaped state could both leak a secret
    and break out of the class attribute into live HTML.
    """
    breakout = 'x"><script>alert(1)</script'
    metric = MetricCard("Config hardening", "62%",
                         breakout + " eyJhbGSECRETPAYLOAD0123456789abcdef")
    content = ReportContent(
        persona="ciso", language="en", tier="executive",
        title="Report", subtitle="Sub",
        sections=[Section(BlockKind.metric_grid, "Posture", "executive", metrics=[metric])],
    )
    html = to_html(content)
    assert "<script>" not in html
    assert '"><script' not in html
    assert "SECRETPAYLOAD" not in html


def _op_finding() -> Finding:
    return Finding(
        source="tenable", finding_type=FindingType.risk, severity=Severity.critical,
        title="3 internet-exposed critical vulnerabilities",
        evidence=[Evidence(key="cvss", value="9.8"), Evidence(key="exposed_assets", value="3")],
        references=[Reference(type="mitre", id="T1190"), Reference(type="cve", id="CVE-2026-1")],
    )


def _op_content() -> ReportContent:
    return ReportContent(
        persona="detection_engineer", language="en", tier="operational",
        title="Security Operations Report", subtitle="Prepared for Detection Engineering",
        sections=[Section(BlockKind.finding_table, "Findings", "operational",
                          findings=[_op_finding()])],
    )


def _exec_content() -> ReportContent:
    f = Finding(source="intune", finding_type=FindingType.risk, severity=Severity.high,
                title="Device compliance gap",
                entity=Entity(kind=EntityKind.tenant, id="t1", name="39% of devices non-compliant"))
    return ReportContent(
        persona="ciso", language="en", tier="executive",
        title="Executive Risk Briefing", subtitle="Prepared for the CISO",
        sections=[Section(BlockKind.finding_rollup, "Top risks", "executive", findings=[f])],
    )


def test_operational_rows_carry_source_mitre_and_all_evidence_md():
    md = to_markdown(_op_content())
    assert ("**[CRITICAL]** 3 internet-exposed critical vulnerabilities — "
            "tenable · ATT&CK: T1190") in md
    assert "cvss: 9.8" in md
    assert "exposed_assets: 3" in md          # unbounded — every evidence pair present


def test_operational_rows_carry_evidence_and_mitre_html():
    html = to_html(_op_content())
    assert "finding--critical" in html
    assert "ATT&amp;CK: T1190" in html   # _e() HTML-escapes; "&" must stay escaped
    assert "finding__evidence" in html
    assert "cvss: 9.8" in html


def test_executive_rows_are_compact_no_evidence_no_mitre():
    md = to_markdown(_exec_content())
    html = to_html(_exec_content())
    # one grounded line, using the entity name as the clause
    assert "**[HIGH]** Device compliance gap — 39% of devices non-compliant" in md
    # executive tier shows neither evidence keys nor ATT&CK
    assert "ATT&CK" not in md and "ATT&CK" not in html
    # the CSS class name itself is always present in the inlined <style> block
    # (report.css is shared across tiers) — check the rendered body, not the head
    body_html = html.split("</style>", 1)[-1]
    assert "finding__evidence" not in body_html


def test_grounding_clause_prefers_headline_over_entity_and_evidence():
    f = Finding(
        source="tenable", finding_type=FindingType.risk, severity=Severity.critical,
        title="3 internet-exposed critical vulnerabilities",
        evidence=[Evidence(key="headline", value="3 critical"), Evidence(key="cvss", value="9.8")],
        entity=Entity(kind=EntityKind.tenant, id="t1", name="some other clause"),
    )
    content = ReportContent(
        persona="ciso", language="en", tier="executive",
        title="Executive Risk Briefing", subtitle="Prepared for the CISO",
        sections=[Section(BlockKind.finding_rollup, "Top risks", "executive", findings=[f])],
    )
    md = to_markdown(content)
    assert "3 internet-exposed critical vulnerabilities — 3 critical" in md
    assert "some other clause" not in md


def test_grounding_clause_skips_headline_already_folded_into_title():
    f = Finding(
        source="intune", finding_type=FindingType.risk, severity=Severity.high,
        title="39% of managed devices non-compliant",
        evidence=[Evidence(key="headline", value="39%")],
        entity=Entity(kind=EntityKind.tenant, id="t1", name="39% of devices non-compliant"),
    )
    content = ReportContent(
        persona="ciso", language="en", tier="executive",
        title="Executive Risk Briefing", subtitle="Prepared for the CISO",
        sections=[Section(BlockKind.finding_rollup, "Top risks", "executive", findings=[f])],
    )
    md = to_markdown(content)
    # headline "39%" is already substring of the title, so grounding falls through
    # to the entity name instead of repeating it
    assert "39% of managed devices non-compliant — 39% of devices non-compliant" in md


def test_operational_rows_omit_headline_sub_bullet():
    f = Finding(
        source="tenable", finding_type=FindingType.risk, severity=Severity.critical,
        title="3 internet-exposed critical vulnerabilities",
        evidence=[Evidence(key="headline", value="3 critical"), Evidence(key="cvss", value="9.8")],
    )
    content = ReportContent(
        persona="detection_engineer", language="en", tier="operational",
        title="Security Operations Report", subtitle="Prepared for Detection Engineering",
        sections=[Section(BlockKind.finding_table, "Findings", "operational", findings=[f])],
    )
    md = to_markdown(content)
    html = to_html(content)
    assert "- headline: 3 critical" not in md
    assert "headline: 3 critical" not in html
    assert "cvss: 9.8" in md and "cvss: 9.8" in html


def test_no_chat_aggregate_heading_leaks_into_report():
    # The old render_findings(ciso) path injected a "## Security posture rollup"
    # heading inside the section body; report-owned rows must not.
    assert "Security posture rollup" not in to_markdown(_exec_content())


def test_evidence_secret_hinting_value_redacted_in_both_emitters():
    # A short, non-token-shaped secret under a secret-hinting evidence key won't
    # match SECRET_VALUE_PATTERNS; the render path must still blank it (key-hint
    # redaction via redact_finding), since the report is a shared artifact.
    from f0_sectools_core.reports.content import BlockKind, ReportContent, Section
    from f0_sectools_core.reports.emit import to_html, to_markdown
    from f0_sectools_core.schema.findings import (
        Evidence,
        Finding,
        FindingType,
        Severity,
    )

    f = Finding(
        source="defender", finding_type=FindingType.incident, severity=Severity.high,
        title="Token stashed in evidence",
        evidence=[Evidence(key="api_key", value="shortOpaque123"),
                  Evidence(key="host", value="web-01.corp.local")],
    )
    content = ReportContent(
        persona="detection_engineer", language="en", tier="operational",
        title="Security Operations Report", subtitle="Prepared for Detection Engineering",
        sections=[Section(BlockKind.finding_table, "Findings", "operational", findings=[f])],
    )
    md = to_markdown(content)
    html = to_html(content)
    assert "shortOpaque123" not in md and "shortOpaque123" not in html  # secret blanked
    assert "web-01.corp.local" in md and "web-01.corp.local" in html    # benign evidence kept


def test_unknown_tier_fails_loud():
    # An unknown tier must raise, never silently fall through to the dense
    # (evidence + MITRE) render path.
    import pytest
    from f0_sectools_core.reports.content import BlockKind, ReportContent, Section
    from f0_sectools_core.reports.emit import to_markdown
    from f0_sectools_core.schema.findings import Finding, FindingType, Severity

    f = Finding(source="tenable", finding_type=FindingType.risk, severity=Severity.low,
                title="x")
    content = ReportContent(
        persona="ciso", language="en", tier="bogus",
        title="t", subtitle="s",
        sections=[Section(BlockKind.finding_table, "Findings", "bogus", findings=[f])],
    )
    with pytest.raises(ValueError, match="unknown report tier"):
        to_markdown(content)
