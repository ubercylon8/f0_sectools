from f0_sectools_core.reports.content import BlockKind
from f0_sectools_core.reports.sections import (
    SECTION_MAPS,
    TIER,
    FindingGroup,
    group_findings,
    is_not_assessed,
)
from f0_sectools_core.schema.findings import Finding, FindingType, Severity


def test_group_findings_keeps_every_real_source():
    # Regression: the old source-based buckets silently dropped any finding whose
    # source wasn't in the persona's bucket, so an operational report showed only
    # part of what was gathered.
    vuln = Finding(source="tenable", finding_type=FindingType.risk,
                   severity=Severity.critical, title="3 critical vulns")
    alert = Finding(source="defender", finding_type=FindingType.alert,
                    severity=Severity.high, title="Suspicious PowerShell")
    weak = Finding(source="projectachilles", finding_type=FindingType.risk,
                   severity=Severity.medium, title="Weak technique T1059")
    grouped = group_findings([vuln, alert, weak], "detection_engineer")
    assert grouped[FindingGroup.all] == [vuln, alert, weak]
    assert grouped[FindingGroup.top_risks] == [vuln, alert, weak]


def test_finding_group_has_only_the_consumed_buckets():
    assert {g.value for g in FindingGroup} == {"posture", "top_risks", "all"}


def test_operational_sections_render_all_gathered_findings():
    for persona in ("detection_engineer", "threat_hunter", "security_engineer"):
        table = [s for s in SECTION_MAPS[persona] if s.kind is BlockKind.finding_table]
        assert table, persona
        assert all(s.group is FindingGroup.all for s in table), persona


def test_all_four_personas_have_maps():
    assert set(SECTION_MAPS) == {"ciso", "detection_engineer", "threat_hunter", "security_engineer"}


def test_ciso_is_executive_tier_and_has_expected_section_order():
    specs = SECTION_MAPS["ciso"]
    assert TIER["ciso"] == "executive"
    kinds = [s.kind for s in specs]
    assert kinds == [
        BlockKind.narrative,      # executive summary
        BlockKind.metric_grid,    # posture at a glance
        BlockKind.finding_rollup, # top risks
        BlockKind.coverage,       # scope & coverage
        BlockKind.open_questions,
        BlockKind.provenance,
    ]


def test_operational_personas_use_finding_table():
    for persona in ("detection_engineer", "threat_hunter", "security_engineer"):
        assert TIER[persona] == "operational"
        kinds = [s.kind for s in SECTION_MAPS[persona]]
        assert BlockKind.finding_table in kinds
        assert BlockKind.metric_grid not in kinds  # operational tier is finding-forward


def test_is_not_assessed_detects_permission_missing():
    dark = Finding.permission_missing("defender", "SecurityEvents.Read.All", "secure score")
    assert is_not_assessed(dark) is True
    real = Finding(source="defender", finding_type=FindingType.risk,
                   severity=Severity.high, title="Device compliance gap")
    assert is_not_assessed(real) is False
