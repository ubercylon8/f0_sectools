from f0_sectools_core.reports.content import BlockKind
from f0_sectools_core.reports.sections import (
    SECTION_MAPS,
    TIER,
    FindingGroup,
    group_findings,
    is_not_assessed,
)
from f0_sectools_core.schema.findings import Finding, FindingType, Severity


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


def test_group_findings_buckets_exposure_for_security_engineer():
    vuln = Finding(source="tenable", finding_type=FindingType.risk,
                   severity=Severity.critical, title="3 critical vulns exposed")
    grouped = group_findings([vuln], "security_engineer")
    assert vuln in grouped[FindingGroup.all]
