from f0_sectools_core.schema.findings import (
    Entity,
    EntityKind,
    Evidence,
    Finding,
    FindingType,
    RecommendedAction,
    Severity,
)


def test_finding_roundtrips_to_dict():
    f = Finding(
        source="defender",
        finding_type=FindingType.incident,
        severity=Severity.high,
        title="Multi-stage incident on web-01",
        entity=Entity(kind=EntityKind.host, id="web-01"),
        evidence=[Evidence(key="alerts", value="3")],
        recommended_action=RecommendedAction(summary="Investigate incident"),
    )
    d = f.model_dump()
    assert d["schema_version"] == "1.0"
    assert d["severity"] == "high"
    assert d["entity"]["kind"] == "host"
    assert d["recommended_action"]["gated_action"] is None


def test_permission_missing_helper():
    f = Finding.permission_missing("entra", "IdentityRiskyUser.Read.All", "risky users")
    assert f.severity == Severity.info
    assert f.finding_type == FindingType.posture
    assert "IdentityRiskyUser.Read.All" in f.title
