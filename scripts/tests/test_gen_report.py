import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/ importable
import report_gather  # noqa: E402
from f0_sectools_core.reports.content import ScopeMeta  # noqa: E402
from f0_sectools_core.schema.findings import Finding, FindingType, Severity  # noqa: E402


def test_gather_degrades_when_platform_unconfigured(monkeypatch):
    # Force every pillar factory to raise (no creds) → all not-assessed, still returns.
    async def boom(window_hours):
        raise ValueError("Missing required environment variables: DEFENDER_TENANT_ID")

    monkeypatch.setitem(report_gather.GATHER_MAP, "ciso",
                        {"Config hardening": boom, "Vulnerability exposure": boom})
    findings, meta = asyncio.run(report_gather.gather("ciso", 168))
    assert isinstance(meta, ScopeMeta)
    assert set(meta.not_assessed) >= {"Config hardening", "Vulnerability exposure"}
    assert meta.assessed == []  # nothing came back healthy
    # every dark pillar still produced a posture finding
    assert all(f.finding_type is FindingType.posture for f in findings)
    # the failure cause survives as redacted evidence, not silently dropped
    for f in findings:
        reasons = [e.value for e in f.evidence if e.key == "reason"]
        assert reasons and reasons[0]


def test_gather_collects_healthy_pillar(monkeypatch):
    async def ok(window_hours):
        return [Finding(source="defender", finding_type=FindingType.posture,
                        severity=Severity.info, title="Secure Score: 62%",
                        evidence=[{"key": "secure_score_pct", "value": "62"}])]

    monkeypatch.setitem(report_gather.GATHER_MAP, "ciso", {"Config hardening": ok})
    findings, meta = asyncio.run(report_gather.gather("ciso", 168))
    assert "Config hardening" in meta.assessed
    assert any("62%" in f.title for f in findings)


def test_metric_from_uses_headline_for_value_and_title_for_detail():
    from f0_sectools_core.schema.findings import Evidence

    findings = [Finding(
        source="defender", finding_type=FindingType.posture, severity=Severity.info,
        title="Secure Score: 62%",
        evidence=[Evidence(key="headline", value="62%"),
                  Evidence(key="secure_score_pct", value="62")],
    )]
    card = report_gather._metric_from("Config hardening", findings)
    assert card.value == "62%"
    assert card.detail == "Secure Score: 62%"
    assert card.state == "strong"


def test_gather_redacts_secret_hinting_evidence_from_findings(monkeypatch):
    # A pillar tool that emits a secret-hinting evidence key with a short,
    # non-token value must have it redacted before it can reach the shared report.
    from f0_sectools_core.schema.findings import Evidence

    async def leaky(window_hours):
        return [Finding(
            source="defender", finding_type=FindingType.posture, severity=Severity.info,
            title="Secure Score: 62%",
            evidence=[
                Evidence(key="secure_score_pct", value="62"),
                Evidence(key="client_secret", value="hunter2pw"),  # must be redacted
            ],
        )]

    monkeypatch.setitem(report_gather.GATHER_MAP, "ciso", {"Config hardening": leaky})
    findings, _meta = asyncio.run(report_gather.gather("ciso", 168))
    ev = {e.key: e.value for f in findings for e in f.evidence}
    assert ev["client_secret"] == "«redacted»"
    assert ev["secure_score_pct"] == "62"


def test_metric_from_no_headline_is_unquantified():
    # A real finding lacking a headline (e.g. an unclassified platform-error
    # finding) must render as unquantified — not a truncated title at tile size
    # nor a misleading "strong" state.
    from f0_sectools_core.schema.findings import Finding, FindingType, Severity

    f = Finding(source="tenable", finding_type=FindingType.posture, severity=Severity.info,
                title="Tenable authentication failed — vulnerability summary unavailable")
    card = report_gather._metric_from("Vulnerability exposure", [f])
    assert card.value == "—"
    assert card.state == "not-assessed"
    assert card.detail == f.title


def test_gather_map_has_all_four_personas():
    assert set(report_gather.GATHER_MAP) == {
        "ciso", "detection_engineer", "threat_hunter", "security_engineer",
    }


def test_ciso_map_is_the_six_pillars():
    assert list(report_gather.GATHER_MAP["ciso"]) == [
        "Config hardening", "Attack validation", "Vulnerability exposure",
        "Device compliance", "Data risk", "Endpoint coverage",
    ]


def test_detection_engineer_gathers_its_own_groups():
    groups = set(report_gather.GATHER_MAP["detection_engineer"])
    assert groups == {
        "Alerts (MITRE)", "Incidents", "Detection rules",
        "Endpoint detections", "Weak techniques",
    }
    # it must NOT be the CISO pillar set
    assert "Data risk" not in groups


def test_security_engineer_gathers_identity_and_exposure():
    groups = set(report_gather.GATHER_MAP["security_engineer"])
    assert {"Conditional access", "Privileged roles", "Risky users",
            "Vulnerability exposure", "Device compliance"} <= groups


def test_threat_hunter_gathers_incidents_and_detections():
    groups = set(report_gather.GATHER_MAP["threat_hunter"])
    assert {"Incidents", "Alerts (MITRE)", "Endpoint detections",
            "Endpoint coverage"} <= groups


def test_gather_runs_only_the_personas_groups(monkeypatch):
    async def ok(window_hours):
        return [Finding(source="defender", finding_type=FindingType.alert,
                        severity=Severity.high, title="Suspicious PowerShell")]

    monkeypatch.setitem(report_gather.GATHER_MAP, "detection_engineer",
                        {"Alerts (MITRE)": ok, "Weak techniques": ok})
    findings, meta = asyncio.run(report_gather.gather("detection-engineer", 168))
    assert set(meta.assessed) == {"Alerts (MITRE)", "Weak techniques"}
    assert len(findings) == 2


def test_gather_rejects_unknown_persona():
    import pytest
    with pytest.raises(ValueError, match="Unknown persona"):
        asyncio.run(report_gather.gather("nonsense", 168))


def test_operational_persona_gets_no_metric_tiles(monkeypatch):
    # Operational groups return lists, not one headline number — a tile would be
    # meaningless, so pillar_metrics stays empty for them (CISO-only).
    async def ok(window_hours):
        return [Finding(source="defender", finding_type=FindingType.alert,
                        severity=Severity.high, title="Suspicious PowerShell")]

    monkeypatch.setitem(report_gather.GATHER_MAP, "threat_hunter", {"Incidents": ok})
    _findings, meta = asyncio.run(report_gather.gather("threat-hunter", 168))
    assert meta.pillar_metrics == []


def test_ciso_still_gets_metric_tiles(monkeypatch):
    from f0_sectools_core.schema.findings import Evidence

    async def ok(window_hours):
        return [Finding(source="defender", finding_type=FindingType.posture,
                        severity=Severity.low, title="Microsoft Secure Score: 90%",
                        evidence=[Evidence(key="headline", value="90%")])]

    monkeypatch.setitem(report_gather.GATHER_MAP, "ciso", {"Config hardening": ok})
    _findings, meta = asyncio.run(report_gather.gather("ciso", 168))
    assert [m.value for m in meta.pillar_metrics] == ["90%"]


def test_entra_conditional_access_factory_bounds_unbounded_result(monkeypatch):
    # list_conditional_access_policies has no limit param and pages unbounded via
    # gc.get_all() — the factory must cap it itself like every sibling group (10-15).
    from unittest.mock import AsyncMock, patch

    monkeypatch.setenv("ENTRA_TENANT_ID", "t")
    monkeypatch.setenv("ENTRA_CLIENT_ID", "c")
    monkeypatch.setenv("ENTRA_CLIENT_SECRET", "s")

    many = [Finding(source="entra", finding_type=FindingType.posture,
                    severity=Severity.info, title=f"Policy {i}") for i in range(25)]

    with patch("f0_entra_mcp.tools.list_conditional_access_policies",
              AsyncMock(return_value=many)):
        result = asyncio.run(report_gather._entra_conditional_access(168))

    assert len(result) == 10
