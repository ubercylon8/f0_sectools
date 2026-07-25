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


# ── FIX 1: a healthy-but-empty group is assessed, not "not assessed" ──────
def test_gather_empty_but_healthy_group_is_assessed_not_dark(monkeypatch):
    # A list-tool factory returning [] (e.g. "no risky users") ran successfully
    # and found nothing to report — that is GOOD news, not a blind spot. It must
    # land in meta.assessed, never meta.not_assessed.
    async def empty(window_hours):
        return []

    monkeypatch.setitem(report_gather.GATHER_MAP, "security_engineer",
                        {"Risky users": empty, "Stale devices": empty})
    findings, meta = asyncio.run(report_gather.gather("security_engineer", 168))
    assert findings == []
    assert set(meta.assessed) == {"Risky users", "Stale devices"}
    assert meta.not_assessed == []


def test_gather_raising_group_still_lands_in_not_assessed(monkeypatch):
    # A genuinely dark platform (raises — no creds, API down) must still be
    # reported as not assessed, unlike the empty-but-healthy case above.
    async def boom(window_hours):
        raise ValueError("no creds")

    monkeypatch.setitem(report_gather.GATHER_MAP, "security_engineer",
                        {"Risky users": boom})
    findings, meta = asyncio.run(report_gather.gather("security_engineer", 168))
    assert meta.not_assessed == ["Risky users"]
    assert meta.assessed == []
    assert findings[0].finding_type is FindingType.posture


# ── FIX 2: provenance counts platforms (source), not group labels ─────────
def test_gather_provenance_counts_distinct_sources_not_groups(monkeypatch):
    # detection_engineer-style: 4 groups, but only 2 distinct platform sources —
    # platforms_queried must report 2, not 4.
    async def defender_ok(window_hours):
        return [Finding(source="defender", finding_type=FindingType.alert,
                        severity=Severity.high, title="Alert A")]

    async def defender_ok2(window_hours):
        return [Finding(source="defender", finding_type=FindingType.incident,
                        severity=Severity.high, title="Incident A")]

    async def lc_ok(window_hours):
        return [Finding(source="limacharlie", finding_type=FindingType.alert,
                        severity=Severity.medium, title="Detection A")]

    async def lc_ok2(window_hours):
        return [Finding(source="limacharlie", finding_type=FindingType.posture,
                        severity=Severity.info, title="Rule A")]

    monkeypatch.setitem(report_gather.GATHER_MAP, "detection_engineer", {
        "Alerts (MITRE)": defender_ok,
        "Incidents": defender_ok2,
        "Endpoint detections": lc_ok,
        "Detection rules": lc_ok2,
    })
    _findings, meta = asyncio.run(report_gather.gather("detection_engineer", 168))
    assert len(meta.platforms_queried) == 2
    assert set(meta.platforms_queried) == {"defender", "limacharlie"}


def test_ciso_provenance_still_six_platforms(monkeypatch):
    # Guardrail for the golden CISO fixture: each of the six pillars has a
    # distinct source, so platforms_queried must still resolve to 6.
    sources = ["defender", "projectachilles", "tenable", "intune", "purview", "limacharlie"]
    groups = list(report_gather.GATHER_MAP["ciso"])

    def make(src):
        async def ok(window_hours):
            return [Finding(source=src, finding_type=FindingType.posture,
                            severity=Severity.info, title=f"{src} posture")]
        return ok

    monkeypatch.setitem(report_gather.GATHER_MAP, "ciso",
                        dict(zip(groups, [make(s) for s in sources], strict=True)))
    _findings, meta = asyncio.run(report_gather.gather("ciso", 168))
    assert len(meta.platforms_queried) == 6


# ── FIX 4: _within_window scopes findings without a time-bounded tool ─────
def test_within_window_drops_old_finding():
    from datetime import UTC, datetime, timedelta

    old = (datetime.now(UTC) - timedelta(days=30)).isoformat()
    f = Finding(source="defender", finding_type=FindingType.alert,
                severity=Severity.high, title="Old alert", observed_at=old)
    assert report_gather._within_window([f], 168) == []


def test_within_window_keeps_recent_finding():
    from datetime import UTC, datetime, timedelta

    recent = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    f = Finding(source="defender", finding_type=FindingType.alert,
                severity=Severity.high, title="Recent alert", observed_at=recent)
    assert report_gather._within_window([f], 168) == [f]


def test_within_window_keeps_finding_with_no_observed_at():
    f = Finding(source="defender", finding_type=FindingType.alert,
                severity=Severity.high, title="No timestamp", observed_at=None)
    assert report_gather._within_window([f], 168) == [f]


def test_within_window_keeps_finding_with_unparsable_observed_at():
    f = Finding(source="defender", finding_type=FindingType.alert,
                severity=Severity.high, title="Bad timestamp", observed_at="not-a-date")
    assert report_gather._within_window([f], 168) == [f]
