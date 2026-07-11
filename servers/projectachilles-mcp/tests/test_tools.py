"""Contract tests for the ProjectAchilles tools.

Tools take a thin async client; tests pass a fake client (no HTTP / network).
Real field names are validated by the live smoke test.
"""
from __future__ import annotations

import pytest
from f0_projectachilles_mcp import tools
from f0_projectachilles_mcp.client import ProjectAchillesError


class FakeClient:
    """Fake async client: canned responses by path prefix, or a configured error."""

    def __init__(self, responses=None, raise_on=None):
        self._responses = responses or {}
        self._raise = raise_on or {}
        self.calls: list[tuple[str, dict]] = []

    async def get(self, path, params=None):
        self.calls.append((path, params or {}))
        for p, err in self._raise.items():
            if path.startswith(p):
                raise err
        for p, resp in self._responses.items():
            if path.startswith(p):
                return resp
        return {}


@pytest.mark.asyncio
async def test_get_defense_score_maps():
    pa = FakeClient(responses={"/analytics/defense-score": {
        "score": 35, "protectedCount": 35, "detectedCount": 10,
        "unprotectedCount": 55, "totalExecutions": 100}})
    findings = await tools.get_defense_score(pa)
    assert findings[0].finding_type.value == "posture"
    assert findings[0].severity.value == "high"  # low score -> high risk
    assert "35" in findings[0].title


@pytest.mark.asyncio
async def test_get_defense_score_requests_any_stage_scoring():
    # The PA dashboard is locked to scoringMode=any-stage (bundle-grouped
    # scoring, aggregation-based totals). Without it the API falls back to
    # legacy per-execution scoring whose total caps at 10k -> inflated score.
    pa = FakeClient(responses={"/analytics/defense-score": {"score": 52.1}})
    await tools.get_defense_score(pa)
    path, params = pa.calls[0]
    assert params["scoringMode"] == "any-stage"


@pytest.mark.asyncio
async def test_get_defense_score_trend_requests_any_stage_scoring():
    pa = FakeClient(responses={"/analytics/defense-score/trend": [
        {"score": 50}, {"score": 55}]})
    await tools.get_defense_score_trend(pa)
    path, params = pa.calls[0]
    assert params["scoringMode"] == "any-stage"


@pytest.mark.asyncio
async def test_get_defense_score_surfaces_risk_adjusted_fields():
    # Dashboard triple: score (risk-adjusted), rawScore (before exclusions),
    # realScore (blocked-only), riskAcceptedCount (excluded executions).
    pa = FakeClient(responses={"/analytics/defense-score": {
        "score": 52.1, "rawScore": 51.8, "realScore": 52.0,
        "riskAcceptedCount": 83, "protectedCount": 80, "detectedCount": 10,
        "unprotectedCount": 82, "totalExecutions": 172}})
    findings = await tools.get_defense_score(pa)
    assert "52" in findings[0].title
    ev = {e.key: e.value for e in findings[0].evidence}
    assert ev["risk_accepted"] == "83"
    assert ev["score_before_exclusions"] == "51.8%"
    assert ev["score_blocked_only"] == "52.0%"


@pytest.mark.asyncio
async def test_get_defense_score_401_degrades():
    pa = FakeClient(
        raise_on={"/analytics/defense-score": ProjectAchillesError(401, "unauthorized")}
    )
    findings = await tools.get_defense_score(pa)
    assert findings[0].finding_type.value == "posture"
    assert "authentication" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_get_weak_techniques_sorts_ascending():
    pa = FakeClient(responses={"/analytics/defense-score/by-technique": {"data": [
        {"name": "T1003", "score": 80, "count": 5},
        {"name": "T1059", "score": 10, "count": 8},
        {"name": "T1055", "score": 50, "count": 3},
    ]}})
    findings = await tools.get_weak_techniques(pa, limit=2)
    assert len(findings) == 2
    assert "T1059" in findings[0].title  # weakest first
    assert any(r.id == "T1059" for r in findings[0].references)


@pytest.mark.asyncio
async def test_list_test_executions_maps_unprotected():
    pa = FakeClient(responses={"/analytics/executions": {"data": [
        {"test_name": "Kerberoast", "hostname": "dc-01", "is_protected": False,
         "severity": "high", "techniques": ["T1558.003"]},
    ], "totalCount": 1}})
    findings = await tools.list_test_executions(pa)
    assert findings[0].finding_type.value == "misconfig"
    assert findings[0].severity.value == "high"
    assert "dc-01" in (findings[0].entity.name or "")


@pytest.mark.asyncio
async def test_list_risk_acceptances_maps():
    pa = FakeClient(responses={"/risk-acceptances": {"success": True, "data": [
        {"test_name": "Mimikatz", "scope": "global", "status": "active",
         "justification": "compensating control", "accepted_by_name": "James"},
    ], "total": 1}})
    findings = await tools.list_risk_acceptances(pa)
    assert "Mimikatz" in findings[0].title


@pytest.mark.asyncio
async def test_list_agents_maps():
    pa = FakeClient(responses={"/agent/admin/agents": {"success": True, "data": {"agents": [
        {"id": "a1", "hostname": "web-01", "os": "windows", "status": "active"},
    ], "total": 1}}})
    findings = await tools.list_agents(pa)
    assert findings[0].entity.name == "web-01"


@pytest.mark.asyncio
async def test_get_fleet_health_maps():
    pa = FakeClient(responses={"/agent/admin/metrics": {"success": True, "data": {
        "online": 8, "offline": 2, "total": 10, "pending_tasks": 3}}})
    findings = await tools.get_fleet_health(pa)
    assert findings[0].finding_type.value == "posture"
    assert "8/10" in findings[0].title


@pytest.mark.asyncio
async def test_list_agents_403_degrades():
    pa = FakeClient(raise_on={"/agent/admin/agents": ProjectAchillesError(403, "forbidden")})
    findings = await tools.list_agents(pa)
    assert "not granted" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_get_defense_score_502_degrades():
    pa = FakeClient(
        raise_on={"/analytics/defense-score": ProjectAchillesError(502, "<html>bad gateway")}
    )
    findings = await tools.get_defense_score(pa)
    assert findings[0].finding_type.value == "posture"
    assert "unavailable" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_get_weak_techniques_handles_bare_list():
    # Live PA returns a bare array (no {data} wrapper) for by-technique.
    pa = FakeClient(responses={"/analytics/defense-score/by-technique": [
        {"name": "T1059", "score": 10, "count": 8},
    ]})
    findings = await tools.get_weak_techniques(pa)
    assert "T1059" in findings[0].title
