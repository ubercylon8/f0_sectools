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
    assert ev["tests_risk_accepted"] == "83"
    assert ev["score_before_exclusions"] == "51.8%"
    assert ev["score_blocked_only"] == "52.0%"


@pytest.mark.asyncio
async def test_get_defense_score_evidence_keys_name_the_counted_noun():
    # Bare keys ("total", "protected") let a small model confabulate the noun —
    # it rendered `total` (=totalExecutions) as "Total HOSTS tested". Keys must
    # say what is counted: test executions / results, not hosts.
    pa = FakeClient(responses={"/analytics/defense-score": {
        "score": 50, "protectedCount": 80, "detectedCount": 10,
        "unprotectedCount": 82, "totalExecutions": 172, "riskAcceptedCount": 5}})
    findings = await tools.get_defense_score(pa)
    keys = {e.key for e in findings[0].evidence}
    assert {"total_tests", "tests_protected", "tests_detected",
            "tests_unprotected"} <= keys
    # the bare, noun-less keys are gone
    assert not ({"total", "protected", "detected", "unprotected"} & keys)


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
    ev = {e.key: e.value for e in findings[0].evidence}
    assert ev["outcome"] == "NOT blocked" and ev["check_kind"] == "security"


@pytest.mark.asyncio
async def test_list_test_executions_hygiene_is_present_not_blocked():
    # A cyber-hygiene control check is present/not-present, NOT blocked/not-blocked.
    # (A missing password policy is a config gap, not a "detection miss".)
    pa = FakeClient(responses={"/analytics/executions": {"data": [
        {"test_name": "Minimum Password Length", "hostname": "lt-01",
         "is_protected": False, "category": "cyber-hygiene", "severity": "high",
         "techniques": ["T1110"]},
        {"test_name": "SMB Encryption", "hostname": "lt-01",
         "is_protected": True, "category": "cyber-hygiene"},
    ]}})
    findings = await tools.list_test_executions(pa)
    ev0 = {e.key: e.value for e in findings[0].evidence}
    assert ev0["outcome"] == "not present" and ev0["check_kind"] == "cyber-hygiene"
    assert "not present" in findings[0].title
    assert findings[0].finding_type.value == "misconfig"
    ev1 = {e.key: e.value for e in findings[1].evidence}
    assert ev1["outcome"] == "present"
    assert findings[1].finding_type.value == "posture"


@pytest.mark.asyncio
async def test_list_test_executions_hygiene_ignores_defender_detected():
    # defender_detected is meaningless for a config check (no attack launched).
    pa = FakeClient(responses={"/analytics/executions": {"data": [
        {"test_name": "Script Block Logging", "hostname": "lt-01",
         "is_protected": False, "defender_detected": True, "category": "cyber-hygiene"},
    ]}})
    findings = await tools.list_test_executions(pa)
    ev = {e.key: e.value for e in findings[0].evidence}
    assert ev["outcome"] == "not present"  # NOT "detected, not blocked"


@pytest.mark.asyncio
async def test_list_test_executions_hygiene_tolerates_category_spelling():
    # A backend separator/case tweak must NOT silently fall back to the security
    # "NOT blocked" branch (a quiet regression of exactly what this fix prevents).
    for cat in ("cyber_hygiene", "Cyber Hygiene", "CYBER-HYGIENE", " cyber-hygiene "):
        pa = FakeClient(responses={"/analytics/executions": {"data": [
            {"test_name": "SMB Encryption", "hostname": "lt-01",
             "is_protected": False, "category": cat}]}})
        findings = await tools.list_test_executions(pa)
        ev = {e.key: e.value for e in findings[0].evidence}
        assert ev["outcome"] == "not present", f"variant {cat!r} fell through to security"
        assert ev["check_kind"] == "cyber-hygiene"


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
    ev = {e.key: e.value for e in findings[0].evidence}
    assert ev["agents_total"] == "10" and ev["agents_online"] == "8"
    assert not ({"total", "online", "offline"} & set(ev))  # noun-carrying keys


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


@pytest.mark.asyncio
async def test_find_tests_technique_uses_server_side_filter():
    pa = FakeClient(responses={"/browser/tests": {"count": 1, "tests": [
        {"uuid": "u1", "name": "Kerberoast", "category": "mitre-top10",
         "severity": "high", "techniques": ["T1558.003"], "target": ["windows-endpoint"],
         "threatActor": "APT29", "complexity": "medium", "description": "Roast SPNs."},
    ]}})
    findings = await tools.find_tests(pa, by="technique", value="T1558.003")
    # server-side filter param is sent
    path, params = pa.calls[0]
    assert path == "/browser/tests" and params == {"technique": "T1558.003"}
    # leading summary finding carries an exact count
    assert findings[0].finding_type.value == "posture"
    assert "1 tests match technique=T1558.003" in findings[0].title
    ev0 = {e.key: e.value for e in findings[0].evidence}
    assert ev0["total_matches"] == "1"
    # per-test finding maps os from target[] and emits a MITRE reference
    ev1 = {e.key: e.value for e in findings[1].evidence}
    assert ev1["os"] == "windows-endpoint"
    assert ev1["threat_actor"] == "APT29"
    assert findings[1].entity.kind.value == "rule"
    assert any(r.id == "T1558.003" for r in findings[1].references)


@pytest.mark.asyncio
async def test_find_tests_category_and_keyword_route_server_side():
    pa = FakeClient(responses={"/browser/tests": {"tests": []}})
    await tools.find_tests(pa, by="category", value="cyber-hygiene")
    await tools.find_tests(pa, by="keyword", value="mimikatz")
    assert pa.calls[0][1] == {"category": "cyber-hygiene"}
    assert pa.calls[1][1] == {"search": "mimikatz"}


@pytest.mark.asyncio
async def test_find_tests_actor_filters_client_side():
    # PA browser routes have no actor filter -> we fetch all and filter locally.
    pa = FakeClient(responses={"/browser/tests": {"tests": [
        {"uuid": "u1", "name": "A", "category": "intel-driven", "threatActor": "APT29"},
        {"uuid": "u2", "name": "B", "category": "intel-driven", "threatActor": "FIN7"},
    ]}})
    findings = await tools.find_tests(pa, by="actor", value="apt29")
    assert pa.calls[0][1] == {}  # no server-side param (FakeClient records `params or {}`)
    assert "1 tests match actor=apt29" in findings[0].title
    assert findings[1].entity.name == "A"


@pytest.mark.asyncio
async def test_find_tests_tag_and_tactic_filter_client_side():
    pa = FakeClient(responses={"/browser/tests": {"tests": [
        {"uuid": "u1", "name": "A", "category": "c", "tags": ["persistence"],
         "tactics": ["TA0003"]},
        {"uuid": "u2", "name": "B", "category": "c", "tags": ["exfil"], "tactics": ["TA0010"]},
    ]}})
    by_tag = await tools.find_tests(pa, by="tag", value="persistence")
    assert by_tag[0].title.startswith("1 tests match tag=persistence")
    by_tactic = await tools.find_tests(pa, by="tactic", value="TA0010")
    assert by_tactic[1].entity.name == "B"


@pytest.mark.asyncio
async def test_find_tests_bounds_output_but_counts_all():
    rows = [{"uuid": f"u{i}", "name": f"T{i}", "category": "c",
             "techniques": ["T1110"]} for i in range(30)]
    pa = FakeClient(responses={"/browser/tests": {"tests": rows}})
    findings = await tools.find_tests(pa, by="technique", value="T1110", limit=5)
    ev0 = {e.key: e.value for e in findings[0].evidence}
    assert ev0["total_matches"] == "30" and ev0["returned"] == "5"  # truncation never lies
    assert len(findings) == 1 + 5  # summary + 5 tests


@pytest.mark.asyncio
async def test_find_tests_empty_returns_only_summary():
    pa = FakeClient(responses={"/browser/tests": {"tests": []}})
    findings = await tools.find_tests(pa, by="technique", value="T9999")
    assert len(findings) == 1
    assert "0 tests match technique=T9999" in findings[0].title


@pytest.mark.asyncio
async def test_find_tests_invalid_by_returns_finding_not_raise():
    pa = FakeClient(responses={"/browser/tests": {"tests": []}})
    findings = await tools.find_tests(pa, by="planet", value="mars")
    assert len(findings) == 1
    assert "planet" in findings[0].title
    assert not pa.calls  # never hit the API


@pytest.mark.asyncio
async def test_find_tests_401_degrades():
    pa = FakeClient(raise_on={"/browser/tests": ProjectAchillesError(401, "unauthorized")})
    findings = await tools.find_tests(pa, by="technique", value="T1110")
    assert findings[0].finding_type.value == "posture"
    assert "authentication" in findings[0].title.lower()
