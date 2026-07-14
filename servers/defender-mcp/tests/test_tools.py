import json

import httpx
import pytest
import respx
from f0_defender_mcp.tools import (
    get_secure_score,
    hunt,
    isolate_host,
    list_alerts,
    list_incidents,
    release_host,
    run_hunting_query,
)
from f0_sectools_core.auth.config import PlatformConfig
from f0_sectools_core.auth.graph import GraphClient
from f0_sectools_core.gating.actions import AuditLog, GatedAction, TokenStore

CFG = PlatformConfig(tenant_id="t", client_id="c", client_secret="s")
TOKEN_URL = "https://login.microsoftonline.com/t/oauth2/v2.0/token"
GRAPH = "https://graph.microsoft.com/v1.0"
SEC = "https://api.security.microsoft.com/api"


def _token(router):
    router.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
    )


def _sec_client():
    return GraphClient(
        CFG, base_url=SEC, scope="https://api.security.microsoft.com/.default"
    )


def _gate(tmp_path, enabled):
    return GatedAction(
        "defender.isolate_host",
        enabled=enabled,
        audit=AuditLog(str(tmp_path / "a.log")),
        token_store=TokenStore(str(tmp_path / "pending")),
    )


@pytest.mark.asyncio
async def test_list_incidents_maps_to_findings():
    with respx.mock as router:
        _token(router)
        router.get(GRAPH + "/security/incidents").mock(
            return_value=httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": "42",
                            "displayName": "Multi-stage incident",
                            "severity": "high",
                            "status": "active",
                            "alerts": [{}, {}, {}, {}],
                        }
                    ]
                },
            )
        )
        async with GraphClient(CFG) as gc:
            findings = await list_incidents(gc)
    assert findings[0].finding_type.value == "incident"
    assert "Multi-stage incident" in findings[0].title
    # 4 alerts on a high incident escalates to critical
    assert findings[0].severity.value == "critical"


@pytest.mark.asyncio
async def test_list_incidents_403_returns_permission_finding():
    with respx.mock as router:
        _token(router)
        router.get(GRAPH + "/security/incidents").mock(
            return_value=httpx.Response(403, json={"error": {"message": "Forbidden"}})
        )
        async with GraphClient(CFG) as gc:
            findings = await list_incidents(gc)
    assert findings[0].finding_type.value == "posture"
    assert "SecurityIncident.Read.All" in findings[0].title


@pytest.mark.asyncio
async def test_list_incidents_429_returns_rate_limited():
    with respx.mock as router:
        _token(router)
        router.get(GRAPH + "/security/incidents").mock(
            return_value=httpx.Response(
                429, headers={"Retry-After": "0"}, json={"error": {"message": "Too many requests"}}
            )
        )
        async with GraphClient(CFG) as gc:
            findings = await list_incidents(gc)
    assert findings[0].finding_type.value == "posture"
    assert "Rate limited" in findings[0].title


@pytest.mark.asyncio
async def test_get_secure_score_maps():
    with respx.mock as router:
        _token(router)
        router.get(GRAPH + "/security/secureScores").mock(
            return_value=httpx.Response(
                200,
                json={"value": [{"currentScore": 42.0, "maxScore": 100.0,
                                 "createdDateTime": "2026-06-28T00:00:00Z"}]},
            )
        )
        async with GraphClient(CFG) as gc:
            findings = await get_secure_score(gc)
    assert findings[0].finding_type.value == "posture"
    assert "42" in findings[0].title


@pytest.mark.asyncio
async def test_get_secure_score_does_not_paginate_history():
    # /security/secureScores is a daily-snapshot time series; we only need the
    # latest record. Regression: get_secure_score must NOT follow @odata.nextLink
    # through months of history — that pagination timed out against a live tenant.
    with respx.mock(assert_all_called=False) as router:
        _token(router)
        page2 = router.get(
            GRAPH + "/security/secureScores", params={"$skiptoken": "next"}
        ).mock(
            return_value=httpx.Response(
                200, json={"value": [{"currentScore": 1.0, "maxScore": 100.0}]}
            )
        )
        router.get(GRAPH + "/security/secureScores", params={"$top": "1"}).mock(
            return_value=httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "currentScore": 42.0,
                            "maxScore": 100.0,
                            "createdDateTime": "2026-06-28T00:00:00Z",
                        }
                    ],
                    "@odata.nextLink": GRAPH + "/security/secureScores?$skiptoken=next",
                },
            )
        )
        async with GraphClient(CFG) as gc:
            findings = await get_secure_score(gc)
    assert "42" in findings[0].title  # uses the latest (head) score
    assert not page2.called  # did NOT paginate into history


@pytest.mark.asyncio
async def test_list_alerts_maps_with_mitre():
    with respx.mock as router:
        _token(router)
        router.get(GRAPH + "/security/alerts_v2").mock(
            return_value=httpx.Response(
                200,
                json={"value": [{"id": "a1", "title": "Suspicious PowerShell",
                                 "severity": "high", "status": "new",
                                 "mitreTechniques": ["T1059.001"]}]},
            )
        )
        async with GraphClient(CFG) as gc:
            findings = await list_alerts(gc)
    assert findings[0].finding_type.value == "alert"
    assert any(r.id == "T1059.001" for r in findings[0].references)


@pytest.mark.asyncio
async def test_run_hunting_query_maps():
    with respx.mock as router:
        _token(router)
        router.post(GRAPH + "/security/runHuntingQuery").mock(
            return_value=httpx.Response(
                200,
                json={"schema": [{"name": "DeviceName"}],
                      "results": [{"DeviceName": "web-01"}, {"DeviceName": "web-02"}]},
            )
        )
        async with GraphClient(CFG) as gc:
            findings = await run_hunting_query(gc, "DeviceProcessEvents | take 2")
    assert findings[0].finding_type.value == "hunt_result"
    assert "2" in findings[0].title


@pytest.mark.asyncio
async def test_isolate_host_no_token_returns_intent_no_call(tmp_path):
    with respx.mock as router:
        _token(router)
        post = router.post(SEC + "/machines/dev-1/isolate")
        gate = _gate(tmp_path, enabled=True)
        async with _sec_client() as sec:
            findings = await isolate_host(sec, gate, "dev-1", "suspected c2")
        assert findings[0].finding_type.value == "action"
        assert findings[0].recommended_action.gated_action == "defender.isolate_host"
        assert not post.called  # intent must not touch the API


@pytest.mark.asyncio
async def test_isolate_host_flag_off_refuses(tmp_path):
    with respx.mock as router:
        _token(router)
        post = router.post(SEC + "/machines/dev-1/isolate")
        gate = _gate(tmp_path, enabled=False)
        tok = gate.token_store.issue("defender.isolate_host", "dev-1")
        async with _sec_client() as sec:
            findings = await isolate_host(sec, gate, "dev-1", "c2", confirmation_token=tok)
        assert findings[0].finding_type.value == "action"
        assert "disabled" in findings[0].title.lower()
        assert not post.called


@pytest.mark.asyncio
async def test_isolate_host_bad_token_refuses(tmp_path):
    with respx.mock as router:
        _token(router)
        post = router.post(SEC + "/machines/dev-1/isolate")
        gate = _gate(tmp_path, enabled=True)
        async with _sec_client() as sec:
            findings = await isolate_host(sec, gate, "dev-1", "c2", confirmation_token="nope")
        assert findings[0].finding_type.value == "action"
        assert "token" in findings[0].title.lower()
        assert not post.called


@pytest.mark.asyncio
async def test_isolate_host_valid_token_executes_and_audits(tmp_path):
    with respx.mock as router:
        _token(router)
        post = router.post(SEC + "/machines/dev-1/isolate").mock(
            return_value=httpx.Response(201, json={"id": "machineaction-9", "status": "Pending"})
        )
        gate = _gate(tmp_path, enabled=True)
        tok = gate.token_store.issue("defender.isolate_host", "dev-1")
        async with _sec_client() as sec:
            findings = await isolate_host(sec, gate, "dev-1", "c2", confirmation_token=tok)
        assert post.called
        assert findings[0].finding_type.value == "action"
        assert "machineaction-9" in [e.value for e in findings[0].evidence]
        # audit line written
        assert (tmp_path / "a.log").read_text().strip() != ""


@pytest.mark.asyncio
async def test_isolate_host_403_degrades_to_permission_finding(tmp_path):
    with respx.mock as router:
        _token(router)
        router.post(SEC + "/machines/dev-1/isolate").mock(
            return_value=httpx.Response(403, json={"error": {"message": "forbidden"}})
        )
        gate = _gate(tmp_path, enabled=True)
        tok = gate.token_store.issue("defender.isolate_host", "dev-1")
        async with _sec_client() as sec:
            findings = await isolate_host(sec, gate, "dev-1", "c2", confirmation_token=tok)
        assert "Machine.Isolate" in findings[0].title


@pytest.mark.asyncio
async def test_isolate_host_404_degrades(tmp_path):
    with respx.mock as router:
        _token(router)
        router.post(SEC + "/machines/dev-1/isolate").mock(
            return_value=httpx.Response(404, json={"error": {"message": "machine not found"}})
        )
        gate = _gate(tmp_path, enabled=True)
        tok = gate.token_store.issue("defender.isolate_host", "dev-1")
        async with _sec_client() as sec:
            findings = await isolate_host(sec, gate, "dev-1", "c2", confirmation_token=tok)
        assert findings[0].finding_type.value == "action"
        assert "not applied" in findings[0].title


@pytest.mark.asyncio
async def test_isolate_host_503_degrades(tmp_path):
    with respx.mock as router:
        _token(router)
        router.post(SEC + "/machines/dev-1/isolate").mock(
            return_value=httpx.Response(503, json={"error": {"message": "upstream error"}})
        )
        gate = _gate(tmp_path, enabled=True)
        tok = gate.token_store.issue("defender.isolate_host", "dev-1")
        async with _sec_client() as sec:
            findings = await isolate_host(sec, gate, "dev-1", "c2", confirmation_token=tok)
        assert "unavailable" in findings[0].title


@pytest.mark.asyncio
async def test_list_incidents_single_page_not_paginated():
    with respx.mock(assert_all_called=False) as router:
        _token(router)
        page2 = router.get(GRAPH + "/security/incidents", params={"$skiptoken": "x"}).mock(
            return_value=httpx.Response(200, json={"value": [{"id": "999", "severity": "high"}]})
        )
        router.get(GRAPH + "/security/incidents", params={"$top": "25"}).mock(
            return_value=httpx.Response(
                200,
                json={
                    "value": [
                        {"id": "1", "displayName": "A", "severity": "high",
                         "status": "active", "alerts": []}
                    ],
                    "@odata.nextLink": GRAPH + "/security/incidents?$skiptoken=x",
                },
            )
        )
        async with GraphClient(CFG) as gc:
            findings = await list_incidents(gc, limit=25)
    assert not page2.called  # did NOT paginate the whole tenant
    assert any("more results available" in f.title for f in findings)  # truncation note


@pytest.mark.asyncio
async def test_list_alerts_single_page_not_paginated():
    with respx.mock(assert_all_called=False) as router:
        _token(router)
        page2 = router.get(GRAPH + "/security/alerts_v2", params={"$skiptoken": "x"}).mock(
            return_value=httpx.Response(200, json={"value": [{"id": "999", "severity": "high"}]})
        )
        router.get(GRAPH + "/security/alerts_v2", params={"$top": "25"}).mock(
            return_value=httpx.Response(
                200,
                json={
                    "value": [
                        {"id": "a1", "title": "T", "severity": "high",
                         "status": "new", "mitreTechniques": []}
                    ],
                    "@odata.nextLink": GRAPH + "/security/alerts_v2?$skiptoken=x",
                },
            )
        )
        async with GraphClient(CFG) as gc:
            findings = await list_alerts(gc, limit=25)
    assert not page2.called
    assert any("more results available" in f.title for f in findings)


@pytest.mark.asyncio
async def test_release_host_valid_token_executes(tmp_path):
    with respx.mock as router:
        _token(router)
        post = router.post(SEC + "/machines/dev-1/unisolate").mock(
            return_value=httpx.Response(201, json={"id": "machineaction-10"})
        )
        gate = GatedAction(
            "defender.release_host",
            enabled=True,
            audit=AuditLog(str(tmp_path / "a.log")),
            token_store=TokenStore(str(tmp_path / "pending")),
        )
        tok = gate.token_store.issue("defender.release_host", "dev-1")
        async with _sec_client() as sec:
            findings = await release_host(sec, gate, "dev-1", "cleared", confirmation_token=tok)
        assert post.called
        assert "machineaction-10" in [e.value for e in findings[0].evidence]


@pytest.mark.asyncio
async def test_hunt_network_builds_correct_kql():
    with respx.mock as router:
        _token(router)
        route = router.post(GRAPH + "/security/runHuntingQuery").mock(
            return_value=httpx.Response(200, json={"results": [{"DeviceName": "web-01"}]})
        )
        async with GraphClient(CFG) as gc:
            findings = await hunt(gc, "network", "evil.com", 24)
    body = json.loads(route.calls.last.request.content)
    assert "DeviceNetworkEvents" in body["Query"]
    assert 'RemoteUrl contains "evil.com"' in body["Query"]
    assert "ago(24h)" in body["Query"]
    assert findings[0].finding_type.value == "hunt_result"


@pytest.mark.asyncio
async def test_hunt_process_builds_correct_kql():
    with respx.mock as router:
        _token(router)
        route = router.post(GRAPH + "/security/runHuntingQuery").mock(
            return_value=httpx.Response(200, json={"results": []})
        )
        async with GraphClient(CFG) as gc:
            await hunt(gc, "process", "powershell.exe")
    body = json.loads(route.calls.last.request.content)
    assert "DeviceProcessEvents" in body["Query"]
    assert 'FileName has "powershell.exe"' in body["Query"]


@pytest.mark.asyncio
async def test_hunt_logon_without_indicator_omits_account_filter():
    with respx.mock as router:
        _token(router)
        route = router.post(GRAPH + "/security/runHuntingQuery").mock(
            return_value=httpx.Response(200, json={"results": []})
        )
        async with GraphClient(CFG) as gc:
            await hunt(gc, "logon")
    body = json.loads(route.calls.last.request.content)
    assert "DeviceLogonEvents" in body["Query"]
    assert "AccountName has" not in body["Query"]


@pytest.mark.asyncio
async def test_hunt_email_with_indicator_adds_filter():
    with respx.mock as router:
        _token(router)
        route = router.post(GRAPH + "/security/runHuntingQuery").mock(
            return_value=httpx.Response(200, json={"results": []})
        )
        async with GraphClient(CFG) as gc:
            await hunt(gc, "email", "bad@sender.com")
    body = json.loads(route.calls.last.request.content)
    assert "EmailEvents" in body["Query"]
    assert 'SenderFromAddress has "bad@sender.com"' in body["Query"]


@pytest.mark.asyncio
async def test_hunt_network_requires_indicator_no_call():
    with respx.mock(assert_all_called=False) as router:
        _token(router)
        route = router.post(GRAPH + "/security/runHuntingQuery")
        async with GraphClient(CFG) as gc:
            findings = await hunt(gc, "network", "")
    assert not route.called
    assert "needs an indicator" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_hunt_invalid_indicator_rejected_no_call():
    with respx.mock(assert_all_called=False) as router:
        _token(router)
        route = router.post(GRAPH + "/security/runHuntingQuery")
        async with GraphClient(CFG) as gc:
            findings = await hunt(gc, "network", 'evil".io')
    assert not route.called
    assert "unsupported characters" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_hunt_unknown_category_no_call():
    with respx.mock(assert_all_called=False) as router:
        _token(router)
        route = router.post(GRAPH + "/security/runHuntingQuery")
        async with GraphClient(CFG) as gc:
            findings = await hunt(gc, "dns", "evil.com")
    assert not route.called
    assert "unknown hunt category" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_hunt_backslash_indicator_rejected_no_call():
    # Backslash is the KQL escape char inside "..."; reject rather than build a
    # malformed query.
    with respx.mock(assert_all_called=False) as router:
        _token(router)
        route = router.post(GRAPH + "/security/runHuntingQuery")
        async with GraphClient(CFG) as gc:
            findings = await hunt(gc, "process", r"C:\Temp\evil.exe")
    assert not route.called
    assert "unsupported characters" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_hunt_query_400_is_graceful_not_raised():
    # A bad query (e.g. wrong field name) must degrade to a finding, never raise.
    with respx.mock as router:
        _token(router)
        router.post(GRAPH + "/security/runHuntingQuery").mock(
            return_value=httpx.Response(400, json={"error": {"message": "Fix semantic errors"}})
        )
        async with GraphClient(CFG) as gc:
            findings = await hunt(gc, "network", "evil.com")
    assert findings[0].finding_type.value == "posture"
    assert "failed" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_hunt_clamps_time_window():
    with respx.mock as router:
        _token(router)
        route = router.post(GRAPH + "/security/runHuntingQuery").mock(
            return_value=httpx.Response(200, json={"results": []})
        )
        async with GraphClient(CFG) as gc:
            await hunt(gc, "network", "evil.com", 99999)
    body = json.loads(route.calls.last.request.content)
    assert "ago(720h)" in body["Query"]
