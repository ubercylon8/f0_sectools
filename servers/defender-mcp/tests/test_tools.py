import httpx
import pytest
import respx
from f0_defender_mcp.tools import (
    get_secure_score,
    list_alerts,
    list_incidents,
    run_hunting_query,
)
from f0_sectools_core.auth.config import PlatformConfig
from f0_sectools_core.auth.graph import GraphClient

CFG = PlatformConfig(tenant_id="t", client_id="c", client_secret="s")
TOKEN_URL = "https://login.microsoftonline.com/t/oauth2/v2.0/token"
GRAPH = "https://graph.microsoft.com/v1.0"


def _token(router):
    router.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
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
