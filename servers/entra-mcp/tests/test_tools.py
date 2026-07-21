import httpx
import pytest
import respx
from f0_entra_mcp.tools import (
    list_conditional_access_policies,
    list_privileged_role_assignments,
    list_risk_detections,
    list_risky_users,
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
async def test_list_risky_users_maps_to_findings():
    with respx.mock as router:
        _token(router)
        router.get(GRAPH + "/identityProtection/riskyUsers").mock(
            return_value=httpx.Response(
                200,
                json={"value": [{"id": "u1", "userPrincipalName": "ada@corp.com",
                                 "riskLevel": "high", "riskState": "atRisk"}]},
            )
        )
        async with GraphClient(CFG) as gc:
            findings = await list_risky_users(gc)
    assert findings[0].finding_type.value == "risk"
    assert findings[0].severity.value == "high"
    assert findings[0].entity.name == "ada@corp.com"


@pytest.mark.asyncio
async def test_list_risky_users_403_returns_permission_finding():
    with respx.mock as router:
        _token(router)
        router.get(GRAPH + "/identityProtection/riskyUsers").mock(
            return_value=httpx.Response(403, json={"error": {"message": "Forbidden"}})
        )
        async with GraphClient(CFG) as gc:
            findings = await list_risky_users(gc)
    assert findings[0].finding_type.value == "posture"
    assert "IdentityRiskyUser.Read.All" in findings[0].title


@pytest.mark.asyncio
async def test_list_risky_users_429_returns_rate_limited():
    with respx.mock as router:
        _token(router)
        router.get(GRAPH + "/identityProtection/riskyUsers").mock(
            return_value=httpx.Response(
                429, headers={"Retry-After": "0"}, json={"error": {"message": "Too many requests"}}
            )
        )
        async with GraphClient(CFG) as gc:
            findings = await list_risky_users(gc)
    assert findings[0].finding_type.value == "posture"
    assert "Rate limited" in findings[0].title


@pytest.mark.asyncio
async def test_list_risk_detections_maps():
    with respx.mock as router:
        _token(router)
        router.get(GRAPH + "/identityProtection/riskDetections").mock(
            return_value=httpx.Response(
                200,
                json={"value": [{"id": "d1", "riskEventType": "unfamiliarFeatures",
                                 "riskLevel": "medium", "userPrincipalName": "bob@corp.com",
                                 "detectedDateTime": "2026-07-14T10:00:00Z"}]},
            )
        )
        async with GraphClient(CFG) as gc:
            findings = await list_risk_detections(gc)
    assert findings[0].finding_type.value == "risk"
    assert "unfamiliarFeatures" in findings[0].title
    ev = {e.key: e.value for e in findings[0].evidence}
    assert ev["detected_at"] == "2026-07-14T10:00:00Z"  # keyed as a time, not bare "detected"


@pytest.mark.asyncio
async def test_list_risky_users_single_page_not_paginated():
    with respx.mock(assert_all_called=False) as router:
        _token(router)
        page2 = router.get(
            GRAPH + "/identityProtection/riskyUsers", params={"$skiptoken": "x"}
        ).mock(
            return_value=httpx.Response(200, json={"value": [{"id": "999", "riskLevel": "high"}]})
        )
        router.get(GRAPH + "/identityProtection/riskyUsers", params={"$top": "25"}).mock(
            return_value=httpx.Response(
                200,
                json={
                    "value": [
                        {"id": "u1", "userPrincipalName": "a@x", "riskLevel": "high",
                         "riskState": "atRisk"}
                    ],
                    "@odata.nextLink": GRAPH + "/identityProtection/riskyUsers?$skiptoken=x",
                },
            )
        )
        async with GraphClient(CFG) as gc:
            findings = await list_risky_users(gc, limit=25)
    assert not page2.called
    assert any("more results available" in f.title for f in findings)


@pytest.mark.asyncio
async def test_list_risk_detections_single_page_not_paginated():
    with respx.mock(assert_all_called=False) as router:
        _token(router)
        page2 = router.get(
            GRAPH + "/identityProtection/riskDetections", params={"$skiptoken": "x"}
        ).mock(
            return_value=httpx.Response(200, json={"value": [{"id": "999", "riskLevel": "high"}]})
        )
        router.get(GRAPH + "/identityProtection/riskDetections", params={"$top": "25"}).mock(
            return_value=httpx.Response(
                200,
                json={
                    "value": [
                        {"id": "d1", "userPrincipalName": "a@x", "riskEventType": "anon",
                         "riskLevel": "high"}
                    ],
                    "@odata.nextLink": GRAPH + "/identityProtection/riskDetections?$skiptoken=x",
                },
            )
        )
        async with GraphClient(CFG) as gc:
            findings = await list_risk_detections(gc, limit=25)
    assert not page2.called
    assert any("more results available" in f.title for f in findings)


@pytest.mark.asyncio
async def test_list_conditional_access_policies_flags_disabled():
    with respx.mock as router:
        _token(router)
        router.get(GRAPH + "/identity/conditionalAccess/policies").mock(
            return_value=httpx.Response(
                200,
                json={"value": [
                    {"id": "p1", "displayName": "Require MFA", "state": "enabled"},
                    {"id": "p2", "displayName": "Legacy block", "state": "disabled"},
                ]},
            )
        )
        async with GraphClient(CFG) as gc:
            findings = await list_conditional_access_policies(gc)
    disabled = [f for f in findings if "Legacy block" in f.title]
    assert disabled and disabled[0].severity.value == "medium"


@pytest.mark.asyncio
async def test_list_privileged_role_assignments_maps():
    # Graph allows only ONE $expand per query, so role names come from a separate
    # roleDefinitions lookup and only `principal` is expanded on the assignments.
    with respx.mock as router:
        _token(router)
        router.get(GRAPH + "/roleManagement/directory/roleDefinitions").mock(
            return_value=httpx.Response(
                200, json={"value": [{"id": "rd1", "displayName": "Global Administrator"}]}
            )
        )
        router.get(GRAPH + "/roleManagement/directory/roleAssignments").mock(
            return_value=httpx.Response(
                200,
                json={"value": [{
                    "id": "ra1",
                    "roleDefinitionId": "rd1",
                    "principal": {"userPrincipalName": "admin@corp.com", "id": "u9"},
                }]},
            )
        )
        async with GraphClient(CFG) as gc:
            findings = await list_privileged_role_assignments(gc)
    assert findings[0].finding_type.value == "posture"
    assert findings[0].severity.value == "high"
    assert "Global Administrator" in findings[0].title


@pytest.mark.asyncio
async def test_list_privileged_role_assignments_bounds_and_notes():
    # A large assignment set must not dump hundreds of findings past a small
    # model's runtime output cap: return one bounded page (default 25) + a
    # "more available" note, criticals first.
    with respx.mock as router:
        _token(router)
        router.get(GRAPH + "/roleManagement/directory/roleDefinitions").mock(
            return_value=httpx.Response(
                200,
                json={"value": [
                    {"id": "rd1", "displayName": "Global Administrator"},
                    {"id": "rd2", "displayName": "Message Center Reader"},
                ]},
            )
        )
        assignments = [
            {"id": f"crit{i}", "roleDefinitionId": "rd1",
             "principal": {"userPrincipalName": f"admin{i}@corp.com", "id": f"c{i}"}}
            for i in range(5)
        ] + [
            {"id": f"reg{i}", "roleDefinitionId": "rd2",
             "principal": {"userPrincipalName": f"user{i}@corp.com", "id": f"u{i}"}}
            for i in range(25)
        ]
        router.get(GRAPH + "/roleManagement/directory/roleAssignments").mock(
            return_value=httpx.Response(200, json={"value": assignments})
        )
        async with GraphClient(CFG) as gc:
            findings = await list_privileged_role_assignments(gc)
    # 30 assignments > default limit 25 -> 25 findings + 1 "more available" note.
    assert len(findings) == 26
    note = findings[-1]
    assert note.severity.value == "info"
    assert "more results available" in note.title.lower()
    shown = findings[:25]
    assert all(f.severity.value == "high" for f in shown[:5])  # criticals first
    assert all("more results" not in f.title.lower() for f in shown)
