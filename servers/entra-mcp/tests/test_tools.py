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
async def test_list_risk_detections_maps():
    with respx.mock as router:
        _token(router)
        router.get(GRAPH + "/identityProtection/riskDetections").mock(
            return_value=httpx.Response(
                200,
                json={"value": [{"id": "d1", "riskEventType": "unfamiliarFeatures",
                                 "riskLevel": "medium", "userPrincipalName": "bob@corp.com"}]},
            )
        )
        async with GraphClient(CFG) as gc:
            findings = await list_risk_detections(gc)
    assert findings[0].finding_type.value == "risk"
    assert "unfamiliarFeatures" in findings[0].title


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
