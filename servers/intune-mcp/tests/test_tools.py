import httpx
import pytest
import respx
from f0_intune_mcp.tools import (
    get_compliance_summary,
    get_managed_device,
    list_compliance_policies,
    list_configuration_profiles,
    list_managed_devices,
    list_stale_devices,
)
from f0_sectools_core.auth.config import PlatformConfig
from f0_sectools_core.auth.graph import GraphClient

CFG = PlatformConfig(tenant_id="t", client_id="c", client_secret="s")
TOKEN_URL = "https://login.microsoftonline.com/t/oauth2/v2.0/token"
GRAPH = "https://graph.microsoft.com/v1.0"
DEV = GRAPH + "/deviceManagement/managedDevices"
CPOL = GRAPH + "/deviceManagement/deviceCompliancePolicies"
CONF = GRAPH + "/deviceManagement/deviceConfigurations"


def _token(router):
    router.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
    )


def _device(name, compliance="compliant", encrypted=True, last_sync="2026-07-10T00:00:00Z"):
    return {"id": name.lower(), "deviceName": name, "operatingSystem": "Windows",
            "osVersion": "10.0", "complianceState": compliance, "isEncrypted": encrypted,
            "managedDeviceOwnerType": "company", "lastSyncDateTime": last_sync,
            "userPrincipalName": "ada@corp.com"}


@pytest.mark.asyncio
async def test_list_managed_devices_maps_to_findings():
    with respx.mock as router:
        _token(router)
        router.get(DEV).mock(return_value=httpx.Response(200, json={"value": [_device("PC-1")]}))
        async with GraphClient(CFG) as gc:
            findings = await list_managed_devices(gc)
    assert findings[0].finding_type.value == "posture"
    assert findings[0].entity.kind.value == "host"
    assert findings[0].entity.name == "PC-1"


@pytest.mark.asyncio
async def test_list_managed_devices_noncompliant_high_severity_and_filter():
    with respx.mock as router:
        _token(router)
        route = router.get(DEV).mock(
            return_value=httpx.Response(200, json={"value": [_device("PC-2", "noncompliant")]})
        )
        async with GraphClient(CFG) as gc:
            findings = await list_managed_devices(gc, compliance="noncompliant")
    assert findings[0].severity.value == "high"
    # the compliance enum applied a $filter on complianceState
    url_str = str(route.calls[0].request.url)
    assert "complianceState" in url_str and "noncompliant" in url_str


@pytest.mark.asyncio
async def test_list_managed_devices_403_permission_finding():
    with respx.mock as router:
        _token(router)
        router.get(DEV).mock(
            return_value=httpx.Response(
                403, json={"error": {"message": "Forbidden"}}
            )
        )
        async with GraphClient(CFG) as gc:
            findings = await list_managed_devices(gc)
    assert findings[0].finding_type.value == "posture"
    assert "DeviceManagementManagedDevices.Read.All" in findings[0].title


@pytest.mark.asyncio
async def test_get_managed_device_by_name():
    with respx.mock as router:
        _token(router)
        route = router.get(DEV).mock(
            return_value=httpx.Response(200, json={"value": [_device("PC-7")]})
        )
        async with GraphClient(CFG) as gc:
            findings = await get_managed_device(gc, "PC-7")
    assert findings[0].entity.name == "PC-7"
    url_str = str(route.calls[0].request.url)
    assert "deviceName" in url_str and "PC-7" in url_str


@pytest.mark.asyncio
async def test_get_managed_device_not_found():
    with respx.mock as router:
        _token(router)
        router.get(DEV).mock(return_value=httpx.Response(200, json={"value": []}))
        async with GraphClient(CFG) as gc:
            findings = await get_managed_device(gc, "ghost")
    assert findings[0].finding_type.value == "posture"
    assert "no managed device" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_list_stale_devices_filters_by_cutoff():
    fresh = _device("FRESH", last_sync="2026-07-10T00:00:00Z")
    stale = _device("OLD", last_sync="2026-01-01T00:00:00Z")
    with respx.mock as router:
        _token(router)
        route = router.get(DEV).mock(
            return_value=httpx.Response(200, json={"value": [fresh, stale]})
        )
        async with GraphClient(CFG) as gc:
            findings = await list_stale_devices(gc, days=30)
    # managedDevices ignores $orderby on lastSyncDateTime but honors a server-side
    # $filter (confirmed live) — assert we push the cutoff to the server, not $orderby.
    query = str(route.calls.last.request.url)
    assert "lastSyncDateTime+le+" in query or "lastSyncDateTime%20le%20" in query
    assert "orderby" not in query
    # client-side cutoff check remains a defensive backstop
    names = [f.entity.name for f in findings]
    assert "OLD" in names and "FRESH" not in names


@pytest.mark.asyncio
async def test_get_compliance_summary_counts():
    summary = GRAPH + "/deviceManagement/deviceCompliancePolicyDeviceStateSummary"
    with respx.mock as router:
        _token(router)
        router.get(summary).mock(return_value=httpx.Response(200, json={
            "compliantDeviceCount": 40, "nonCompliantDeviceCount": 5,
            "inGracePeriodCount": 2, "unknownDeviceCount": 3, "errorDeviceCount": 0,
            "conflictDeviceCount": 0, "notApplicableDeviceCount": 1}))
        async with GraphClient(CFG) as gc:
            findings = await get_compliance_summary(gc)
    assert findings[0].finding_type.value == "posture"
    ev = {e.key: e.value for e in findings[0].evidence}
    assert ev["devices_compliant"] == "40" and ev["devices_noncompliant"] == "5"
    assert ev["devices_total"]  # keys name the counted noun (devices), not bare
    assert findings[0].severity.value in ("low", "medium", "high")  # 5 noncompliant present


@pytest.mark.asyncio
async def test_list_compliance_policies_maps():
    with respx.mock as router:
        _token(router)
        router.get(CPOL).mock(return_value=httpx.Response(200, json={"value": [
            {"id": "p1", "displayName": "Win10 baseline",
             "description": "encryption required",
             "@odata.type": "#microsoft.graph.windows10CompliancePolicy"}]}))
        async with GraphClient(CFG) as gc:
            findings = await list_compliance_policies(gc)
    assert findings[0].entity.kind.value == "policy"
    assert "Win10 baseline" in findings[0].title


@pytest.mark.asyncio
async def test_list_configuration_profiles_maps():
    with respx.mock as router:
        _token(router)
        router.get(CONF).mock(return_value=httpx.Response(200, json={"value": [
            {"id": "c1", "displayName": "Disk encryption",
             "description": "BitLocker",
             "@odata.type": "#microsoft.graph.windows10GeneralConfiguration"}]}))
        async with GraphClient(CFG) as gc:
            findings = await list_configuration_profiles(gc)
    assert "Disk encryption" in findings[0].title


@pytest.mark.asyncio
async def test_list_compliance_policies_403_names_config_permission():
    with respx.mock as router:
        _token(router)
        router.get(CPOL).mock(
            return_value=httpx.Response(403, json={"error": {"message": "Forbidden"}})
        )
        async with GraphClient(CFG) as gc:
            findings = await list_compliance_policies(gc)
    assert "DeviceManagementConfiguration.Read.All" in findings[0].title


@pytest.mark.asyncio
async def test_compliance_enum_closed():
    from f0_intune_mcp import server
    tools = {t.name: t for t in await server.mcp.list_tools()}
    enum = tools["list_managed_devices"].inputSchema["properties"]["compliance"]["enum"]
    assert set(enum) == {"all", "compliant", "noncompliant", "ingraceperiod", "unknown"}
