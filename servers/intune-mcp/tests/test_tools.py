from datetime import UTC, datetime, timedelta

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


def _ago(days: int) -> str:
    """A Graph timestamp `days` before now.

    Device fixtures must be relative, never absolute. `list_stale_devices`
    derives its cutoff from `datetime.now(UTC)`, so a hardcoded date's
    relationship to that cutoff changes as wall-clock advances: the previous
    default, 2026-07-10T00:00:00Z, sat inside the default 30-day window when it
    was written and fell outside it on 2026-08-09, failing the suite on `main`
    with no code change.
    """
    return (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _device(name, compliance="compliant", encrypted=True, last_sync=None):
    last_sync = _ago(1) if last_sync is None else last_sync
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
async def test_list_managed_devices_clamps_oversized_limit():
    with respx.mock as router:
        _token(router)
        route = router.get(DEV).mock(return_value=httpx.Response(200, json={"value": []}))
        async with GraphClient(CFG) as gc:
            await list_managed_devices(gc, limit=5000)
    assert route.calls[0].request.url.params["$top"] == "100"  # clamped from 5000


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
    # Either side of the 30-day cutoff by a wide margin, so neither the test nor a
    # slow CI run can straddle the boundary.
    fresh = _device("FRESH", last_sync=_ago(1))
    stale = _device("OLD", last_sync=_ago(365))
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
    # total = 40 + 5 + 2 + 3 + 0 + 0 = 50; pct = round(40/50*100) = 80
    assert findings[0].evidence[0].key == "headline"
    assert ev["headline"] == "80% compliant"


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
    enum = tools["list_managed_devices"].input_schema["properties"]["compliance"]["enum"]
    assert set(enum) == {"all", "compliant", "noncompliant", "ingraceperiod", "unknown"}


# ---------- truncation disclosure ----------

def _page(rows, count=None, next_link=False):
    page = {"value": rows}
    if count is not None:
        page["@odata.count"] = count
    if next_link:
        page["@odata.nextLink"] = GRAPH + "/next"
    return page


def _params(router, path):
    """Query params sent for the last call to `path` (call INSIDE the mock block)."""
    for call in reversed(router.calls):
        if path in str(call.request.url):
            return dict(call.request.url.params)
    raise AssertionError(f"no request captured for {path}")


@pytest.mark.asyncio
async def test_managed_devices_disclose_truncation_via_next_link():
    # Live-probed: managedDevices echoes the PAGE size in @odata.count (3 rows ->
    # count=3 on a 1507-device tenant), so a count that equals what we fetched
    # must NOT be read as "that is everything". nextLink is the reliable signal.
    with respx.mock as router:
        _token(router)
        router.get(DEV).mock(return_value=httpx.Response(
            200, json=_page([_device("PC-1"), _device("PC-2")], count=2, next_link=True)))
        async with GraphClient(CFG) as gc:
            findings = await list_managed_devices(gc, limit=2)
        sent = _params(router, "/managedDevices")
    assert "more results available" in findings[-1].title
    # $count=true returns ZERO rows on this endpoint — never request it here.
    assert "$count" not in sent


@pytest.mark.asyncio
async def test_managed_devices_quiet_on_a_complete_page():
    with respx.mock as router:
        _token(router)
        router.get(DEV).mock(return_value=httpx.Response(
            200, json=_page([_device("PC-1")], count=1)))
        async with GraphClient(CFG) as gc:
            findings = await list_managed_devices(gc, limit=25)
    assert all("more results" not in f.title for f in findings)


@pytest.mark.asyncio
async def test_compliance_policies_trust_the_count_they_asked_for():
    # This endpoint never sends nextLink, and its $count IS the true total
    # (live-probed: 3 rows, count=9, and the tenant has 9 policies).
    with respx.mock as router:
        _token(router)
        router.get(CPOL).mock(return_value=httpx.Response(
            200, json=_page([{"id": "p1", "displayName": "P"}], count=9)))
        async with GraphClient(CFG) as gc:
            findings = await list_compliance_policies(gc, limit=1)
        sent = _params(router, "/deviceCompliancePolicies")
    assert sent.get("$count") == "true"
    assert "Showing 1 of 9" in findings[-1].title


@pytest.mark.asyncio
async def test_compliance_policies_quiet_when_the_count_fits():
    with respx.mock as router:
        _token(router)
        router.get(CPOL).mock(return_value=httpx.Response(
            200, json=_page([{"id": "p1", "displayName": "P"}], count=1)))
        async with GraphClient(CFG) as gc:
            findings = await list_compliance_policies(gc, limit=25)
    assert all("Showing" not in f.title for f in findings)


@pytest.mark.asyncio
async def test_configuration_profiles_ignore_a_page_echoing_count():
    # Live-probed: deviceConfigurations reports count=2 for a 2-row page of a
    # 28-profile tenant. Believing it would suppress a real truncation note, so
    # the tool neither requests nor reads the count here.
    with respx.mock as router:
        _token(router)
        router.get(CONF).mock(return_value=httpx.Response(
            200, json=_page([{"id": "c1", "displayName": "C"},
                             {"id": "c2", "displayName": "C2"}], count=2, next_link=True)))
        async with GraphClient(CFG) as gc:
            findings = await list_configuration_profiles(gc, limit=5)
        sent = _params(router, "/deviceConfigurations")
    assert "$count" not in sent
    assert "more results available" in findings[-1].title


@pytest.mark.asyncio
async def test_stale_devices_disclose_truncation():
    with respx.mock as router:
        _token(router)
        router.get(DEV).mock(return_value=httpx.Response(
            200, json=_page([_device("OLD-1", last_sync="2020-01-01T00:00:00Z"),
                             _device("OLD-2", last_sync="2020-02-01T00:00:00Z")],
                            next_link=True)))
        async with GraphClient(CFG) as gc:
            findings = await list_stale_devices(gc, days=30, limit=2)
    assert "more results available" in findings[-1].title
