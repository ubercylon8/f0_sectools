"""Contract tests for the Tenable tools.

Tools take a thin async client; tests pass a fake client (no HTTP / network).
Real Tenable field names are validated by the live smoke test (recipe step 9).
"""
from __future__ import annotations

import inspect

import pytest
from f0_tenable_mcp import tools
from f0_tenable_mcp.client import TenableError
from f0_tenable_mcp.errors import map_tenable_error


class FakeClient:
    """Fake async client: canned responses by path prefix, or a configured error."""

    def __init__(self, responses=None, raise_on=None):
        self._responses = responses or {}
        self._raise = raise_on or {}
        self.calls: list[tuple[str, dict]] = []

    async def get(self, path, params=None):
        self.calls.append((path, params or {}))
        # Longest-prefix-first so e.g. "/workbenches/assets/<uuid>/vulnerabilities"
        # matches its own canned response rather than the shorter "/workbenches/assets".
        for p, err in sorted(self._raise.items(), key=lambda kv: -len(kv[0])):
            if path.startswith(p):
                raise err
        for p, resp in sorted(self._responses.items(), key=lambda kv: -len(kv[0])):
            if path.startswith(p):
                return resp
        return {}


def test_map_tenable_error_403_permission():
    f = map_tenable_error(TenableError(403, "forbidden"), "Tenable vulnerabilities")
    assert f is not None
    assert f.finding_type.value == "posture"
    assert "Tenable vulnerabilities" in f.title


def test_map_tenable_error_429_rate_limited():
    f = map_tenable_error(TenableError(429, "slow down"), "Tenable assets")
    assert f is not None and "Rate limited" in f.title


def test_map_tenable_error_502_unavailable():
    f = map_tenable_error(TenableError(503, "bad gateway"), "Tenable scans")
    assert f is not None and "unavailable" in f.title.lower()


def test_map_tenable_error_unknown_returns_none():
    assert map_tenable_error(ValueError("nope"), "x") is None
    assert map_tenable_error(TenableError(418, "teapot"), "x") is None


def test_tenable_error_redacts_message():
    e = TenableError(401, "Authorization: Bearer Tenable_SuperLongSecretToken_12345")
    assert "Tenable_SuperLongSecretToken_12345" not in str(e) or "«redacted»" in str(e)


# Shapes mirror the live Workbenches /vulnerabilities response: rows carry
# cvss3_base_score / cvss_base_score (NOT vpr_score), and no CVE field (CVEs are
# only on the per-plugin /info endpoint). Validated live 2026-07-13.
_VULNS = {"vulnerabilities": [
    {"plugin_id": 19506, "plugin_name": "SSL cert", "severity": 4, "count": 12,
     "cvss3_base_score": 9.1, "cvss_base_score": 8.8},
    {"plugin_id": 11219, "plugin_name": "Open port", "severity": 1, "count": 40,
     "cvss_base_score": 2.0},
]}


@pytest.mark.asyncio
async def test_get_vulnerability_summary_counts_by_severity():
    tio = FakeClient(responses={"/workbenches/vulnerabilities": _VULNS})
    findings = await tools.get_vulnerability_summary(tio)
    f = findings[0]
    assert f.finding_type.value == "posture"
    assert f.severity.value == "critical"  # worst present (sev 4)
    # evidence carries per-severity instance counts
    ev = {e.key: e.value for e in f.evidence}
    assert ev["critical"] == "12" and ev["low"] == "40"


@pytest.mark.asyncio
async def test_list_top_vulnerabilities_filters_and_sorts():
    tio = FakeClient(responses={"/workbenches/vulnerabilities": _VULNS})
    findings = await tools.list_top_vulnerabilities(tio, severity_min="high", limit=10)
    # only the critical plugin passes severity_min=high; low one is filtered out
    assert len(findings) == 1
    assert findings[0].severity.value == "critical"
    # list rows carry no CVE (CVEs are on the /info endpoint); only the plugin ref
    assert findings[0].references[0].type == "tenable_plugin"
    assert findings[0].references[0].id == "19506"
    ev = {e.key: e.value for e in findings[0].evidence}
    assert ev["affected_hosts"] == "12"
    assert ev["cvss"] == "9.1"  # CVSSv3 preferred over v2


@pytest.mark.asyncio
async def test_list_assets_maps_host_entities():
    tio = FakeClient(responses={"/workbenches/assets": {"assets": [
        {"id": "abc", "fqdn": ["web-01.corp"], "ipv4": ["10.0.0.5"],
         "last_seen": "2026-07-01T00:00:00Z"},
    ]}})
    findings = await tools.list_assets(tio, limit=5)
    assert findings[0].entity.kind.value == "host"
    assert findings[0].entity.name == "web-01.corp"


def test_list_assets_has_no_severity_min_param():
    assert "severity_min" not in inspect.signature(tools.list_assets).parameters


@pytest.mark.asyncio
async def test_list_assets_finds_hostname_beyond_page_and_fetches_unbounded():
    tio = FakeClient(responses={"/workbenches/assets": {"assets": [
        {"id": "1", "fqdn": ["a.corp"]},
        {"id": "2", "fqdn": ["b.corp"]},
        {"id": "3", "fqdn": ["web-01.corp"]},
    ]}})
    findings = await tools.list_assets(tio, hostname="web-01", limit=1)
    assert len(findings) == 1 and findings[0].entity.name == "web-01.corp"
    # unbounded fetch when hostname set: no limit param
    assert tio.calls[0][1] == {}


@pytest.mark.asyncio
async def test_list_top_vulnerabilities_tolerates_string_severity():
    tio = FakeClient(responses={"/workbenches/vulnerabilities": {"vulnerabilities": [
        {"plugin_id": 1, "plugin_name": "x", "severity": "critical", "count": 1,
         "cvss3_base_score": "n/a"},
    ]}})
    findings = await tools.list_top_vulnerabilities(tio, severity_min="high")
    assert len(findings) == 1 and findings[0].severity.value == "critical"


@pytest.mark.asyncio
async def test_list_top_vulnerabilities_permission_error_is_graceful():
    tio = FakeClient(raise_on={"/workbenches/vulnerabilities": TenableError(403, "forbidden")})
    findings = await tools.list_top_vulnerabilities(tio)
    assert len(findings) == 1 and findings[0].finding_type.value == "posture"


_UUID = "12345678-1234-1234-1234-1234567890ab"


@pytest.mark.asyncio
async def test_get_asset_vulnerabilities_uuid_direct():
    tio = FakeClient(responses={
        f"/workbenches/assets/{_UUID}/vulnerabilities": {"vulnerabilities": [
            {"plugin_id": 19506, "plugin_name": "SSL cert", "severity": 4, "count": 1,
             "cves": ["CVE-2021-1234"]},
        ]},
    })
    findings = await tools.get_asset_vulnerabilities(tio, _UUID)
    assert findings[0].entity.kind.value == "host"
    assert findings[0].severity.value == "critical"
    # went straight to the uuid endpoint, no asset search
    assert any(_UUID in c[0] for c in tio.calls)


@pytest.mark.asyncio
async def test_get_asset_vulnerabilities_resolves_hostname():
    tio = FakeClient(responses={
        "/workbenches/assets": {"assets": [
            {"id": _UUID, "fqdn": ["web-01.corp"], "ipv4": ["10.0.0.5"]}]},
        f"/workbenches/assets/{_UUID}/vulnerabilities": {"vulnerabilities": [
            {"plugin_id": 11219, "plugin_name": "x", "severity": 3, "count": 2}]},
    })
    findings = await tools.get_asset_vulnerabilities(tio, "web-01", severity_min="high")
    assert findings and findings[0].severity.value == "high"


@pytest.mark.asyncio
async def test_get_asset_vulnerabilities_no_match_is_graceful():
    tio = FakeClient(responses={"/workbenches/assets": {"assets": []}})
    findings = await tools.get_asset_vulnerabilities(tio, "ghost-host")
    assert len(findings) == 1
    assert findings[0].finding_type.value == "posture"
    assert "ghost-host" in findings[0].title


@pytest.mark.asyncio
async def test_get_vulnerability_info_maps_detail():
    # Live /info shape: cvss under risk_information, CVEs under reference_information,
    # vpr at top level. Validated live 2026-07-13.
    tio = FakeClient(responses={"/workbenches/vulnerabilities/19506/info": {"info": {
        "plugin_details": {"name": "SSL cert", "severity": 4},
        "description": "the desc", "solution": "patch it",
        "risk_information": {"cvss3_base_score": "6.5", "cvss_base_score": "7.5"},
        "vpr": {"score": 9.1},
        "reference_information": [{"name": "cve", "values": ["CVE-2021-1234"]}]}}})
    findings = await tools.get_vulnerability_info(tio, "19506")
    f = findings[0]
    assert f.finding_type.value == "misconfig"
    ev = {e.key: e.value for e in f.evidence}
    assert "patch it" in ev["solution"]
    assert ev["cvss"] == "6.5" and ev["vpr"] == "9.1"
    assert f.references[0].id == "CVE-2021-1234"


@pytest.mark.asyncio
async def test_list_scans_maps_status():
    tio = FakeClient(responses={"/scans": {"scans": [
        {"id": 7, "name": "Weekly", "status": "completed",
         "last_modification_date": 1783900000}]}})
    findings = await tools.list_scans(tio, limit=5)
    assert findings[0].title.startswith("Tenable scan")
    ev = {e.key: e.value for e in findings[0].evidence}
    assert ev["status"] == "completed"
    # last_run is converted from a unix epoch to ISO (so a model can judge freshness)
    assert "T" in ev["last_run"] and ev["last_run"].endswith("Z")
    assert ev["last_run"] != "1783900000"


_OUTPUTS = {"outputs": [{"states": [{"results": [
    {"assets": [
        {"id": "uuid-1", "hostname": "web-01", "ipv4": ["10.0.0.1"],
         "last_seen": "2026-01-01T00:00:00Z"},
        {"id": "uuid-2", "hostname": "web-02", "ipv4": ["10.0.0.2"]},
    ]},
    {"assets": [{"id": "uuid-1", "hostname": "web-01"}]},  # duplicate of uuid-1
]}]}]}


@pytest.mark.asyncio
async def test_list_vulnerability_assets_maps_hosts_and_dedupes():
    tio = FakeClient(responses={"/workbenches/vulnerabilities/172179/outputs": _OUTPUTS})
    findings = await tools.list_vulnerability_assets(tio, "172179", limit=25)
    hosts = [f for f in findings if f.entity and f.entity.kind.value == "host"]
    assert len(hosts) == 2  # uuid-1 deduped
    assert "web-01" in hosts[0].title
    assert "affected by plugin 172179" in hosts[0].title


@pytest.mark.asyncio
async def test_list_vulnerability_assets_no_assets_is_graceful():
    tio = FakeClient(responses={"/workbenches/vulnerabilities/999/outputs": {"outputs": []}})
    findings = await tools.list_vulnerability_assets(tio, "999")
    assert "no affected assets" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_list_vulnerability_assets_truncates_with_note():
    many = {"outputs": [{"states": [{"results": [{"assets": [
        {"id": f"u{i}", "hostname": f"h{i}"} for i in range(30)]}]}]}]}
    tio = FakeClient(responses={"/workbenches/vulnerabilities/1/outputs": many})
    findings = await tools.list_vulnerability_assets(tio, "1", limit=10)
    hosts = [f for f in findings if f.entity and f.entity.kind.value == "host"]
    assert len(hosts) == 10
    assert any("Showing 10 of 30" in f.title for f in findings)


@pytest.mark.asyncio
async def test_list_vulnerability_assets_permission_error_is_graceful():
    tio = FakeClient(raise_on={
        "/workbenches/vulnerabilities/1/outputs": TenableError(403, "forbidden")})
    findings = await tools.list_vulnerability_assets(tio, "1")
    assert findings[0].finding_type.value == "posture"


@pytest.mark.asyncio
async def test_server_registers_seven_tools():
    from f0_tenable_mcp import server
    names = {t.name for t in await server.mcp.list_tools()}
    assert names == {
        "get_vulnerability_summary", "list_top_vulnerabilities", "list_assets",
        "get_asset_vulnerabilities", "get_vulnerability_info", "list_vulnerability_assets",
        "list_scans",
    }
