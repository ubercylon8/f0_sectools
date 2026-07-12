# Intune MCP Server (server #5) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a read-only `servers/intune-mcp/` exposing 6 Microsoft Intune device-management / compliance-coverage tools over Microsoft Graph, reusing `core/` unchanged.

**Architecture:** Mirror `entra-mcp` exactly — `PlatformConfig.from_env("INTUNE")` + the existing `GraphClient` (standard `graph.microsoft.com/v1.0`), tools returning `list[Finding]`, `map_graph_error` for graceful 403/license/429/5xx degradation, redaction at the server boundary. List tools use `gc.get` (single bounded page) for bounded output. No `core/` change.

**Tech Stack:** Python 3.11+, `httpx`, `mcp` FastMCP, `pytest` + `respx`, `uv` workspace.

## Global Constraints

- **Reuse `core/` unchanged:** `GraphClient` (from `f0_sectools_core.auth.graph`), `PlatformConfig` (`f0_sectools_core.auth.config`), `map_graph_error` (`f0_sectools_core.graph_errors`), the findings schema, `redact_obj`. No new `core/` code, no `errors.py`.
- **Read-only.** No writes. Every failure is a Finding, never an exception: catch `GraphError` → `map_graph_error(e, "intune", <permission>, <capability>)`; if it returns a finding, return `[finding]`, else re-raise. (`map_graph_error` handles 403→permission_missing, 429→rate_limited, 502/503/504→api_unavailable; an unlicensed-Intune tenant returns 403/4xx → the same graceful posture finding.)
- **Permissions:** device tools name `DeviceManagementManagedDevices.Read.All`; policy/config tools name `DeviceManagementConfiguration.Read.All`.
- **Bounded output (small-model-safe):** list tools use `gc.get(path, params={"$top": limit, ...})` and read `.get("value", [])` — a single page, not `gc.get_all`. Flat scalar args; `compliance` is a closed enum.
- **Credentials:** gitignored `.env.intune` (`INTUNE_TENANT_ID`/`INTUNE_CLIENT_ID`/`INTUNE_CLIENT_SECRET`) — same Entra-app values as `.env.entra`, isolated file (Rule 7). `load_dotenv(".env.intune")` in server.py.
- **Contract tests** mock Graph with `respx` (mirror `servers/entra-mcp/tests/test_tools.py`): `CFG = PlatformConfig(tenant_id="t", client_id="c", client_secret="s")`, `TOKEN_URL = "https://login.microsoftonline.com/t/oauth2/v2.0/token"`, `GRAPH = "https://graph.microsoft.com/v1.0"`, a `_token(router)` helper.
- **Commit style:** conventional commits ending with the two trailer lines exactly:
  `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`
  `Claude-Session: https://claude.ai/code/session_01TMoap3fRVq13TQah7BMdLm`
  Stage specific files; never `git add -A`. Do not push. Task 6 (live) is user-gated.

---

### Task 1: Scaffold the workspace member

**Files:**
- Create: `servers/intune-mcp/pyproject.toml`, `README.md`, `.env.intune.example`, `f0_intune_mcp/__init__.py`, `tests/__init__.py`

- [ ] **Step 1: Create the package files**

`servers/intune-mcp/pyproject.toml`:
```toml
[project]
name = "f0-intune-mcp"
version = "0.0.1"
description = "f0_sectools MCP server for Microsoft Intune device management (read-only) via Microsoft Graph."
readme = "README.md"
requires-python = ">=3.11"
license = { text = "Apache-2.0" }
authors = [{ name = "F0RT1KA Contributors" }]
dependencies = [
    "f0-sectools-core",
    "mcp>=1.0",
    "httpx>=0.27",
]

[project.scripts]
f0-intune-mcp = "f0_intune_mcp.server:main"

[tool.uv.sources]
f0-sectools-core = { workspace = true }

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["f0_intune_mcp"]
```

`servers/intune-mcp/f0_intune_mcp/__init__.py`: empty file.
`servers/intune-mcp/tests/__init__.py`: empty file.

`servers/intune-mcp/.env.intune.example`:
```bash
# Microsoft Intune (device management) — reuses a Microsoft Entra app registration.
# Same app as .env.entra is fine; kept a separate file for per-platform isolation.
# Grant the app (admin consent): DeviceManagementManagedDevices.Read.All and
# DeviceManagementConfiguration.Read.All. Requires an active Intune license on the tenant.
INTUNE_TENANT_ID=
INTUNE_CLIENT_ID=
INTUNE_CLIENT_SECRET=
INTUNE_VERIFY_TLS=true
```

`servers/intune-mcp/README.md`:
```markdown
# f0-intune-mcp

Read-only MCP server for **Microsoft Intune** device management, over Microsoft Graph.

Reuses the shared `core/` Graph client and the same auth as the Entra/Defender servers
(a Microsoft Entra app, client-credentials). Configure `.env.intune` at the repo root
(`INTUNE_TENANT_ID` / `INTUNE_CLIENT_ID` / `INTUNE_CLIENT_SECRET`) and grant the app
`DeviceManagementManagedDevices.Read.All` + `DeviceManagementConfiguration.Read.All`
(admin consent). Requires an active Intune license on the tenant.

Tools (all read-only): `list_managed_devices`, `get_compliance_summary`,
`get_managed_device`, `list_stale_devices`, `list_compliance_policies`,
`list_configuration_profiles`.
```

- [ ] **Step 2: Sync the workspace and verify import**

Run: `uv sync --all-packages`
Then: `uv run python -c "import f0_intune_mcp; print('ok')"`
Expected: `ok` (the new member installs and imports).

- [ ] **Step 3: Commit**

```bash
git add servers/intune-mcp/pyproject.toml servers/intune-mcp/README.md servers/intune-mcp/.env.intune.example servers/intune-mcp/f0_intune_mcp/__init__.py servers/intune-mcp/tests/__init__.py
git commit -m "feat(intune): scaffold read-only Intune MCP server workspace member

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TMoap3fRVq13TQah7BMdLm"
```

---

### Task 2: Device tools (list, get, stale, summary) — TDD

**Files:**
- Create: `servers/intune-mcp/f0_intune_mcp/tools.py`, `servers/intune-mcp/tests/test_tools.py`

**Interfaces:**
- Produces (each `async (gc: GraphClient, …) -> list[Finding]`):
  - `list_managed_devices(gc, compliance="all", limit=25)`
  - `get_compliance_summary(gc)`
  - `get_managed_device(gc, device_name)`
  - `list_stale_devices(gc, days=30, limit=25)`

- [ ] **Step 1: Write the failing tests**

Create `servers/intune-mcp/tests/test_tools.py`:
```python
import httpx
import pytest
import respx
from f0_intune_mcp.tools import (
    get_compliance_summary,
    get_managed_device,
    list_managed_devices,
    list_stale_devices,
)
from f0_sectools_core.auth.config import PlatformConfig
from f0_sectools_core.auth.graph import GraphClient

CFG = PlatformConfig(tenant_id="t", client_id="c", client_secret="s")
TOKEN_URL = "https://login.microsoftonline.com/t/oauth2/v2.0/token"
GRAPH = "https://graph.microsoft.com/v1.0"
DEV = GRAPH + "/deviceManagement/managedDevices"


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
            return_value=httpx.Response(200, json={"value": [_device("PC-2", "noncompliant")]}))
        async with GraphClient(CFG) as gc:
            findings = await list_managed_devices(gc, compliance="noncompliant")
    assert findings[0].severity.value == "high"
    # the compliance enum applied a $filter on complianceState
    assert "complianceState eq 'noncompliant'" in str(route.calls[0].request.url)


@pytest.mark.asyncio
async def test_list_managed_devices_403_permission_finding():
    with respx.mock as router:
        _token(router)
        router.get(DEV).mock(return_value=httpx.Response(403, json={"error": {"message": "Forbidden"}}))
        async with GraphClient(CFG) as gc:
            findings = await list_managed_devices(gc)
    assert findings[0].finding_type.value == "posture"
    assert "DeviceManagementManagedDevices.Read.All" in findings[0].title


@pytest.mark.asyncio
async def test_get_managed_device_by_name():
    with respx.mock as router:
        _token(router)
        route = router.get(DEV).mock(return_value=httpx.Response(200, json={"value": [_device("PC-7")]}))
        async with GraphClient(CFG) as gc:
            findings = await get_managed_device(gc, "PC-7")
    assert findings[0].entity.name == "PC-7"
    assert "deviceName eq 'PC-7'" in str(route.calls[0].request.url)


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
        router.get(DEV).mock(return_value=httpx.Response(200, json={"value": [fresh, stale]}))
        async with GraphClient(CFG) as gc:
            findings = await list_stale_devices(gc, days=30)
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
    assert ev["compliant"] == "40" and ev["noncompliant"] == "5"
    assert findings[0].severity.value in ("low", "medium", "high")  # 5 noncompliant present
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest servers/intune-mcp/tests/test_tools.py -q`
Expected: FAIL — `ModuleNotFoundError`/`ImportError` (tools.py doesn't exist yet).

- [ ] **Step 3: Implement `tools.py` (device tools)**

Create `servers/intune-mcp/f0_intune_mcp/tools.py`:
```python
"""Microsoft Intune read tools -> findings.

Read-only. Every tool catches a Graph 403 (or an unlicensed-Intune 4xx) and returns a
posture finding naming the missing permission, so a partially-configured or unlicensed
tenant still produces actionable guidance instead of failing. List tools use gc.get (a
single bounded page) to keep output small-model-safe.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from f0_sectools_core.auth.graph import GraphError
from f0_sectools_core.graph_errors import map_graph_error
from f0_sectools_core.schema.findings import (
    Entity,
    EntityKind,
    Evidence,
    Finding,
    FindingType,
    RecommendedAction,
    Severity,
)

_PERM = "DeviceManagementManagedDevices.Read.All"
_CONFIG_PERM = "DeviceManagementConfiguration.Read.All"

_COMPLIANCE_SEV = {
    "compliant": Severity.info,
    "configmanager": Severity.info,
    "ingraceperiod": Severity.low,
    "unknown": Severity.medium,
    "conflict": Severity.medium,
    "error": Severity.medium,
    "noncompliant": Severity.high,
}
# model-facing enum -> Graph complianceState filter value
_COMPLIANCE_FILTER = {
    "compliant": "compliant",
    "noncompliant": "noncompliant",
    "ingraceperiod": "inGracePeriod",
    "unknown": "unknown",
}
_DEVICE_SELECT = (
    "id,deviceName,operatingSystem,osVersion,complianceState,isEncrypted,"
    "managedDeviceOwnerType,lastSyncDateTime,userPrincipalName"
)


def _sev(state: str) -> Severity:
    return _COMPLIANCE_SEV.get(str(state).lower(), Severity.info)


def _device_finding(d: dict) -> Finding:
    name = d.get("deviceName") or d.get("id", "unknown")
    return Finding(
        source="intune",
        finding_type=FindingType.posture,
        severity=_sev(d.get("complianceState", "unknown")),
        title=f"Managed device {name}: {d.get('complianceState', 'unknown')}",
        entity=Entity(kind=EntityKind.host, id=str(d.get("id", "")), name=d.get("deviceName")),
        evidence=[
            Evidence(key="os", value=f"{d.get('operatingSystem', '')} {d.get('osVersion', '')}".strip()),
            Evidence(key="compliance", value=str(d.get("complianceState", ""))),
            Evidence(key="encrypted", value=str(d.get("isEncrypted", ""))),
            Evidence(key="owner", value=str(d.get("managedDeviceOwnerType", ""))),
            Evidence(key="user", value=str(d.get("userPrincipalName", ""))),
            Evidence(key="last_sync", value=str(d.get("lastSyncDateTime", ""))),
        ],
        observed_at=d.get("lastSyncDateTime"),
    )


async def list_managed_devices(gc: Any, compliance: str = "all", limit: int = 25) -> list[Finding]:
    params: dict = {"$top": limit, "$select": _DEVICE_SELECT}
    filt = _COMPLIANCE_FILTER.get(str(compliance).lower())
    if filt:
        params["$filter"] = f"complianceState eq '{filt}'"
    try:
        resp = await gc.get("/deviceManagement/managedDevices", params=params)
    except GraphError as e:
        finding = map_graph_error(e, "intune", _PERM, "Intune managed devices")
        if finding:
            return [finding]
        raise
    return [_device_finding(d) for d in (resp.get("value") or [])[:limit]]


async def get_managed_device(gc: Any, device_name: str) -> list[Finding]:
    params = {"$filter": f"deviceName eq '{device_name}'", "$select": _DEVICE_SELECT, "$top": 1}
    try:
        resp = await gc.get("/deviceManagement/managedDevices", params=params)
    except GraphError as e:
        finding = map_graph_error(e, "intune", _PERM, "Intune managed device lookup")
        if finding:
            return [finding]
        raise
    rows = resp.get("value") or []
    if not rows:
        return [
            Finding(
                source="intune",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"No managed device named {device_name} found in Intune",
                entity=Entity(kind=EntityKind.host, id=device_name, name=device_name),
                recommended_action=RecommendedAction(
                    summary="The device may be unmanaged, or its Defender name differs from its "
                    "Intune device name — confirm the hostname."
                ),
            )
        ]
    return [_device_finding(rows[0])]


def _parse_dt(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


async def list_stale_devices(gc: Any, days: int = 30, limit: int = 25) -> list[Finding]:
    # Prefer oldest-first so a bounded page surfaces the stalest devices; filter by cutoff
    # client-side (managedDevices doesn't reliably support a $filter on lastSyncDateTime).
    params = {"$top": limit, "$select": _DEVICE_SELECT, "$orderby": "lastSyncDateTime asc"}
    try:
        resp = await gc.get("/deviceManagement/managedDevices", params=params)
    except GraphError as e:
        finding = map_graph_error(e, "intune", _PERM, "Intune stale devices")
        if finding:
            return [finding]
        raise
    cutoff = datetime.now(UTC) - timedelta(days=days)
    out: list[Finding] = []
    for d in resp.get("value") or []:
        dt = _parse_dt(str(d.get("lastSyncDateTime", "")))
        if dt is not None and dt < cutoff:
            f = _device_finding(d)
            f.severity = Severity.medium
            f.title = f"Stale device {d.get('deviceName', d.get('id'))}: last sync {d.get('lastSyncDateTime', '')}"
            out.append(f)
    return out


async def get_compliance_summary(gc: Any) -> list[Finding]:
    try:
        s = await gc.get("/deviceManagement/deviceCompliancePolicyDeviceStateSummary")
    except GraphError as e:
        finding = map_graph_error(e, "intune", _PERM, "Intune compliance summary")
        if finding:
            return [finding]
        raise
    compliant = int(s.get("compliantDeviceCount", 0) or 0)
    noncompliant = int(s.get("nonCompliantDeviceCount", 0) or 0)
    grace = int(s.get("inGracePeriodCount", 0) or 0)
    unknown = int(s.get("unknownDeviceCount", 0) or 0)
    error = int(s.get("errorDeviceCount", 0) or 0)
    conflict = int(s.get("conflictDeviceCount", 0) or 0)
    total = compliant + noncompliant + grace + unknown + error + conflict
    sev = Severity.high if noncompliant else (Severity.low if (grace or unknown) else Severity.info)
    return [
        Finding(
            source="intune",
            finding_type=FindingType.posture,
            severity=sev,
            title=f"Intune device compliance: {compliant}/{total} compliant, {noncompliant} non-compliant",
            entity=Entity(kind=EntityKind.host, id="tenant"),
            evidence=[
                Evidence(key="total", value=str(total)),
                Evidence(key="compliant", value=str(compliant)),
                Evidence(key="noncompliant", value=str(noncompliant)),
                Evidence(key="in_grace_period", value=str(grace)),
                Evidence(key="unknown", value=str(unknown)),
                Evidence(key="error", value=str(error)),
                Evidence(key="conflict", value=str(conflict)),
            ],
            recommended_action=RecommendedAction(
                summary="Investigate non-compliant and unknown devices; list them with list_managed_devices."
            ),
        )
    ]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest servers/intune-mcp/tests/test_tools.py -q`
Expected: PASS (all device-tool tests).

- [ ] **Step 5: Commit**

```bash
git add servers/intune-mcp/f0_intune_mcp/tools.py servers/intune-mcp/tests/test_tools.py
git commit -m "feat(intune): device tools (list/get/stale/compliance-summary) + contract tests

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TMoap3fRVq13TQah7BMdLm"
```

---

### Task 3: Policy tools (compliance policies, configuration profiles) — TDD

**Files:**
- Modify: `servers/intune-mcp/f0_intune_mcp/tools.py` (append 2 functions)
- Modify: `servers/intune-mcp/tests/test_tools.py` (append tests)

**Interfaces:**
- Consumes: `_CONFIG_PERM`, `EntityKind`, `Finding`, `Severity` (from Task 2 tools.py).
- Produces: `list_compliance_policies(gc, limit=25)`, `list_configuration_profiles(gc, limit=25)`.

- [ ] **Step 1: Write the failing tests**

Append to `servers/intune-mcp/tests/test_tools.py`:
```python
from f0_intune_mcp.tools import list_compliance_policies, list_configuration_profiles

CPOL = GRAPH + "/deviceManagement/deviceCompliancePolicies"
CONF = GRAPH + "/deviceManagement/deviceConfigurations"


@pytest.mark.asyncio
async def test_list_compliance_policies_maps():
    with respx.mock as router:
        _token(router)
        router.get(CPOL).mock(return_value=httpx.Response(200, json={"value": [
            {"id": "p1", "displayName": "Win10 baseline", "description": "encryption required",
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
            {"id": "c1", "displayName": "Disk encryption", "description": "BitLocker",
             "@odata.type": "#microsoft.graph.windows10GeneralConfiguration"}]}))
        async with GraphClient(CFG) as gc:
            findings = await list_configuration_profiles(gc)
    assert "Disk encryption" in findings[0].title


@pytest.mark.asyncio
async def test_list_compliance_policies_403_names_config_permission():
    with respx.mock as router:
        _token(router)
        router.get(CPOL).mock(return_value=httpx.Response(403, json={"error": {"message": "Forbidden"}}))
        async with GraphClient(CFG) as gc:
            findings = await list_compliance_policies(gc)
    assert "DeviceManagementConfiguration.Read.All" in findings[0].title
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest servers/intune-mcp/tests/test_tools.py -q -k "compliance_policies or configuration_profiles"`
Expected: FAIL — `ImportError` on the two new functions.

- [ ] **Step 3: Implement the two policy tools**

Append to `servers/intune-mcp/f0_intune_mcp/tools.py`:
```python
def _policy_finding(p: dict, kind_label: str) -> Finding:
    name = p.get("displayName") or p.get("id", "unknown")
    odata = str(p.get("@odata.type", "")).split(".")[-1]
    return Finding(
        source="intune",
        finding_type=FindingType.posture,
        severity=Severity.info,
        title=f"Intune {kind_label}: {name}",
        entity=Entity(kind=EntityKind.policy, id=str(p.get("id", "")), name=p.get("displayName")),
        evidence=[
            Evidence(key="type", value=odata),
            Evidence(key="description", value=str(p.get("description") or "")),
        ],
    )


async def list_compliance_policies(gc: Any, limit: int = 25) -> list[Finding]:
    try:
        resp = await gc.get("/deviceManagement/deviceCompliancePolicies", params={"$top": limit})
    except GraphError as e:
        finding = map_graph_error(e, "intune", _CONFIG_PERM, "Intune compliance policies")
        if finding:
            return [finding]
        raise
    return [_policy_finding(p, "compliance policy") for p in (resp.get("value") or [])[:limit]]


async def list_configuration_profiles(gc: Any, limit: int = 25) -> list[Finding]:
    try:
        resp = await gc.get("/deviceManagement/deviceConfigurations", params={"$top": limit})
    except GraphError as e:
        finding = map_graph_error(e, "intune", _CONFIG_PERM, "Intune configuration profiles")
        if finding:
            return [finding]
        raise
    return [_policy_finding(p, "configuration profile") for p in (resp.get("value") or [])[:limit]]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest servers/intune-mcp/tests/test_tools.py -q`
Expected: PASS (all 10 tool tests).

- [ ] **Step 5: Commit**

```bash
git add servers/intune-mcp/f0_intune_mcp/tools.py servers/intune-mcp/tests/test_tools.py
git commit -m "feat(intune): compliance-policy and configuration-profile tools + tests

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TMoap3fRVq13TQah7BMdLm"
```

---

### Task 4: server.py — register the 6 MCP tools

**Files:**
- Create: `servers/intune-mcp/f0_intune_mcp/server.py`

**Interfaces:**
- Consumes: all 6 functions from `tools.py`.
- Produces: 6 `@mcp.tool()` async endpoints; the server module `f0_intune_mcp.server` exposing `mcp`.

- [ ] **Step 1: Write server.py**

Create `servers/intune-mcp/f0_intune_mcp/server.py`:
```python
"""Intune MCP server (stdio). Read-only tools over Microsoft Graph.

Loads credentials from the INTUNE_* environment (typically a `.env.intune` file),
opens a short-lived Graph client, maps results to findings, and redacts every payload
before returning it to the agent.
"""
from __future__ import annotations

from dotenv import load_dotenv
from f0_sectools_core.auth.config import PlatformConfig
from f0_sectools_core.auth.graph import GraphClient
from f0_sectools_core.redaction.redact import redact_obj
from f0_sectools_core.schema.findings import Finding
from mcp.server.fastmcp import FastMCP

from . import tools

load_dotenv(".env.intune")

mcp = FastMCP("f0-intune")


def _render(findings: list[Finding]) -> list[dict]:
    return [redact_obj(f.model_dump()) for f in findings]


@mcp.tool()
async def list_managed_devices(compliance: str = "all", limit: int = 25) -> list[dict]:
    """List Intune-managed devices with compliance/encryption/owner/sync state.

    compliance: one of all|compliant|noncompliant|ingraceperiod|unknown. limit: max devices.
    """
    cfg = PlatformConfig.from_env("INTUNE")
    async with GraphClient(cfg) as gc:
        return _render(await tools.list_managed_devices(gc, compliance, limit))


@mcp.tool()
async def get_compliance_summary() -> list[dict]:
    """Intune device-compliance rollup: how many managed devices are compliant vs not."""
    cfg = PlatformConfig.from_env("INTUNE")
    async with GraphClient(cfg) as gc:
        return _render(await tools.get_compliance_summary(gc))


@mcp.tool()
async def get_managed_device(device_name: str) -> list[dict]:
    """Get one Intune-managed device by its device name (compliance, encryption, owner, sync)."""
    cfg = PlatformConfig.from_env("INTUNE")
    async with GraphClient(cfg) as gc:
        return _render(await tools.get_managed_device(gc, device_name))


@mcp.tool()
async def list_stale_devices(days: int = 30, limit: int = 25) -> list[dict]:
    """List Intune devices not synced in the last `days` (coverage drift / abandoned)."""
    cfg = PlatformConfig.from_env("INTUNE")
    async with GraphClient(cfg) as gc:
        return _render(await tools.list_stale_devices(gc, days, limit))


@mcp.tool()
async def list_compliance_policies(limit: int = 25) -> list[dict]:
    """List Intune device COMPLIANCE POLICIES — the rules that define whether a device is compliant."""
    cfg = PlatformConfig.from_env("INTUNE")
    async with GraphClient(cfg) as gc:
        return _render(await tools.list_compliance_policies(gc, limit))


@mcp.tool()
async def list_configuration_profiles(limit: int = 25) -> list[dict]:
    """List Intune device CONFIGURATION PROFILES — the settings pushed to devices (not the compliance rules)."""
    cfg = PlatformConfig.from_env("INTUNE")
    async with GraphClient(cfg) as gc:
        return _render(await tools.list_configuration_profiles(gc, limit))


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Verify the server registers 6 tools**

Run:
```bash
uv run python -c "from f0_intune_mcp import server; import asyncio; print(sorted(t.name for t in asyncio.run(server.mcp.list_tools())))"
```
Expected: the 6 names — `get_compliance_summary`, `get_managed_device`, `list_compliance_policies`, `list_configuration_profiles`, `list_managed_devices`, `list_stale_devices`.

- [ ] **Step 3: Lint + full server test run**

Run: `uv run ruff check servers/intune-mcp/ && uv run pytest servers/intune-mcp/ -q`
Expected: lint clean, tests pass.

- [ ] **Step 4: Commit**

```bash
git add servers/intune-mcp/f0_intune_mcp/server.py
git commit -m "feat(intune): register the 6 read-only Intune MCP tools

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TMoap3fRVq13TQah7BMdLm"
```

---

### Task 5: Evals, live-smoke script, docs

**Files:**
- Create: `evals/intune/tasks.yaml`, `scripts/live_smoke_intune.py`
- Modify: `evals/run.py` (SERVER_MODULES), `evals/test_eval_coverage.py` (SERVERS), `CLAUDE.md`, `README.md`

**Interfaces:**
- Consumes: the 6 registered tool names.

- [ ] **Step 1: Add the eval task set**

Create `evals/intune/tasks.yaml`:
```yaml
# Small-model tool-calling eval task set — Microsoft Intune server.
# See evals/defender/tasks.yaml for the field schema. evals/test_eval_coverage.py
# enforces that every Intune tool has a task and every task names a real tool.

- prompt: "List our Intune-managed devices."
  expect_tool: list_managed_devices

- prompt: "Show me the non-compliant devices in Intune."
  expect_tool: list_managed_devices
  expect_args: { compliance: noncompliant }

- prompt: "How many of our devices are compliant?"
  expect_tool: get_compliance_summary

- prompt: "What's our device compliance posture?"
  expect_tool: get_compliance_summary

- prompt: "Look up the Intune device named PC-7."
  expect_tool: get_managed_device
  expect_args_contains: { device_name: PC-7 }

- prompt: "Which devices haven't checked in for a month?"
  expect_tool: list_stale_devices

- prompt: "List our Intune device compliance policies."
  expect_tool: list_compliance_policies

- prompt: "Show the Intune configuration profiles pushed to devices."
  expect_tool: list_configuration_profiles
```

- [ ] **Step 2: Register the server in the eval harness**

In `evals/run.py`, add to `SERVER_MODULES` (after the projectachilles line):
```python
    "intune": "f0_intune_mcp.server",
```

In `evals/test_eval_coverage.py`, add to `SERVERS` (after the projectachilles tuple):
```python
    ("intune", "f0_intune_mcp.server"),
```

- [ ] **Step 3: Run the coverage guard**

Run: `uv run pytest evals/test_eval_coverage.py -q`
Expected: PASS — every Intune tool (6) has a task and every task names a real tool.

**Then update the combined-eval hardcoded counts** (adding Intune's 6 tools + 8 tasks changes them). In `evals/test_combined.py`:
- lines ~23-24 in `test_combined_registry_unions_all_22_tools`: change both `== 22` to `== 28` (22 + 6 Intune tools). Also rename the test to `..._all_28_tools` for accuracy.
- line ~66 in `test_combined_tasks_tagged_with_origin_and_include_probes`: change `assert len(per_server) == 36` to `== 44` (36 + 8 Intune tasks), and update the comment that lists the per-server counts to include `+ 8 intune`.

Run: `uv run pytest evals/test_combined.py -q`
Expected: PASS after the count updates.

- [ ] **Step 4: Write the live-smoke script**

Create `scripts/live_smoke_intune.py`:
```python
"""Live smoke test for the Intune MCP server against a real tenant.

Usage (from the repo root):
    1. Copy servers/intune-mcp/.env.intune.example to ./.env.intune and fill in
       INTUNE_TENANT_ID / INTUNE_CLIENT_ID / INTUNE_CLIENT_SECRET (an Entra app with
       DeviceManagementManagedDevices.Read.All + DeviceManagementConfiguration.Read.All).
    2. uv run python scripts/live_smoke_intune.py

Calls each read tool against live Microsoft Graph and prints REDACTED findings.
Secrets are never printed. A missing permission/license shows up as a posture finding
(graceful degradation), not a crash.
"""
from __future__ import annotations

import asyncio
import json

from dotenv import load_dotenv
from f0_intune_mcp import tools
from f0_sectools_core.auth.config import PlatformConfig
from f0_sectools_core.auth.graph import GraphClient
from f0_sectools_core.redaction.redact import redact_obj

load_dotenv(".env.intune")


def _show(label: str, findings) -> None:
    print(f"\n=== {label}: {len(findings)} finding(s) ===")
    for f in findings[:8]:
        print(json.dumps(redact_obj(f.model_dump()), indent=2, default=str))
    if len(findings) > 8:
        print(f"... ({len(findings) - 8} more)")


async def main() -> None:
    cfg = PlatformConfig.from_env("INTUNE")
    print(f"Tenant {cfg.tenant_id[:8]}…  client {cfg.client_id[:8]}…  (secrets not shown)")
    async with GraphClient(cfg) as gc:
        _show("get_compliance_summary", await tools.get_compliance_summary(gc))
        _show("list_managed_devices", await tools.list_managed_devices(gc, limit=5))
        _show("list_managed_devices(noncompliant)", await tools.list_managed_devices(gc, "noncompliant", 5))
        _show("list_stale_devices", await tools.list_stale_devices(gc, days=30, limit=5))
        _show("list_compliance_policies", await tools.list_compliance_policies(gc, limit=5))
        _show("list_configuration_profiles", await tools.list_configuration_profiles(gc, limit=5))


if __name__ == "__main__":
    asyncio.run(main())
```

- [ ] **Step 5: Update docs**

In `CLAUDE.md`: add `intune-mcp/` to the `servers/` Architecture tree (after `projectachilles-mcp/`, `# built (live-validation pending)`); add an **Intune** row to the Platform Integrations table (`Intune | Identity/Endpoint mgmt | Entra app | devices, compliance, policies | — `). In `README.md`: add Intune to the servers/status list. (Match the surrounding style; keep edits minimal.)

- [ ] **Step 6: Full verification + commit**

Run: `uv run pytest -q && uv run ruff check .`
Expected: all pass, lint clean.

```bash
git add evals/intune/tasks.yaml evals/run.py evals/test_eval_coverage.py evals/test_combined.py scripts/live_smoke_intune.py CLAUDE.md README.md
git commit -m "feat(intune): evals, live-smoke script, and docs for the Intune server

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TMoap3fRVq13TQah7BMdLm"
```

---

### Task 6: Live validation (USER-GATED)

**Files:**
- Possibly modify: `servers/intune-mcp/f0_intune_mcp/tools.py` (fix-forward field/shape mismatches)

> This step calls a LIVE Microsoft tenant. It requires the operator to (a) grant the Entra app `DeviceManagementManagedDevices.Read.All` + `DeviceManagementConfiguration.Read.All` (admin consent) and confirm an Intune license, (b) create `.env.intune`, and (c) run the smoke with the shell sandbox disabled (network to Graph). PAUSE for the human — do not call the live tenant autonomously.

- [ ] **Step 1: Operator prepares creds + permissions**

Operator: copy `.env.intune.example` → `.env.intune`, fill the Entra app values (same app as `.env.entra` works), grant the two read permissions (admin consent), confirm Intune is licensed on the tenant.

- [ ] **Step 2: Run the live smoke (sandbox/network enabled)**

Run: `uv run python scripts/live_smoke_intune.py`
Expected: each tool prints findings. Likely 1-3 live field-shape mismatches to fix-forward (the recipe's known step — e.g. the compliance-summary field names, whether `$orderby lastSyncDateTime` is accepted, the `$filter deviceName eq` shape). If a permission/license is missing, expect a graceful posture finding (not a crash) — that still validates the degradation path.

- [ ] **Step 3: Fix-forward any mismatch and re-run**

For each mismatch, correct `tools.py` (real field names/query shapes), re-run the smoke, and re-run `uv run pytest servers/intune-mcp/ -q` to confirm the contract tests still hold (update a mock if the real shape differed). Commit fixes:
```bash
git add servers/intune-mcp/f0_intune_mcp/tools.py servers/intune-mcp/tests/test_tools.py
git commit -m "fix(intune): live-validated — real Graph field names/shapes

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TMoap3fRVq13TQah7BMdLm"
```

- [ ] **Step 4: Report** the live results (which tools returned data, any degradations, any fix-forwards). Skills (`skills/intune/*`) come in a follow-up now that the server is live-validated.

---

## Self-Review

**Spec coverage:**
- Mirror entra-mcp, reuse core, no core change → Task 1-4. ✓
- 6 read tools (list_managed_devices enum, get_compliance_summary, get_managed_device, list_stale_devices, list_compliance_policies, list_configuration_profiles) → Tasks 2-3. ✓
- Graceful 403/license/429/5xx via map_graph_error; every failure a Finding → all tools. ✓
- Bounded (gc.get single page), flat args, closed compliance enum → Task 2. ✓
- .env.intune isolation (Rule 7) → Task 1. ✓
- Contract tests (respx) → Tasks 2-3. Evals + register + smoke + docs → Task 5. Live-validate → Task 6. ✓
- Read-only, no writes → Global Constraints + tool set. ✓

**Deviations from spec (reconciled):** the spec's `get_compliance_summary` listed "encrypted count, stale count" alongside the compliance counts; the plan scopes the summary to **compliance-state counts** from the direct aggregate endpoint (accurate + single bounded call) and leaves encrypted/stale to the dedicated `list_managed_devices` (encrypted field) and `list_stale_devices` tools — accuracy over an approximate count from a capped scan. Noted so the reviewer expects it.

**Placeholder scan:** No TBD/TODO; every code step is complete. Task 5 Step 5 (docs prose) and Task 6 (live, human-run) are descriptive by nature.

**Type consistency:** `list_managed_devices(gc, compliance, limit)`, `get_compliance_summary(gc)`, `get_managed_device(gc, device_name)`, `list_stale_devices(gc, days, limit)`, `list_compliance_policies(gc, limit)`, `list_configuration_profiles(gc, limit)` are defined in Tasks 2-3 and called identically in server.py (Task 4), the tests, and the smoke script (Task 5). `_PERM`/`_CONFIG_PERM`, `_device_finding`, `_policy_finding`, `EntityKind.host`/`.policy` consistent throughout. Eval registration keys (`"intune"` / `"f0_intune_mcp.server"`) match between run.py and test_eval_coverage.py.
