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
from f0_sectools_core.paging import clamp_limit
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


def _device_finding(d: dict[str, Any]) -> Finding:
    name = d.get("deviceName") or d.get("id", "unknown")
    os_str = f"{d.get('operatingSystem', '')} {d.get('osVersion', '')}".strip()
    return Finding(
        source="intune",
        finding_type=FindingType.posture,
        severity=_sev(d.get("complianceState", "unknown")),
        title=f"Managed device {name}: {d.get('complianceState', 'unknown')}",
        entity=Entity(kind=EntityKind.host, id=str(d.get("id", "")), name=d.get("deviceName")),
        evidence=[
            Evidence(key="os", value=os_str),
            Evidence(key="compliance", value=str(d.get("complianceState", ""))),
            Evidence(key="encrypted", value=str(d.get("isEncrypted", ""))),
            Evidence(key="owner", value=str(d.get("managedDeviceOwnerType", ""))),
            Evidence(key="user", value=str(d.get("userPrincipalName", ""))),
            Evidence(key="last_sync", value=str(d.get("lastSyncDateTime", ""))),
        ],
        observed_at=d.get("lastSyncDateTime"),
    )


async def list_managed_devices(gc: Any, compliance: str = "all", limit: int = 25) -> list[Finding]:
    limit = clamp_limit(limit)
    params: dict[str, Any] = {"$top": limit, "$select": _DEVICE_SELECT}
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
    # managedDevices silently IGNORES $orderby on lastSyncDateTime (confirmed live: asc and
    # desc return identical unordered pages), so an oldest-first page is impossible. It DOES
    # honor a server-side $filter, so select stale devices directly and bound to `limit`.
    # The client-side cutoff check below stays as a defensive backstop.
    limit = clamp_limit(limit)
    cutoff = datetime.now(UTC) - timedelta(days=days)
    cutoff_iso = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
    params = {
        "$top": limit,
        "$select": _DEVICE_SELECT,
        "$filter": f"lastSyncDateTime le {cutoff_iso}",
    }
    try:
        resp = await gc.get("/deviceManagement/managedDevices", params=params)
    except GraphError as e:
        finding = map_graph_error(e, "intune", _PERM, "Intune stale devices")
        if finding:
            return [finding]
        raise
    out: list[Finding] = []
    for d in resp.get("value") or []:
        dt = _parse_dt(str(d.get("lastSyncDateTime", "")))
        if dt is not None and dt < cutoff:
            f = _device_finding(d)
            f.severity = Severity.medium
            dev_name = d.get("deviceName", d.get("id"))
            last_sync = d.get("lastSyncDateTime", "")
            f.title = f"Stale device {dev_name}: last sync {last_sync}"
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
            title=(
                f"Intune device compliance: {compliant}/{total} compliant, "
                f"{noncompliant} non-compliant"
            ),
            entity=Entity(kind=EntityKind.host, id="tenant"),
            evidence=[
                Evidence(key="devices_total", value=str(total)),
                Evidence(key="devices_compliant", value=str(compliant)),
                Evidence(key="devices_noncompliant", value=str(noncompliant)),
                Evidence(key="devices_in_grace_period", value=str(grace)),
                Evidence(key="devices_unknown", value=str(unknown)),
                Evidence(key="devices_error", value=str(error)),
                Evidence(key="devices_conflict", value=str(conflict)),
            ],
            recommended_action=RecommendedAction(
                summary=(
                    "Investigate non-compliant and unknown devices; "
                    "list them with list_managed_devices."
                )
            ),
        )
    ]


def _policy_finding(p: dict[str, Any], kind_label: str) -> Finding:
    name = p.get("displayName") or p.get("id", "unknown")
    odata = str(p.get("@odata.type", "")).split(".")[-1]
    return Finding(
        source="intune",
        finding_type=FindingType.posture,
        severity=Severity.info,
        title=f"Intune {kind_label}: {name}",
        entity=Entity(
            kind=EntityKind.policy,
            id=str(p.get("id", "")),
            name=p.get("displayName"),
        ),
        evidence=[
            Evidence(key="type", value=odata),
            Evidence(key="description", value=str(p.get("description") or "")),
        ],
    )


async def list_compliance_policies(gc: Any, limit: int = 25) -> list[Finding]:
    limit = clamp_limit(limit)
    try:
        resp = await gc.get(
            "/deviceManagement/deviceCompliancePolicies", params={"$top": limit}
        )
    except GraphError as e:
        finding = map_graph_error(
            e, "intune", _CONFIG_PERM, "Intune compliance policies"
        )
        if finding:
            return [finding]
        raise
    return [
        _policy_finding(p, "compliance policy")
        for p in (resp.get("value") or [])[:limit]
    ]


async def list_configuration_profiles(gc: Any, limit: int = 25) -> list[Finding]:
    limit = clamp_limit(limit)
    try:
        resp = await gc.get(
            "/deviceManagement/deviceConfigurations", params={"$top": limit}
        )
    except GraphError as e:
        finding = map_graph_error(
            e, "intune", _CONFIG_PERM, "Intune configuration profiles"
        )
        if finding:
            return [finding]
        raise
    return [
        _policy_finding(p, "configuration profile")
        for p in (resp.get("value") or [])[:limit]
    ]
