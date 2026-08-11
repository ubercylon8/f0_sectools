"""Microsoft Sentinel read tools -> findings.

Read-only. Every API failure maps to a posture finding, never an exception.
Table and field names were validated against a live workspace on 2026-08-11;
dict access is defensive throughout because the next workspace differs.
"""
from __future__ import annotations

from typing import Any

from f0_sectools_core.auth.graph import GraphError
from f0_sectools_core.paging import clamp_limit, more_available_finding
from f0_sectools_core.schema.findings import (
    Entity,
    EntityKind,
    Evidence,
    Finding,
    FindingType,
    RecommendedAction,
    Severity,
)

from . import normalize as n
from .errors import map_sentinel_error
from .probe import probed_tables, require_table

_FAMILY_PREFIX = (
    ("CommonSecurityLog", "firewall"),
    ("Cisco_Umbrella", "dns_web"),
    ("OfficeActivity", "office"),
    ("SecurityIncident", "incident"),
    ("SecurityAlert", "incident"),
    ("SigninLogs", "identity"),
    ("AAD", "identity"),
    ("IdentityInfo", "identity"),
    ("BehaviorAnalytics", "identity"),
    ("Syslog", "firewall"),
)


def _family(table: str) -> str:
    for prefix, fam in _FAMILY_PREFIX:
        if table.startswith(prefix):
            return fam
    return "custom"


def _bad_arg(name: str, value: str, accepted: str) -> Finding:
    """A rejected argument is reported, never silently dropped from the filter."""
    return Finding(
        source="sentinel",
        finding_type=FindingType.posture,
        severity=Severity.info,
        title=f"Unsupported {name} '{value[:60]}'",
        recommended_action=RecommendedAction(summary=f"Accepted: {accepted}.", confidence="high"),
    )


async def list_data_sources(client: Any) -> list[Finding]:
    """What telemetry this workspace actually ingests (last 30 days), by volume.

    Each table's finding carries its rounded GB and a one-word family label as
    evidence, and the list is sorted by GB descending -- a 250 GB/30d feed and a
    0.02 GB/30d trickle are very different claims about what this workspace can
    answer, so the volume figure the probe already computed is not discarded.
    """
    cap = "Sentinel data sources"
    try:
        table_gb = await probed_tables(client)
    except GraphError as e:
        mapped = map_sentinel_error(e, cap, half="logs")
        if mapped:
            return [mapped]
        raise

    if not table_gb:
        return [
            Finding(
                source="sentinel",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title="No telemetry found in this Sentinel workspace (last 30 days)",
                recommended_action=RecommendedAction(
                    summary="Check that connectors are configured and the app has "
                    "the Log Analytics Reader role.",
                ),
            )
        ]

    tables = sorted(table_gb, key=lambda t: table_gb[t], reverse=True)
    findings = [
        Finding(
            source="sentinel",
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=f"{len(tables)} tables ingesting in this Sentinel workspace (30d)",
            entity=Entity(kind=EntityKind.tenant, id="sentinel"),
            evidence=[Evidence(key="table_count", value=str(len(tables)))],
        )
    ]
    for t in tables:
        findings.append(
            Finding(
                source="sentinel",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"{t} — ingesting",
                entity=Entity(kind=EntityKind.tenant, id=t, name=t),
                evidence=[
                    Evidence(key="family", value=_family(t)),
                    Evidence(key="gb_30d", value=f"{table_gb[t]:.2f}"),
                ],
            )
        )
    return findings


_INDICATOR_HELP = {
    "net": "an IP address or a port number (this table carries no URLs or "
    "usernames — for domains and URLs use hunt_dns_web)",
    "domain": "a domain, URL fragment, or IP",
}


def _rows_to_findings(rows: list[dict[str, Any]], title_key: str, limit: int) -> list[Finding]:
    out: list[Finding] = []
    for r in rows[:limit]:
        out.append(
            Finding(
                source="sentinel",
                finding_type=FindingType.hunt_result,
                severity=Severity.info,
                title=str(r.get(title_key) or "event"),
                evidence=[
                    Evidence(key=str(k), value=str(v))
                    for k, v in r.items()
                    if v is not None and str(v) != ""
                ][:12],
                observed_at=str(r.get("TimeGenerated") or "") or None,
            )
        )
    return out


async def _run_surface(
    client: Any,
    spec: n.Surface,
    cap: str,
    human: str,
    action: str,
    indicator: str,
    hours: float,
    limit: int,
) -> list[Finding]:
    """Shared execution path for every KQL telemetry surface.

    Bounding rules live here so no individual tool can forget one: time
    predicate first, retention clamp, limit clamp, and aggregate-only whenever
    no indicator narrows the scan.
    """
    if action not in n.ACTIONS:
        return [_bad_arg("action", action, ", ".join(n.ACTIONS))]
    if not n.validate_indicator(indicator, spec.indicator_kind):
        return [_bad_arg("indicator", indicator, _INDICATOR_HELP[spec.indicator_kind])]

    missing = await require_table(client, spec.table, human)
    if missing:
        return [missing]

    hours = n.clamp_hours(hours, client.retention_days)
    limit = clamp_limit(limit)

    parts = [
        spec.table,
        f"| where TimeGenerated > ago({hours:g}h)",
        n.hygiene_clause(spec),
        n.action_clause(spec, action),
        n.indicator_clause(spec, indicator),
    ]
    if indicator:
        parts.append(f"| project {', '.join(spec.project)}")
        parts.append(f"| order by TimeGenerated desc | take {limit}")
    else:
        # No indicator -> aggregate. Never dump rows from a table this large.
        parts.append(
            f"| summarize Events=count() by {spec.action_field}, {spec.indicator_fields[0]}"
        )
        parts.append(f"| top {limit} by Events desc")
    kql = " ".join(p for p in parts if p)

    try:
        rows = await client.query(kql, n.timespan(hours))
    except GraphError as e:
        mapped = map_sentinel_error(e, cap, half="logs")
        if mapped:
            return [mapped]
        raise

    if not rows:
        return [
            Finding(
                source="sentinel",
                finding_type=FindingType.hunt_result,
                severity=Severity.info,
                title=f"No {human} activity matched in the last {hours:g}h",
                recommended_action=RecommendedAction(
                    summary="Widen hours, relax action, or drop the indicator.",
                ),
            )
        ]

    title_key = spec.indicator_fields[0] if indicator else spec.action_field
    findings = _rows_to_findings(rows, title_key, limit)
    if len(rows) >= limit:
        findings.append(
            more_available_finding(
                "sentinel", shown=len(findings),
                hint="Narrow with an indicator or a shorter hours window.",
            )
        )
    return findings


async def hunt_firewall(
    client: Any,
    action: str = "any",
    indicator: str = "",
    hours: float = 24,
    limit: int = 25,
) -> list[Finding]:
    """Firewall traffic from the CEF table (Check Point / Fortinet)."""
    return await _run_surface(
        client, n.SURFACE_SPECS["firewall"],
        cap="Sentinel firewall telemetry", human="firewall (CEF)",
        action=action, indicator=indicator, hours=hours, limit=limit,
    )
