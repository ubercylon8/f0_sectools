"""Microsoft Sentinel read tools -> findings.

Read-only. Every API failure maps to a posture finding, never an exception.
Table and field names were validated against a live workspace on 2026-08-11;
dict access is defensive throughout because the next workspace differs.
"""
from __future__ import annotations

from typing import Any

from f0_sectools_core.auth.graph import GraphError
from f0_sectools_core.schema.findings import (
    Entity,
    EntityKind,
    Evidence,
    Finding,
    FindingType,
    RecommendedAction,
    Severity,
)

from .errors import map_sentinel_error
from .probe import probed_tables

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
    """What telemetry this workspace actually ingests (last 30 days), sorted by name.

    Table names come from the probe as a set (no per-table volume is retained),
    so this list is alphabetical, not ranked by ingestion volume.
    """
    cap = "Sentinel data sources"
    try:
        tables = sorted(await probed_tables(client))
    except GraphError as e:
        mapped = map_sentinel_error(e, cap, half="logs")
        if mapped:
            return [mapped]
        raise

    if not tables:
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
                evidence=[Evidence(key="family", value=_family(t))],
            )
        )
    return findings
