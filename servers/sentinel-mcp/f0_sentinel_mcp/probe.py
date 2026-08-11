"""Runtime capability probe: which tables does THIS workspace actually have?

Built on the `Usage` table, deliberately NOT on the `dataConnectors` management
API. Measured 2026-08-11 on the validation tenant: `dataConnectors` reported a
single connector (Office365) while at least six sources were actively ingesting
— AMA/DCR and codeless connectors never register there. A coverage answer built
on that API would systematically understate reality.

Cached per workspace for the process lifetime: reads are idempotent and the set
of ingesting tables does not change within a session.
"""
from __future__ import annotations

from typing import Any

from f0_sectools_core.schema.findings import (
    Finding,
    FindingType,
    RecommendedAction,
    Severity,
)

_CACHE: dict[str, set[str]] = {}

# No IsBillable filter: free-tier tables (SecurityIncident, SecurityAlert,
# OfficeActivity on some SKUs) are absent from a billable-only Usage roll-up,
# and those are exactly the tables three of our tools depend on.
_USAGE_KQL = (
    "Usage | where TimeGenerated > ago(30d) "
    "| summarize GB=round(sum(Quantity)/1024, 3) by DataType | sort by GB desc"
)


async def probed_tables(client: Any) -> set[str]:
    """The set of table names with data in the last 30d. Cached per workspace."""
    key = str(getattr(client, "workspace_id", "default"))
    cached = _CACHE.get(key)
    if cached is not None:
        return cached
    rows = await client.query(_USAGE_KQL, "P30D")
    tables = {str(r.get("DataType", "")) for r in rows if r.get("DataType")}
    _CACHE[key] = tables
    return tables


def reset_cache() -> None:
    """Clear the probe cache (tests, and the live smoke script between runs)."""
    _CACHE.clear()


async def require_table(client: Any, table: str, human: str) -> Finding | None:
    """None if the workspace has `table`, else a posture finding saying so.

    Returning a posture finding rather than an empty list is the whole point: an
    empty list reads as "nothing matched your search", which is a different — and
    wrong — answer from "this workspace has no such feed".
    """
    if table in await probed_tables(client):
        return None
    return Finding(
        source="sentinel",
        finding_type=FindingType.posture,
        severity=Severity.info,
        title=f"No {human} data in this workspace ({table} is not ingesting)",
        recommended_action=RecommendedAction(
            summary="Use list_data_sources to see which telemetry this workspace "
            "does have, then pick a tool that matches it.",
            confidence="high",
        ),
    )
