"""Map Sentinel API errors to graceful findings (Critical Rule: never raise)."""
from __future__ import annotations

from typing import Literal

from f0_sectools_core.auth.graph import GraphError
from f0_sectools_core.schema.findings import (
    Finding,
    FindingType,
    RecommendedAction,
    Severity,
)

_ROLE = {
    "logs": "Log Analytics Reader",
    "arm": "Microsoft Sentinel Reader",
}


def map_sentinel_error(
    e: Exception, capability: str, half: Literal["logs", "arm"] = "logs"
) -> Finding | None:
    """Return a graceful finding for known Sentinel errors, else None (caller re-raises).

    ``half`` selects which Azure role the operator is told to grant. The logs
    (KQL) and objects (ARM) halves are authorized independently, so naming the
    wrong role sends the operator to the wrong blade.
    """
    if not isinstance(e, GraphError):
        return None
    role = _ROLE.get(half, _ROLE["logs"])

    if e.status == 401:
        return Finding(
            source="sentinel",
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=f"Sentinel authentication failed — {capability} unavailable",
            recommended_action=RecommendedAction(
                summary="Check SENTINEL_TENANT_ID / SENTINEL_CLIENT_ID / "
                "SENTINEL_CLIENT_SECRET in .env.sentinel.",
                confidence="high",
            ),
        )
    if e.status == 403:
        return Finding(
            source="sentinel",
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=f"Sentinel permission missing — {capability} unavailable",
            recommended_action=RecommendedAction(
                summary=f"Grant the app the '{role}' role on the Log Analytics "
                "workspace resource, then retry.",
                confidence="high",
            ),
        )
    if e.status == 429:
        return Finding.rate_limited("sentinel", capability)
    if e.status in (502, 503):
        return Finding.api_unavailable("sentinel", capability, e.status)
    if e.status == 504:
        return Finding(
            source="sentinel",
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=f"Sentinel query timed out — {capability}",
            recommended_action=RecommendedAction(
                summary="Narrow the search: reduce hours, or supply an indicator "
                "so the query filters before it scans.",
                confidence="high",
            ),
        )
    if e.status == 400:
        # The KQL was rejected. Hand the sanitized reason back so the model can
        # correct itself instead of blindly retrying the same broken query.
        return Finding(
            source="sentinel",
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=f"Sentinel rejected the query — {capability}: {e.message[:300]}",
            recommended_action=RecommendedAction(
                summary="The column or operator does not exist in this workspace. "
                "Use list_data_sources to see which tables exist, then retry.",
                confidence="medium",
            ),
        )
    return None
