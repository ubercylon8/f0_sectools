"""Map Tenable HTTP errors to graceful findings."""
from __future__ import annotations

from f0_sectools_core.schema.findings import (
    Finding,
    FindingType,
    RecommendedAction,
    Severity,
)

from .client import TenableError


def map_tenable_error(e: Exception, capability: str) -> Finding | None:
    """Return a graceful finding for known Tenable errors, else None (caller re-raises)."""
    if not isinstance(e, TenableError):
        return None
    if e.status == 401:
        return Finding(
            source="tenable",
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=f"Tenable authentication failed — {capability} unavailable",
            recommended_action=RecommendedAction(
                summary="Check TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY "
                "(valid, non-revoked API keys).",
                confidence="high",
            ),
        )
    if e.status == 403:
        return Finding.permission_missing(
            "tenable", "a read-scope Tenable role", capability
        )
    if e.status == 429:
        return Finding.rate_limited("tenable", capability)
    if e.status in (502, 503, 504):
        return Finding.api_unavailable("tenable", capability, e.status)
    return None
