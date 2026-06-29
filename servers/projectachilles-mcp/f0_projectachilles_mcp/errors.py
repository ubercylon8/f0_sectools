"""Map ProjectAchilles HTTP errors to graceful findings."""
from __future__ import annotations

from f0_sectools_core.schema.findings import (
    Finding,
    FindingType,
    RecommendedAction,
    Severity,
)

from .client import ProjectAchillesError


def map_pa_error(e: Exception, capability: str) -> Finding | None:
    """Return a graceful finding for known PA errors, else None (caller re-raises)."""
    if not isinstance(e, ProjectAchillesError):
        return None
    if e.status == 401:
        return Finding(
            source="projectachilles",
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=f"ProjectAchilles authentication failed — {capability} unavailable",
            recommended_action=RecommendedAction(
                summary="Check PROJECTACHILLES_BASE_URL and PROJECTACHILLES_API_KEY "
                "(a valid, non-revoked pa_ key).",
                confidence="high",
            ),
        )
    if e.status == 403:
        return Finding.permission_missing(
            "projectachilles", "a read-scope API key", capability
        )
    if e.status == 429:
        return Finding.rate_limited("projectachilles", capability)
    if e.status in (502, 503, 504):
        return Finding(
            source="projectachilles",
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=f"ProjectAchilles API temporarily unavailable (HTTP {e.status}) — "
            f"{capability} deferred",
            recommended_action=RecommendedAction(
                summary="The PA API gateway returned an upstream error; confirm the "
                "backend is running, then retry.",
                confidence="high",
            ),
        )
    return None
