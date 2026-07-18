"""Map ProjectAchilles HTTP errors to graceful findings (write-aware)."""
from __future__ import annotations

from f0_sectools_core.schema.findings import (
    Evidence,
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
            "projectachilles", "a read-write-scope pa_ API key", capability
        )
    if e.status == 429:
        return Finding.rate_limited("projectachilles", capability)
    if e.status in (502, 503, 504):
        return Finding.api_unavailable("projectachilles", capability, e.status)
    if e.status in (400, 404, 409, 422):
        return Finding(
            source="projectachilles",
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=f"ProjectAchilles rejected the request (HTTP {e.status}) — {capability}",
            evidence=[Evidence(key="error", value=e.message)],
            recommended_action=RecommendedAction(
                summary="Check the id/arguments and retry. If a confirmation token "
                "was consumed, issue a fresh one.",
                confidence="high",
            ),
        )
    return None
