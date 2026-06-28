"""Map limacharlie SDK errors to graceful findings.

Mirrors core's map_graph_error: a permission error names the likely missing
LimaCharlie permission, a rate-limit becomes a "throttled" finding, and an auth
failure points at the credentials — none of them crash the tool.
"""
from __future__ import annotations

from f0_sectools_core.schema.findings import (
    Finding,
    FindingType,
    RecommendedAction,
    Severity,
)
from limacharlie.errors import (
    AuthenticationError,
    PermissionDeniedError,
    RateLimitError,
)


def map_lc_error(e: Exception, capability: str, permission: str) -> Finding | None:
    """Return a graceful finding for known LC errors, else None (caller re-raises)."""
    if isinstance(e, PermissionDeniedError):
        return Finding.permission_missing("limacharlie", permission, capability)
    if isinstance(e, RateLimitError):
        return Finding.rate_limited("limacharlie", capability)
    if isinstance(e, AuthenticationError):
        return Finding(
            source="limacharlie",
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=f"LimaCharlie authentication failed — {capability} unavailable",
            recommended_action=RecommendedAction(
                summary="Check LIMACHARLIE_OID / LIMACHARLIE_API_KEY (key needs read access).",
                confidence="high",
            ),
        )
    return None
