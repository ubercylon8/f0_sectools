"""Pagination, truncation, and rate-limiting to keep payloads small-model-safe."""
from __future__ import annotations

from f0_sectools_core.schema.findings import (
    Entity,
    EntityKind,
    Finding,
    FindingType,
    RecommendedAction,
    Severity,
)

DEFAULT_LIMIT = 25
MAX_LIMIT = 100


def clamp_limit(limit: object, default: int = DEFAULT_LIMIT, maximum: int = MAX_LIMIT) -> int:
    """Bound a caller-supplied page size to [1, maximum]; invalid -> default.

    Small local models sometimes pass an oversized limit; an unbounded dump blows
    the context window and degrades tool accuracy (Critical Rule 5).
    """
    try:
        n: int = int(limit)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return default
    if n < 1:
        return 1
    return min(n, maximum)


def more_available_finding(
    source: str, shown: int, total: int | None = None, hint: str = ""
) -> Finding:
    """An info finding signalling a truncated result set, so a model stops re-querying."""
    if total is not None:
        title = (
            f"Showing {shown} of {total} — narrow the filter or raise limit "
            f"(max {MAX_LIMIT}) to see more."
        )
    else:
        title = (
            f"Showing {shown}; more results available — narrow the filter or raise "
            f"limit (max {MAX_LIMIT}) to see more."
        )
    return Finding(
        source=source,
        finding_type=FindingType.posture,
        severity=Severity.info,
        title=title,
        entity=Entity(kind=EntityKind.tenant, id=source),
        recommended_action=RecommendedAction(
            summary=hint or "Add a filter (severity_min, hostname) or raise limit to page further.",
        ),
    )
