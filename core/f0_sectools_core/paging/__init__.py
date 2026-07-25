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


def truncation_finding(
    source: str,
    shown: int,
    fetched: int,
    total: int | None = None,
    has_more: bool = False,
    hint: str = "",
) -> Finding | None:
    """A "showing M of N" note, or None when nothing was actually cut.

    Platform-free: each server extracts its own truncation signals (Graph's
    @odata.count/@odata.nextLink, a vendor `total`, or simply the length of a
    full list) and passes the numbers here, so the "did we hide anything?"
    decision is made once.

    `shown` is how many findings are being returned; `fetched` is how many
    records the platform handed back. They differ whenever a tool refines
    results client-side, and truncation is judged on `fetched` — a refinement
    that drops rows is not a page that was cut short, and reporting it as one
    tells the caller to raise a limit that will not help.

    A known `total` is authoritative: if it does not exceed what we fetched,
    there is nothing more, whatever other signals say.
    """
    if total is not None:
        if total > fetched:
            return more_available_finding(source, shown=shown, total=total, hint=hint)
        return None
    if has_more:
        return more_available_finding(source, shown=shown, hint=hint)
    return None


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
