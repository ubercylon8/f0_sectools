"""The last line of defence on a tool's return path: nothing escapes unredacted.

Every server maps the errors it *expects* -- auth, permission, licensing, rate
limit -- into posture findings. What is left over is the problem: a DNS or TLS
failure, an HTTP status no mapper claims, or a bug in our own mapping code.
Those propagate out of the tool, past the server's ``_render``, and reach the
MCP client as a raw exception string. That breaks two Critical Rules at once --
the text never passes through redaction (Rule 3), and the tool returns no
finding at all (Rule 4).

``guarded_tool`` closes that path once, here, so that no server has to remember
to. It is applied *beneath* ``@mcp.tool()`` on every registered tool, which is
the only place wide enough to catch a failure in client construction, in the
tool body, and in the mapping code alike.

Deliberately catches ``Exception`` and not ``BaseException``: cancellation and
interrupts must keep propagating so a shutting-down server actually shuts down.
"""

from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar, cast

from f0_sectools_core.redaction.redact import redact_finding
from f0_sectools_core.schema.findings import (
    Entity,
    EntityKind,
    Evidence,
    Finding,
    FindingType,
    RecommendedAction,
    Severity,
)

__all__ = ["MAX_ERROR_CHARS", "guarded_tool", "unexpected_error_finding"]

# An exception message can carry an entire HTTP response body. Bounded output is
# a repo rule, and an unbounded error is the worst kind of context flood --
# it arrives exactly when the model is already off its intended path.
MAX_ERROR_CHARS = 300


def unexpected_error_finding(source: str, capability: str, exc: BaseException) -> Finding:
    """A posture finding standing in for an error no server mapper claimed.

    The title carries "temporarily unavailable" on purpose: that string is one
    of ``core/reports``' DEGRADATION_MARKERS, so a generated report files this
    under coverage ("not assessed") rather than counting an infrastructure
    failure as a security finding.

    The message is included, truncated, and left to the standard redaction pass
    -- Critical Rule 3 requires stripping secrets from error text, not
    discarding the text, and a caller with no detail cannot act.
    """
    detail = str(exc)
    if len(detail) > MAX_ERROR_CHARS:
        detail = detail[:MAX_ERROR_CHARS] + "…"
    return Finding(
        source=source,
        finding_type=FindingType.posture,
        severity=Severity.info,
        title=f"{capability} temporarily unavailable — unexpected {type(exc).__name__}",
        entity=Entity(kind=EntityKind.tenant, id=source),
        evidence=[
            Evidence(key="error_type", value=type(exc).__name__),
            Evidence(key="error", value=detail),
        ],
        recommended_action=RecommendedAction(
            summary="Retry once. If it persists, check host connectivity and the "
            "platform's service health before treating it as a data finding.",
        ),
    )


F = TypeVar("F", bound=Callable[..., Awaitable[list[dict[str, Any]]]])


def guarded_tool(source: str) -> Callable[[F], F]:
    """Turn any unmapped exception into one redacted finding.

    ``functools.wraps`` keeps ``__name__``/``__doc__``/``__wrapped__`` intact so
    the MCP layer still derives the same tool name, description and argument
    schema from the wrapped function -- the decorator must be invisible to
    schema generation, or it would silently change every tool's contract.
    """

    def decorate(fn: F) -> F:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> list[dict[str, Any]]:
            try:
                return await fn(*args, **kwargs)
            except Exception as exc:
                finding = unexpected_error_finding(source, fn.__name__, exc)
                return [redact_finding(finding).model_dump()]

        return cast(F, wrapper)

    return decorate
