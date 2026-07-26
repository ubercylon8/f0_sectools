"""Microsoft Purview read tools -> findings (data-risk pillar).

Read-only. Every Graph failure maps to a posture finding (permission missing /
rate limited / unavailable), never an exception. Field names and the
serviceSource enum values are ASSUMPTIONS until the live smoke confirms them
(recipe step 9); dict access is defensive throughout.
"""
from __future__ import annotations

import asyncio
import re
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from f0_sectools_core.auth.graph import GraphError
from f0_sectools_core.graph_errors import map_graph_error
from f0_sectools_core.paging import (
    clamp_limit,
    more_available_finding,
    truncation_finding,
)
from f0_sectools_core.schema.findings import (
    Entity,
    EntityKind,
    Evidence,
    Finding,
    FindingType,
    RecommendedAction,
    Severity,
)

_ALERT_PERM = "SecurityAlert.Read.All"
_AUDIT_PERM = "AuditLogsQuery.Read.All"
_LABEL_PERM = "InformationProtectionPolicy.Read.All"

# serviceSource enum constants, LIVE-CONFIRMED 2026-07-21: DLP is the
# unprefixed 'dataLossPrevention' (the 'microsoft…' guess 400s as an invalid
# enumeration constant); IRM is 'microsoftInsiderRiskManagement'.
_DLP_SOURCE = "dataLossPrevention"
_IRM_SOURCE = "microsoftInsiderRiskManagement"

# Graph beta is required for the labels inventory AND (live-confirmed 2026-07-21)
# the Audit Search API — the documented v1.0 audit path 404s on the real tenant
# while beta serves it. GraphClient passes absolute URLs through unchanged.
_LABELS_BETA_URL = (
    "https://graph.microsoft.com/beta/security/informationProtection/sensitivityLabels"
)
_AUDIT_QUERIES_URL = "https://graph.microsoft.com/beta/security/auditLog/queries"

_SEV = {"informational": Severity.info, "low": Severity.low,
        "medium": Severity.medium, "high": Severity.high}
_SEV_ORDER = ["low", "medium", "high"]

# Filter values are spliced into Graph OData filters / API paths — guard charsets.
_ACTIVITY_RE = re.compile(r"^[A-Za-z0-9 ._-]{1,64}$")
_UPN_RE = re.compile(r"^[A-Za-z0-9@._-]{1,128}$")
_QUERY_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")

# Poll briefly, then hand back the query id: real tenant audit queries take
# 5-15+ minutes, so a long blocking poll only produced "timed out" UX (live
# opencode run 2026-07-21) without ever completing in-call.
_POLL_DEADLINE_S = 15.0
_POLL_INTERVAL_S = 5.0
# Small models resubmit identical searches when results aren't ready, spawning
# a fresh multi-minute server-side query each time. Dedupe: an identical
# search (same filters/window) within the TTL reuses the in-flight query. The
# stored (query_id, monotonic_ts, window_str) lets a reuse report the ORIGINAL
# queried window, not a freshly recomputed one.
_RECENT_SEARCHES: dict[tuple[str, str, float], tuple[str, float, str]] = {}
_REUSE_TTL_S = 1800.0
_FETCH_CAP = 100  # single bounded page for summaries/lists


def _since_iso(hours_back: float) -> str:
    return (datetime.now(UTC) - timedelta(hours=hours_back)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _sev(value: Any) -> Severity:
    return _SEV.get(str(value).lower(), Severity.medium)


# A resolved alert is already handled and is not current data risk. Live-checked
# 2026-07-25: every DLP alert in the default 168h window on the validation tenant
# was `resolved`, so the headline read "6 DLP alerts" while the open count was 0 —
# and that headline feeds the CISO report's data-risk tile. `status ne 'resolved'`
# is honoured on alerts_v2 (the same clause the Defender tools use); `state="all"`
# keeps the history reachable.
_ALERT_CLOSED = "resolved"
_STATES = ("open", "all")


def _bad_state(state: str) -> Finding:
    """An unrecognized state is reported, never silently treated as one of them."""
    return Finding(
        source="purview",
        finding_type=FindingType.posture,
        severity=Severity.info,
        title=f"Unsupported state '{state}'",
        recommended_action=RecommendedAction(summary="Use one of: " + ", ".join(_STATES) + "."),
    )


async def _fetch_alerts(
    gc: Any, source: str, hours_back: float, state: str = "open"
) -> tuple[list[dict[str, Any]], int | None]:
    """Alerts for one service source in the window; returns (rows, total-or-None).

    `total` is Graph's filtered @odata.count, so a bounded page can report how
    many matched rather than how many it happened to fetch.
    """
    clauses = [
        f"serviceSource eq '{source}'",
        f"createdDateTime ge {_since_iso(hours_back)}",
    ]
    if state != "all":
        clauses.append(f"status ne '{_ALERT_CLOSED}'")
    data = await gc.get(
        "/security/alerts_v2",
        params={"$filter": " and ".join(clauses), "$top": _FETCH_CAP, "$count": "true"},
    )
    rows = [a for a in data.get("value", []) if isinstance(a, dict)]
    total = data.get("@odata.count")
    if not isinstance(total, int) or isinstance(total, bool):
        total = None
    return rows, total


def _alert_finding(a: dict[str, Any]) -> Finding:
    title = str(a.get("title") or a.get("category") or "Purview alert")
    evidence = [
        Evidence(key=k, value=str(a.get(src)))
        for k, src in (("status", "status"), ("category", "category"),
                       ("created", "createdDateTime"), ("alert_id", "id"))
        if a.get(src)
    ]
    actor = a.get("actorDisplayName")
    return Finding(
        source="purview",
        finding_type=FindingType.alert,
        severity=_sev(a.get("severity")),
        title=title[:200],
        entity=(Entity(kind=EntityKind.user, id=str(actor), name=str(actor))
                if actor else None),
        evidence=evidence,
        observed_at=a.get("createdDateTime"),
    )


async def get_dlp_summary(
    gc: Any, hours_back: float = 168, state: str = "open"
) -> list[Finding]:
    """DLP alert rollup: counts by severity/status over the window."""
    if state not in _STATES:
        return [_bad_state(state)]
    try:
        alerts, total = await _fetch_alerts(gc, _DLP_SOURCE, hours_back, state)
    except GraphError as e:
        finding = map_graph_error(e, "purview", _ALERT_PERM, "dlp.alerts")
        if finding:
            return [finding]
        raise
    counted = total if total is not None else len(alerts)
    scope = "" if state == "all" else "unresolved "
    by_sev: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for a in alerts:
        by_sev[str(a.get("severity", "unknown"))] = by_sev.get(
            str(a.get("severity", "unknown")), 0) + 1
        by_status[str(a.get("status", "unknown"))] = by_status.get(
            str(a.get("status", "unknown")), 0) + 1
    def fmt(d: dict[str, int]) -> str:
        return ", ".join(f"{k}: {v}" for k, v in sorted(d.items())) or "none"

    if alerts:
        action = "Review the highest-severity alerts with list_dlp_alerts."
    elif state == "all":
        action = (
            "0 DLP alerts can mean a quiet period, no DLP policies configured, "
            "or missing Purview licensing — verify policies exist in the Purview portal."
        )
    else:
        # Distinguishing "nothing happened" from "everything was handled" matters:
        # the first may mean DLP is not deployed, the second means it is working.
        action = (
            "No unresolved DLP alerts. This can mean a quiet period, no DLP policies "
            "configured, or that every alert in the window is already resolved — "
            "re-run with state='all' to tell those apart."
        )
    # The rollup — including the finding's own `severity` — is computed from the
    # fetched page, and the query carries no ordering, so a capped window yields
    # an ARBITRARY sample rather than the worst or the newest alerts. Saying so
    # in machine-readable evidence matters more than the title caveat: a model
    # reading `severity` sees a claim about the window, and past the cap that
    # claim is only true of the sample.
    sampled = total is not None and total > len(alerts)
    evidence = [
        Evidence(key="headline", value=f"{counted} {scope}DLP alerts"),
        Evidence(key="alerts_total", value=str(counted)),
        Evidence(key="by_severity", value=fmt(by_sev)),
        Evidence(key="by_status", value=fmt(by_status)),
    ]
    if sampled:
        evidence.append(Evidence(
            key="severity_basis",
            value=f"worst of an unordered {len(alerts)}-alert sample of {total}; "
                  "a higher-severity alert may lie outside it — narrow hours_back",
        ))
    return [
        Finding(
            source="purview",
            finding_type=FindingType.posture,
            severity=Severity.info if not alerts else _sev(
                max(alerts, key=lambda a: _SEV_ORDER.index(str(a.get("severity")).lower())
                    if str(a.get("severity")).lower() in _SEV_ORDER else 0).get("severity")),
            title=f"{counted} {scope}DLP alert(s) in the last {hours_back:g}h"
            + (f" (counts from {len(alerts)} sampled)" if sampled else ""),
            evidence=evidence,
            recommended_action=RecommendedAction(summary=action),
        )
    ]


async def list_dlp_alerts(
    gc: Any, hours_back: float = 168, severity_min: str = "low", limit: int = 25,
    state: str = "open",
) -> list[Finding]:
    """Recent DLP alerts at/above severity_min, bounded."""
    limit = clamp_limit(limit)
    if state not in _STATES:
        return [_bad_state(state)]
    try:
        alerts, total = await _fetch_alerts(gc, _DLP_SOURCE, hours_back, state)
    except GraphError as e:
        finding = map_graph_error(e, "purview", _ALERT_PERM, "dlp.alerts")
        if finding:
            return [finding]
        raise
    floor = _SEV_ORDER.index(severity_min) if severity_min in _SEV_ORDER else 0
    # Membership check MUST run before .index(): Graph's severity enum also has
    # 'informational'/'unknown', which are excluded from the floor filter.
    kept = [
        a for a in alerts
        if str(a.get("severity")).lower() in _SEV_ORDER
        and _SEV_ORDER.index(str(a.get("severity")).lower()) >= floor
    ]
    if not kept:
        return [
            Finding(
                source="purview",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"No {'' if state == 'all' else 'unresolved '}DLP alerts at or "
                f"above '{severity_min}' in the last {hours_back:g}h",
                recommended_action=RecommendedAction(
                    summary="Lower severity_min or widen hours_back; get_dlp_summary "
                    "shows the full rollup. state='all' includes resolved alerts."
                ),
            )
        ]
    out = [_alert_finding(a) for a in kept[:limit]]
    # Two truncations can apply here and they mean different things. The fetch
    # cap is the more serious one: it means the severity refinement above only
    # examined part of the window, so `kept` itself is incomplete and raising
    # `limit` would not help. Report that in preference to the local bound.
    if total is not None and total > len(alerts):
        out.append(more_available_finding(
            "purview", shown=len(out), total=total,
            hint=f"Only the first {_FETCH_CAP} alerts in the window were examined — "
                 "narrow hours_back to see the rest.",
        ))
        return out
    note = truncation_finding(
        "purview", shown=len(out), fetched=len(out), total=len(kept),
        hint="Narrow the window (hours_back) or raise severity_min.",
    )
    if note:
        out.append(note)
    return out


async def list_insider_risk_alerts(
    gc: Any, hours_back: float = 168, limit: int = 25, state: str = "open"
) -> list[Finding]:
    """Recent Insider Risk Management alerts (users may be pseudonymized by IRM)."""
    limit = clamp_limit(limit)
    if state not in _STATES:
        return [_bad_state(state)]
    try:
        alerts, total = await _fetch_alerts(gc, _IRM_SOURCE, hours_back, state)
    except GraphError as e:
        finding = map_graph_error(e, "purview", _ALERT_PERM, "irm.alerts")
        if finding:
            return [finding]
        raise
    if not alerts:
        return [
            Finding(
                source="purview",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"No {'' if state == 'all' else 'unresolved '}insider-risk alerts "
                f"in the last {hours_back:g}h",
                recommended_action=RecommendedAction(
                    summary="A quiet period, or Insider Risk Management policies are "
                    "not configured/licensed on this tenant."
                ),
            )
        ]
    out = [_alert_finding(a) for a in alerts[:limit]]
    note = truncation_finding(
        "purview", shown=len(out), fetched=len(alerts), total=total,
        hint="Narrow the window (hours_back) or raise limit.",
    )
    if note:
        out.append(note)
    return out


async def list_sensitivity_labels(gc: Any) -> list[Finding]:
    """The org's sensitivity-label inventory (classification-coverage posture)."""
    try:
        data = await gc.get(_LABELS_BETA_URL)
    except GraphError as e:
        finding = map_graph_error(e, "purview", _LABEL_PERM, "labels.list")
        if finding:
            return [finding]
        raise
    labels = [label for label in data.get("value", []) if isinstance(label, dict)]
    shown_labels = labels[:clamp_limit(len(labels))] if labels else []
    if not labels:
        return [
            Finding(
                source="purview",
                finding_type=FindingType.posture,
                severity=Severity.medium,
                title="No sensitivity labels defined — data classification is not deployed",
                recommended_action=RecommendedAction(
                    summary="Define and publish sensitivity labels in the Purview "
                    "portal to enable classification-based protection."
                ),
            )
        ]
    out: list[Finding] = []
    for label in shown_labels:
        name = str(label.get("name") or label.get("displayName") or label.get("id"))
        out.append(
            Finding(
                source="purview",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"Sensitivity label: {name}",
                entity=Entity(kind=EntityKind.rule, id=str(label.get("id", name)),
                              name=name),
                evidence=[
                    Evidence(key=k, value=str(label.get(k)))
                    for k in ("priority", "isActive") if label.get(k) is not None
                ],
            )
        )
    note = truncation_finding(
        "purview", shown=len(out), fetched=len(out), total=len(labels),
        hint="The label inventory is bounded; review the rest in the Purview portal.",
    )
    if note:
        out.append(note)
    return out


def _audit_record_finding(r: dict[str, Any]) -> Finding:
    op = str(r.get("operation") or "audit event")
    upn = r.get("userPrincipalName") or r.get("userId")
    evidence = [
        Evidence(key=k, value=str(r.get(src))[:300])
        for k, src in (("user", "userPrincipalName"), ("service", "service"),
                       ("time", "createdDateTime"), ("object", "objectId"))
        if r.get(src)
    ]
    return Finding(
        source="purview",
        finding_type=FindingType.hunt_result,
        severity=Severity.info,
        title=op[:200],
        entity=(Entity(kind=EntityKind.user, id=str(upn), name=str(upn))
                if upn else None),
        evidence=evidence,
        observed_at=r.get("createdDateTime"),
    )


async def _audit_records(gc: Any, query_id: str, limit: int) -> list[Finding]:
    data = await gc.get(
        f"{_AUDIT_QUERIES_URL}/{query_id}/records", params={"$top": limit}
    )
    records = [r for r in data.get("value", []) if isinstance(r, dict)]
    summary = Finding(
        source="purview",
        finding_type=FindingType.hunt_result,
        severity=Severity.info,
        title=f"{len(records)} audit record(s)"
        + (f" (showing first {limit})" if len(records) >= limit else ""),
        evidence=[Evidence(key="audit_query_id", value=query_id)],
        recommended_action=RecommendedAction(
            summary="Review the records; narrow with `activity`/`user` filters "
            "to investigate further."
        ),
    )
    return [summary] + [_audit_record_finding(r) for r in records[:limit]]


def _pending_finding(
    query_id: str, status: str, reused: bool = False, window: str = "",
    reused_age_s: float | None = None,
) -> Finding:
    evidence = [Evidence(key="audit_query_id", value=query_id),
                Evidence(key="status", value=status)]
    if window:
        evidence.append(Evidence(key="window", value=window))
    if reused:
        # Say how OLD the reused query is, not merely that it was reused. Its
        # window was computed when it was CREATED, so "the last 24h" silently
        # means "the 24h before then" — without the age a caller cannot tell a
        # query started seconds ago from one started half an hour ago, and the
        # reuse TTL runs to 30 minutes.
        age = "" if reused_age_s is None else f" (started {round(reused_age_s / 60)} min ago)"
        evidence.append(Evidence(
            key="note",
            value=f"identical search already in flight{age} — reusing it, no new "
                  "query created; the window above is the one it was created with",
        ))
    return Finding(
        source="purview",
        finding_type=FindingType.posture,
        severity=Severity.info,
        title=f"Audit search {status} — results not ready yet",
        evidence=evidence,
        recommended_action=RecommendedAction(
            summary="Audit queries typically take 5-15 minutes on large tenants and "
            "this tool already waited. STOP polling now: tell the user the search is "
            f"running (audit_query_id '{query_id}') and that they should ask again in "
            "a few minutes — then call get_audit_results ONCE when they do. Do not "
            "call get_audit_results or search_audit_log again in this turn."
        ),
    )


async def _poll_until_terminal(gc: Any, query_id: str, status: str) -> str:
    """Block-poll the query up to the deadline. Returns the terminal status, or
    the last non-terminal status if the deadline is hit first. A small model has
    no timer, so both entry points poll HERE rather than returning instantly on a
    not-ready query (which turned the model's retry loop into a tight hammer)."""
    deadline = asyncio.get_event_loop().time() + _POLL_DEADLINE_S
    while status not in ("succeeded", "failed", "cancelled"):
        if asyncio.get_event_loop().time() >= deadline:
            return status
        await asyncio.sleep(_POLL_INTERVAL_S)
        q = await gc.get(f"{_AUDIT_QUERIES_URL}/{query_id}")
        status = str(q.get("status", "running"))
    return status


async def search_audit_log(
    gc: Any,
    activity: str = "",
    user: str = "",
    hours_back: float = 24,
    limit: int = 25,
) -> list[Finding]:
    """Guided unified-audit search: submit an async query, poll briefly, return
    records — or the query id to fetch later via get_audit_results."""
    limit = clamp_limit(limit)
    if activity and not _ACTIVITY_RE.match(activity):
        return [_invalid("activity", activity)]
    if user and not _UPN_RE.match(user):
        return [_invalid("user", user)]
    window_start, window_end = _since_iso(hours_back), _since_iso(0)
    body: dict[str, Any] = {
        "displayName": "f0_sectools audit search",
        "filterStartDateTime": window_start,
        "filterEndDateTime": window_end,
    }
    if activity:
        body["operationFilters"] = [activity]
    if user:
        body["userPrincipalNameFilters"] = [user]
    key = (activity, user, round(hours_back, 2))
    now = time.monotonic()
    # No lock between this read and the write below. Two things make that a
    # deliberate choice rather than an oversight:
    #
    #   - It cannot fire under the transport in use: MCP-over-stdio is
    #     single-flight per session, and the dedupe exists for SEQUENTIAL
    #     retries (a model resubmitting while a query runs), not concurrency.
    #   - If it ever did fire, the cost is ONE duplicate server-side query —
    #     i.e. the optimization not applying, which is exactly the pre-dedupe
    #     behaviour. Nothing is corrupted and no result is wrong.
    #
    # A lock would have to be held across the POST below to actually close the
    # window, which would serialize unrelated searches behind an unrelated
    # network call — a real cost paid against a benign, unreachable race.
    # Revisit if a concurrent transport is ever added.
    cached = _RECENT_SEARCHES.get(key)
    reused = bool(cached and now - cached[1] < _REUSE_TTL_S)
    reused_age_s: float | None = None
    try:
        if reused and cached:
            query_id = cached[0]
            window = cached[2]  # the ORIGINAL queried window, not a fresh one
            reused_age_s = now - cached[1]
            status = "running"
        else:
            window = f"{window_start} to {window_end}"
            created = await gc.post(_AUDIT_QUERIES_URL, json_body=body)
            query_id = str(created.get("id", ""))
            status = str(created.get("status", "notStarted"))
            if query_id:
                for k, (_, ts, _w) in list(_RECENT_SEARCHES.items()):
                    if now - ts >= _REUSE_TTL_S:
                        _RECENT_SEARCHES.pop(k, None)
                if len(_RECENT_SEARCHES) >= 32:
                    _RECENT_SEARCHES.pop(next(iter(_RECENT_SEARCHES)), None)
                _RECENT_SEARCHES[key] = (query_id, now, window)
        status = await _poll_until_terminal(gc, query_id, status)
        if status not in ("succeeded", "failed", "cancelled"):
            return [_pending_finding(query_id, status, reused=reused, window=window,
                                     reused_age_s=reused_age_s)]
        if status != "succeeded":
            return [
                Finding(
                    source="purview",
                    finding_type=FindingType.posture,
                    severity=Severity.medium,
                    title=f"Audit search {status}",
                    evidence=[Evidence(key="audit_query_id", value=query_id)],
                    recommended_action=RecommendedAction(
                        summary="Retry with a narrower window; if it persists, check "
                        "audit availability in the Purview portal."
                    ),
                )
            ]
        return await _audit_records(gc, query_id, limit)
    except GraphError as e:
        finding = map_graph_error(e, "purview", _AUDIT_PERM, "audit.search")
        if finding:
            return [finding]
        raise


async def get_audit_results(gc: Any, audit_query_id: str, limit: int = 25) -> list[Finding]:
    """Fetch results of a previously submitted audit search.

    Blocks for up to ~15s polling the query first, matching search_audit_log —
    a model that expects an instant read otherwise polls this in a tight loop.
    """
    limit = clamp_limit(limit)
    if not _QUERY_ID_RE.match(audit_query_id or ""):
        return [_invalid("audit_query_id", audit_query_id)]
    try:
        q = await gc.get(f"{_AUDIT_QUERIES_URL}/{audit_query_id}")
        status = str(q.get("status", "unknown"))
        # Block-poll like search_audit_log so a timer-less model's repeated calls
        # are paced and catch completion mid-poll instead of hammering instantly.
        status = await _poll_until_terminal(gc, audit_query_id, status)
        if status == "succeeded":
            return await _audit_records(gc, audit_query_id, limit)
        if status in ("failed", "cancelled"):
            return [
                Finding(
                    source="purview",
                    finding_type=FindingType.posture,
                    severity=Severity.medium,
                    title=f"Audit search {status}",
                    evidence=[Evidence(key="audit_query_id", value=audit_query_id)],
                    recommended_action=RecommendedAction(
                        summary="Submit a fresh search with a narrower window; if it "
                        "persists, check audit availability in the Purview portal."
                    ),
                )
            ]
        return [_pending_finding(audit_query_id, status)]
    except GraphError as e:
        finding = map_graph_error(e, "purview", _AUDIT_PERM, "audit.results")
        if finding:
            return [finding]
        raise


def _invalid(param: str, value: str) -> Finding:
    return Finding(
        source="purview",
        finding_type=FindingType.posture,
        severity=Severity.info,
        title=f"Invalid {param} '{value}' — query not run",
        recommended_action=RecommendedAction(
            summary=f"{param} may contain only letters, digits and simple "
            "punctuation (no quotes or pipes)."
        ),
    )
