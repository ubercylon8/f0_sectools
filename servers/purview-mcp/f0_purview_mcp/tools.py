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
from f0_sectools_core.paging import clamp_limit
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
# search (same filters/window) within the TTL reuses the in-flight query.
_RECENT_SEARCHES: dict[tuple[str, str, float], tuple[str, float]] = {}
_REUSE_TTL_S = 1800.0
_FETCH_CAP = 100  # single bounded page for summaries/lists


def _since_iso(hours_back: float) -> str:
    return (datetime.now(UTC) - timedelta(hours=hours_back)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _sev(value: Any) -> Severity:
    return _SEV.get(str(value).lower(), Severity.medium)


async def _fetch_alerts(gc: Any, source: str, hours_back: float) -> list[dict[str, Any]]:
    params = {
        "$filter": (
            f"serviceSource eq '{source}' and createdDateTime ge {_since_iso(hours_back)}"
        ),
        "$top": _FETCH_CAP,
    }
    data = await gc.get("/security/alerts_v2", params=params)
    return [a for a in data.get("value", []) if isinstance(a, dict)]


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


def _more_note(shown: int, total: int) -> Finding:
    return Finding(
        source="purview",
        finding_type=FindingType.posture,
        severity=Severity.info,
        title=f"More alerts available ({total - shown} not shown)",
        recommended_action=RecommendedAction(
            summary="Narrow the window (hours_back) or raise severity_min."
        ),
    )


async def get_dlp_summary(gc: Any, hours_back: float = 168) -> list[Finding]:
    """DLP alert rollup: counts by severity/status over the window."""
    try:
        alerts = await _fetch_alerts(gc, _DLP_SOURCE, hours_back)
    except GraphError as e:
        finding = map_graph_error(e, "purview", _ALERT_PERM, "dlp.alerts")
        if finding:
            return [finding]
        raise
    by_sev: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for a in alerts:
        by_sev[str(a.get("severity", "unknown"))] = by_sev.get(
            str(a.get("severity", "unknown")), 0) + 1
        by_status[str(a.get("status", "unknown"))] = by_status.get(
            str(a.get("status", "unknown")), 0) + 1
    def fmt(d: dict[str, int]) -> str:
        return ", ".join(f"{k}: {v}" for k, v in sorted(d.items())) or "none"

    action = (
        "Review the highest-severity alerts with list_dlp_alerts."
        if alerts
        else "0 DLP alerts can mean a quiet period, no DLP policies configured, "
        "or missing Purview licensing — verify policies exist in the Purview portal."
    )
    return [
        Finding(
            source="purview",
            finding_type=FindingType.posture,
            severity=Severity.info if not alerts else _sev(
                max(alerts, key=lambda a: _SEV_ORDER.index(str(a.get("severity")).lower())
                    if str(a.get("severity")).lower() in _SEV_ORDER else 0).get("severity")),
            title=f"{len(alerts)} DLP alert(s) in the last {hours_back:g}h"
            + (f" (showing counts for first {_FETCH_CAP})" if len(alerts) >= _FETCH_CAP else ""),
            evidence=[
                Evidence(key="alerts_total", value=str(len(alerts))),
                Evidence(key="by_severity", value=fmt(by_sev)),
                Evidence(key="by_status", value=fmt(by_status)),
            ],
            recommended_action=RecommendedAction(summary=action),
        )
    ]


async def list_dlp_alerts(
    gc: Any, hours_back: float = 168, severity_min: str = "low", limit: int = 25
) -> list[Finding]:
    """Recent DLP alerts at/above severity_min, bounded."""
    limit = clamp_limit(limit)
    try:
        alerts = await _fetch_alerts(gc, _DLP_SOURCE, hours_back)
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
                title=f"No DLP alerts at or above '{severity_min}' in the last "
                f"{hours_back:g}h",
                recommended_action=RecommendedAction(
                    summary="Lower severity_min or widen hours_back; get_dlp_summary "
                    "shows the full rollup."
                ),
            )
        ]
    out = [_alert_finding(a) for a in kept[:limit]]
    if len(kept) > limit:
        out.append(_more_note(limit, len(kept)))
    return out


async def list_insider_risk_alerts(
    gc: Any, hours_back: float = 168, limit: int = 25
) -> list[Finding]:
    """Recent Insider Risk Management alerts (users may be pseudonymized by IRM)."""
    limit = clamp_limit(limit)
    try:
        alerts = await _fetch_alerts(gc, _IRM_SOURCE, hours_back)
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
                title=f"No insider-risk alerts in the last {hours_back:g}h",
                recommended_action=RecommendedAction(
                    summary="A quiet period, or Insider Risk Management policies are "
                    "not configured/licensed on this tenant."
                ),
            )
        ]
    out = [_alert_finding(a) for a in alerts[:limit]]
    if len(alerts) > limit:
        out.append(_more_note(limit, len(alerts)))
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
    for label in labels[:clamp_limit(len(labels))]:
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


def _pending_finding(query_id: str, status: str, reused: bool = False) -> Finding:
    evidence = [Evidence(key="audit_query_id", value=query_id),
                Evidence(key="status", value=status)]
    if reused:
        evidence.append(Evidence(
            key="note",
            value="identical search already in flight — reusing it, no new query created",
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
    body: dict[str, Any] = {
        "displayName": "f0_sectools audit search",
        "filterStartDateTime": _since_iso(hours_back),
        "filterEndDateTime": _since_iso(0),
    }
    if activity:
        body["operationFilters"] = [activity]
    if user:
        body["userPrincipalNameFilters"] = [user]
    key = (activity, user, round(hours_back, 2))
    now = time.monotonic()
    cached = _RECENT_SEARCHES.get(key)
    reused = bool(cached and now - cached[1] < _REUSE_TTL_S)
    try:
        if reused and cached:
            query_id = cached[0]
            status = "running"
        else:
            created = await gc.post(_AUDIT_QUERIES_URL, json_body=body)
            query_id = str(created.get("id", ""))
            status = str(created.get("status", "notStarted"))
            if query_id:
                for k, (_, ts) in list(_RECENT_SEARCHES.items()):
                    if now - ts >= _REUSE_TTL_S:
                        _RECENT_SEARCHES.pop(k, None)
                if len(_RECENT_SEARCHES) >= 32:
                    _RECENT_SEARCHES.pop(next(iter(_RECENT_SEARCHES)), None)
                _RECENT_SEARCHES[key] = (query_id, now)
        status = await _poll_until_terminal(gc, query_id, status)
        if status not in ("succeeded", "failed", "cancelled"):
            return [_pending_finding(query_id, status, reused=reused)]
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
    """Fetch results of a previously submitted audit search."""
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
