"""ProjectAchilles read tools -> findings.

Read-only. Each tool catches a ProjectAchilles HTTP error (auth / permission /
rate-limit) and returns a posture finding instead of crashing. PA measures
defensive posture by running f0_library attack simulations and scoring whether
controls blocked or detected them.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from f0_sectools_core.schema.findings import (
    Entity,
    EntityKind,
    Evidence,
    Finding,
    FindingType,
    RecommendedAction,
    Reference,
    Severity,
)

from .errors import map_pa_error

_SEV = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "low": Severity.low,
    "info": Severity.info,
}


def _window(days: int) -> tuple[str, str]:
    now = datetime.now(UTC)
    return (now - timedelta(days=days)).date().isoformat(), now.date().isoformat()


def _score_severity(score: float) -> Severity:
    # Higher defense score = better, so a LOW score is a HIGH-risk finding.
    if score < 40:
        return Severity.high
    if score < 70:
        return Severity.medium
    if score < 85:
        return Severity.low
    return Severity.info


def _rows(resp: Any) -> list:
    """Extract a list of rows. Some PA endpoints return a bare array, others
    wrap it as ``{"data": [...]}`` — handle both."""
    if isinstance(resp, list):
        return resp
    if isinstance(resp, dict):
        return resp.get("data") or []
    return []


# The PA dashboard is locked to any-stage scoring (multi-stage test bundles
# count as one unit; totals come from aggregations, immune to the ES 10k
# hits.total cap). Omitting scoringMode selects the legacy per-execution path
# whose capped total inflates the score — so always request any-stage.
_SCORING_MODE = "any-stage"


async def get_defense_score(pa: Any, days: int = 30) -> list[Finding]:
    frm, to = _window(days)
    try:
        d = await pa.get(
            "/analytics/defense-score",
            params={"from": frm, "to": to, "scoringMode": _SCORING_MODE},
        )
    except Exception as e:
        finding = map_pa_error(e, "ProjectAchilles defense score")
        if finding:
            return [finding]
        raise
    score = float(d.get("score", 0) or 0)
    evidence = [
        Evidence(key="protected", value=str(d.get("protectedCount", 0))),
        Evidence(key="detected", value=str(d.get("detectedCount", 0))),
        Evidence(key="unprotected", value=str(d.get("unprotectedCount", 0))),
        Evidence(key="total", value=str(d.get("totalExecutions", 0))),
        Evidence(key="risk_accepted", value=str(d.get("riskAcceptedCount", 0))),
    ]
    raw = d.get("rawScore")
    if raw is not None:
        evidence.append(Evidence(key="score_before_exclusions", value=f"{float(raw):.1f}%"))
    real = d.get("realScore")
    if real is not None:
        evidence.append(Evidence(key="score_blocked_only", value=f"{float(real):.1f}%"))
    return [
        Finding(
            source="projectachilles",
            finding_type=FindingType.posture,
            severity=_score_severity(score),
            title=f"Defense score: {score:.1f}% (blocked/detected, risk-adjusted)",
            entity=Entity(kind=EntityKind.tenant, id="org"),
            evidence=evidence,
            recommended_action=RecommendedAction(
                summary="Investigate the lowest-scoring techniques and unprotected results."
            ),
        )
    ]


async def get_defense_score_trend(pa: Any, days: int = 30, interval: str = "day") -> list[Finding]:
    frm, to = _window(days)
    try:
        d = await pa.get(
            "/analytics/defense-score/trend",
            params={
                "from": frm,
                "to": to,
                "interval": interval,
                "windowDays": days,
                "scoringMode": _SCORING_MODE,
            },
        )
    except Exception as e:
        finding = map_pa_error(e, "ProjectAchilles defense-score trend")
        if finding:
            return [finding]
        raise
    pts = _rows(d)
    if not pts:
        return []
    first = float(pts[0].get("score", 0) or 0)
    last = float(pts[-1].get("score", 0) or 0)
    delta = last - first
    direction = "improving" if delta > 1 else "declining" if delta < -1 else "flat"
    sev = Severity.medium if delta < -1 else Severity.info
    return [
        Finding(
            source="projectachilles",
            finding_type=FindingType.posture,
            severity=sev,
            title=f"Defense score trend ({days}d): {first:.0f}% to {last:.0f}% ({direction})",
            evidence=[
                Evidence(key="start", value=f"{first:.0f}%"),
                Evidence(key="end", value=f"{last:.0f}%"),
                Evidence(key="delta", value=f"{delta:+.0f}"),
            ],
        )
    ]


async def get_weak_techniques(pa: Any, days: int = 30, limit: int = 10) -> list[Finding]:
    frm, to = _window(days)
    try:
        d = await pa.get("/analytics/defense-score/by-technique", params={"from": frm, "to": to})
    except Exception as e:
        finding = map_pa_error(e, "ProjectAchilles technique coverage")
        if finding:
            return [finding]
        raise
    rows = sorted(_rows(d), key=lambda r: float(r.get("score", 100) or 100))[:limit]
    out: list[Finding] = []
    for r in rows:
        name = str(r.get("name", "technique"))
        score = float(r.get("score", 0) or 0)
        refs = [Reference(type="mitre", id=name)] if name.upper().startswith("T") else []
        out.append(
            Finding(
                source="projectachilles",
                finding_type=FindingType.misconfig,
                severity=_score_severity(score),
                title=f"Weak coverage: {name} ({score:.0f}%)",
                entity=Entity(kind=EntityKind.rule, id=name, name=name),
                evidence=[
                    Evidence(key="score", value=f"{score:.0f}%"),
                    Evidence(key="executions", value=str(r.get("count", 0))),
                ],
                references=refs,
                recommended_action=RecommendedAction(
                    summary="Strengthen the control/detection for this technique."
                ),
            )
        )
    return out


async def list_test_executions(pa: Any, days: int = 7, limit: int = 25) -> list[Finding]:
    frm, to = _window(days)
    try:
        d = await pa.get("/analytics/executions", params={"from": frm, "to": to, "limit": limit})
    except Exception as e:
        finding = map_pa_error(e, "ProjectAchilles test executions")
        if finding:
            return [finding]
        raise
    out: list[Finding] = []
    for x in _rows(d)[:limit]:
        host = x.get("hostname", "")
        name = x.get("test_name", "test")
        if x.get("is_protected"):
            sev, ftype, outcome = Severity.info, FindingType.posture, "blocked"
        elif x.get("defender_detected"):
            sev, ftype, outcome = Severity.low, FindingType.misconfig, "detected, not blocked"
        else:
            sev = _SEV.get(str(x.get("severity", "high")).lower(), Severity.high)
            ftype, outcome = FindingType.misconfig, "NOT blocked"
        ent = Entity(kind=EntityKind.host, id=str(host), name=str(host)) if host else None
        out.append(
            Finding(
                source="projectachilles",
                finding_type=ftype,
                severity=sev,
                title=f"{name}: {outcome} on {host}",
                entity=ent,
                evidence=[Evidence(key="outcome", value=outcome)],
                references=[Reference(type="mitre", id=t) for t in (x.get("techniques") or [])],
                observed_at=x.get("timestamp"),
            )
        )
    return out


async def list_risk_acceptances(pa: Any, status: str = "active", limit: int = 50) -> list[Finding]:
    try:
        d = await pa.get("/risk-acceptances", params={"status": status, "pageSize": limit})
    except Exception as e:
        finding = map_pa_error(e, "ProjectAchilles risk acceptances")
        if finding:
            return [finding]
        raise
    out: list[Finding] = []
    for r in _rows(d)[:limit]:
        name = r.get("test_name", "risk")
        out.append(
            Finding(
                source="projectachilles",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"Risk accepted: {name} ({r.get('scope', '')})",
                evidence=[
                    Evidence(key="accepted_by", value=str(r.get("accepted_by_name", ""))),
                    Evidence(key="justification", value=str(r.get("justification", ""))),
                ],
                observed_at=r.get("accepted_at"),
            )
        )
    return out


async def list_agents(
    pa: Any, status: str | None = None, online_only: bool = False, limit: int = 50
) -> list[Finding]:
    params: dict = {"limit": limit, "online_only": str(online_only).lower()}
    if status:
        params["status"] = status
    try:
        d = await pa.get("/agent/admin/agents", params=params)
    except Exception as e:
        finding = map_pa_error(e, "ProjectAchilles agents")
        if finding:
            return [finding]
        raise
    data = d.get("data") or {}
    agents = (data.get("agents") if isinstance(data, dict) else data) or []
    out: list[Finding] = []
    for a in agents[:limit]:
        host = a.get("hostname", "unknown")
        out.append(
            Finding(
                source="projectachilles",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"Agent: {host} ({a.get('status', '?')})",
                entity=Entity(kind=EntityKind.host, id=str(a.get("id", "")), name=str(host)),
                evidence=[
                    Evidence(key="os", value=str(a.get("os", "?"))),
                    Evidence(key="status", value=str(a.get("status", "?"))),
                ],
            )
        )
    return out


async def get_fleet_health(pa: Any) -> list[Finding]:
    try:
        d = await pa.get("/agent/admin/metrics")
    except Exception as e:
        finding = map_pa_error(e, "ProjectAchilles fleet health")
        if finding:
            return [finding]
        raise
    m = d.get("data") or {}
    online = m.get("online", 0)
    total = m.get("total", 0)
    return [
        Finding(
            source="projectachilles",
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=f"Agent fleet: {online}/{total} online",
            entity=Entity(kind=EntityKind.tenant, id="fleet"),
            evidence=[
                Evidence(key="online", value=str(online)),
                Evidence(key="offline", value=str(m.get("offline", 0))),
                Evidence(key="total", value=str(total)),
                Evidence(key="pending_tasks", value=str(m.get("pending_tasks", 0))),
            ],
        )
    ]
