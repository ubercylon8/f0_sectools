"""ProjectAchilles read tools -> findings.

Read-only. Each tool catches a ProjectAchilles HTTP error (auth / permission /
rate-limit) and returns a posture finding instead of crashing. PA measures
defensive posture by running f0_library attack simulations and scoring whether
controls blocked or detected them.
"""
from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

from f0_sectools_core.paging import clamp_limit
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
from f0_sectools_core.smallmodel import scope_ok, search_ok

from .client import ProjectAchillesError
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


def _rows(resp: Any) -> list[dict[str, Any]]:
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


_FIND_BY = {"technique", "actor", "tactic", "category", "tag", "keyword"}

_UUID_RE = re.compile(
    r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", re.IGNORECASE
)

# PA supports these filters server-side on GET /api/browser/tests; the rest
# (actor/tactic/tag) are filtered client-side over the returned list.
_SERVER_SIDE = {"technique": "technique", "category": "category", "keyword": "search"}


def _tests(resp: Any) -> list[dict[str, Any]]:
    """Browser /tests returns {success, count, tests: [...]}. Be defensive."""
    if isinstance(resp, dict):
        t = resp.get("tests")
        if isinstance(t, list):
            return t
    if isinstance(resp, list):
        return resp
    return []


def _test_evidence(t: dict[str, Any]) -> list[Evidence]:
    return [
        Evidence(key="techniques", value=", ".join(t.get("techniques") or []) or "none"),
        Evidence(key="threat_actor", value=str(t.get("threatActor") or "none")),
        Evidence(key="os", value=", ".join(t.get("target") or []) or "any"),
        Evidence(key="severity", value=str(t.get("severity") or "unspecified")),
        Evidence(key="complexity", value=str(t.get("complexity") or "unspecified")),
        Evidence(key="uuid", value=str(t.get("uuid", ""))),
    ]


async def find_tests(pa: Any, by: str, value: str, limit: int = 25) -> list[Finding]:
    limit = clamp_limit(limit)
    by = by.strip().lower()
    if by not in _FIND_BY:
        return [
            Finding(
                source="projectachilles",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"Unknown search dimension '{by}'",
                recommended_action=RecommendedAction(
                    summary="Use by = technique | actor | tactic | category | tag | keyword.",
                ),
            )
        ]
    if value and not search_ok(value):
        return [
            Finding(
                source="projectachilles",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title="Search value too long or contains control characters",
                recommended_action=RecommendedAction(
                    summary="Use a plain search term (<=128 chars, no control characters).",
                ),
            )
        ]
    param = _SERVER_SIDE.get(by)
    try:
        resp = await pa.get("/browser/tests", params={param: value} if param else None)
    except Exception as e:
        finding = map_pa_error(e, "ProjectAchilles test catalog")
        if finding:
            return [finding]
        raise
    raw = _tests(resp)
    # The browser /tests endpoint currently returns the full filtered set in one
    # response (its `count` == len(tests)). Defend the count invariant in code
    # rather than by a one-time manual check: if the endpoint ever pages (its
    # `count` exceeds the rows it handed us), len(raw) is only a LOWER BOUND and
    # any client-side filter below ran over a partial page — so flag it instead
    # of emitting a confident wrong number.
    server_count = resp.get("count") if isinstance(resp, dict) else None
    paged = (
        isinstance(server_count, int)
        and not isinstance(server_count, bool)
        and server_count > len(raw)
    )
    rows = raw
    needle = value.lower()
    if by == "actor":
        rows = [r for r in rows if needle in str(r.get("threatActor") or "").lower()]
    elif by == "tactic":
        rows = [r for r in rows if any(needle in str(x).lower() for x in (r.get("tactics") or []))]
    elif by == "tag":
        rows = [r for r in rows if any(needle in str(x).lower() for x in (r.get("tags") or []))]
    total = len(rows)
    count_label = f"≥{total}" if paged else str(total)
    summary_evidence = [
        Evidence(key="total_matches", value=str(total)),
        Evidence(key="returned", value=str(min(total, limit))),
    ]
    if paged:
        summary_evidence.append(Evidence(key="paging_truncated", value="true"))
    out: list[Finding] = [
        Finding(
            source="projectachilles",
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=f"{count_label} tests match {by}={value}",
            entity=Entity(kind=EntityKind.tenant, id="catalog"),
            evidence=summary_evidence,
        )
    ]
    for t in rows[:limit]:
        name = str(t.get("name", "test"))
        cat = str(t.get("category", "?"))
        ev = _test_evidence(t)
        desc = str(t.get("description") or "").strip().replace("\n", " ")
        if desc:
            ev.append(
                Evidence(key="description", value=desc[:197] + "..." if len(desc) > 200 else desc)
            )
        out.append(
            Finding(
                source="projectachilles",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"Test: {name} ({cat})",
                entity=Entity(kind=EntityKind.rule, id=str(t.get("uuid", "")), name=name),
                evidence=ev,
                references=[Reference(type="mitre", id=x) for x in (t.get("techniques") or [])],
            )
        )
    return out


def _not_found(test_id: str) -> Finding:
    return Finding(
        source="projectachilles",
        finding_type=FindingType.posture,
        severity=Severity.info,
        title=f"No test found for '{test_id}'",
        recommended_action=RecommendedAction(
            summary="Use find_tests to browse the catalog, then get_test by uuid or exact name.",
        ),
    )


def _test_detail_finding(t: dict[str, Any]) -> Finding:
    name = str(t.get("name", "test"))
    ev = [
        Evidence(key="description", value=str(t.get("description") or "none").strip()),
        Evidence(key="os", value=", ".join(t.get("target") or []) or "any"),
        Evidence(key="complexity", value=str(t.get("complexity") or "unspecified")),
        Evidence(key="category", value=str(t.get("category", "?"))),
        Evidence(key="subcategory", value=str(t.get("subcategory") or "none")),
        Evidence(key="severity", value=str(t.get("severity") or "unspecified")),
        Evidence(key="tactics", value=", ".join(t.get("tactics") or []) or "none"),
        Evidence(key="tags", value=", ".join(t.get("tags") or []) or "none"),
        Evidence(key="threat_actor", value=str(t.get("threatActor") or "none")),
    ]
    stage_count = t.get("stageCount")
    if stage_count is None and isinstance(t.get("stages"), list):
        stage_count = len(t["stages"])
    if stage_count is not None:
        ev.append(Evidence(key="stage_count", value=str(stage_count)))
    return Finding(
        source="projectachilles",
        finding_type=FindingType.posture,
        severity=Severity.info,
        title=f"Test: {name}",
        entity=Entity(kind=EntityKind.rule, id=str(t.get("uuid", "")), name=name),
        evidence=ev,
        references=[Reference(type="mitre", id=x) for x in (t.get("techniques") or [])],
    )


async def get_test(pa: Any, test_id: str) -> list[Finding]:
    test_id = test_id.strip()
    if _UUID_RE.match(test_id):
        try:
            resp = await pa.get(f"/browser/tests/{test_id}")
        except ProjectAchillesError as e:
            if e.status == 404:
                return [_not_found(test_id)]
            finding = map_pa_error(e, "ProjectAchilles test detail")
            if finding:
                return [finding]
            raise
        t = resp.get("test") if isinstance(resp, dict) else None
        return [_test_detail_finding(t)] if t else [_not_found(test_id)]
    # Resolve by name via search.
    try:
        resp = await pa.get("/browser/tests", params={"search": test_id})
    except Exception as e:
        finding = map_pa_error(e, "ProjectAchilles test detail")
        if finding:
            return [finding]
        raise
    rows = _tests(resp)
    exact = [r for r in rows if str(r.get("name", "")).lower() == test_id.lower()]
    candidates = exact or rows
    if len(candidates) == 1:
        return [_test_detail_finding(candidates[0])]
    if len(candidates) > 1:
        return [
            Finding(
                source="projectachilles",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"Multiple tests match '{test_id}' — specify by uuid",
                evidence=[
                    Evidence(key=str(r.get("name", "?")), value=str(r.get("uuid", "")))
                    for r in candidates[:10]
                ],
            )
        ]
    return [_not_found(test_id)]


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
    # Keys name what is counted — test executions/results, NOT hosts. Bare keys
    # ("total"/"protected") led a small model to render this as "Total hosts
    # tested"; the counts are per test execution.
    evidence = [
        Evidence(key="tests_protected", value=str(d.get("protectedCount", 0))),
        Evidence(key="tests_detected", value=str(d.get("detectedCount", 0))),
        Evidence(key="tests_unprotected", value=str(d.get("unprotectedCount", 0))),
        Evidence(key="total_tests", value=str(d.get("totalExecutions", 0))),
        Evidence(key="tests_risk_accepted", value=str(d.get("riskAcceptedCount", 0))),
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
    limit = clamp_limit(limit)
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


def _scope_guidance(field: str, value: str) -> Finding:
    return Finding(
        source="projectachilles",
        finding_type=FindingType.posture,
        severity=Severity.info,
        title=f"Invalid scope: {field} contains unsupported characters",
        evidence=[Evidence(key=field, value=value[:64])],
        recommended_action=RecommendedAction(
            summary=f"Pass a plain {field} (letters, digits, spaces, . _ - : @ /).",
        ),
    )


async def list_test_executions(
    pa: Any, days: int = 7, limit: int = 25,
    test: str = "", tag: str = "", hostname: str = "",
) -> list[Finding]:
    limit = clamp_limit(limit)
    frm, to = _window(days)
    for field, value in (("test", test), ("tag", tag), ("hostname", hostname)):
        if value and not scope_ok(value):
            return [_scope_guidance(field, value)]
    params: dict[str, Any] = {
        "from": frm,
        "to": to,
        "pageSize": limit,
        "sortField": "routing.event_time",
        "sortOrder": "desc",
    }
    if test:
        params["tests"] = test          # ?tests= — name or UUID (live-validate)
    if tag:
        params["tags"] = tag
    if hostname:
        params["hostnames"] = hostname
    try:
        # Use the ENRICHED paginated endpoint. The plain /analytics/executions
        # strips category/defender_detected/severity/techniques, which starves the
        # security-vs-hygiene branch below (cyber-hygiene then misreads as "NOT
        # blocked"). /executions/paginated returns EnrichedTestExecution rows under
        # {"data": [...]}; it takes pageSize (max 100 server-side, so limit>100 is
        # silently capped at 100), not limit. Sort is passed EXPLICITLY (not left to
        # the endpoint default) so "recent" is guaranteed most-recent-first.
        d = await pa.get(
            "/analytics/executions/paginated",
            params=params,
        )
    except Exception as e:
        finding = map_pa_error(e, "ProjectAchilles test executions")
        if finding:
            return [finding]
        raise
    rows = _rows(d)[:limit]
    # The rollup below only sees the fetched window (pageSize=limit). If the
    # server-reported total exceeds what we actually fetched, a COMPLIANT verdict
    # is only true FOR THIS WINDOW — failing rows outside it wouldn't be caught.
    # A NON-COMPLIANT verdict stays definitive: a found failure is a found failure.
    total_items = None
    if isinstance(d, dict):
        pagination = d.get("pagination")
        if isinstance(pagination, dict):
            total_items = pagination.get("totalItems")
    truncated = (
        isinstance(total_items, int)
        and not isinstance(total_items, bool)
        and total_items > len(rows)
    )
    bundle_rows = [r for r in rows if r.get("is_bundle_control")]
    single_rows = [r for r in rows if not r.get("is_bundle_control")]
    out: list[Finding] = []

    # Roll up bundle-control rows: one finding per (bundle, host) run.
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for r in bundle_rows:
        key = (str(r.get("bundle_name") or r.get("test_name") or "bundle"),
               str(r.get("hostname") or ""))
        groups.setdefault(key, []).append(r)
    for (bname, host), ctrls in groups.items():
        total = len(ctrls)
        failing = [c for c in ctrls if not c.get("is_protected")]
        passed = total - len(failing)
        non_compliant = bool(failing)
        if non_compliant:
            any_high = any(
                str(c.get("severity", "")).lower() in ("critical", "high") for c in failing
            )
            sev = Severity.high if any_high else Severity.medium
        else:
            sev = Severity.info
        ftype = FindingType.misconfig if non_compliant else FindingType.posture
        verdict = "NON-COMPLIANT" if non_compliant else "COMPLIANT"
        # A found failure is definitive even over a truncated window; only soften
        # a COMPLIANT verdict, which is only true for the rows we actually saw.
        verdict_label = "COMPLIANT (in fetched window)" if (
            truncated and not non_compliant
        ) else verdict
        ev = [
            Evidence(key="verdict", value=verdict),
            Evidence(key="passed", value=str(passed)),
            Evidence(key="failed", value=str(len(failing))),
            Evidence(key="total", value=str(total)),
        ]
        for i, c in enumerate(failing[:15]):
            ev.append(Evidence(
                key=f"failing_control_{i + 1}",
                value=f"{c.get('test_name', '?')} ({c.get('control_validator', '?')})",
            ))
        if len(failing) > 15:
            ev.append(Evidence(key="more_not_shown",
                               value=f"{len(failing) - 15} more not shown"))
        if truncated:
            ev.append(Evidence(
                key="window_truncated",
                value=f"verdict based on {len(rows)} of {total_items} rows in window",
            ))
        techniques = {str(t) for c in failing for t in (c.get("techniques") or []) if t}
        ent = Entity(kind=EntityKind.host, id=host, name=host) if host else None
        out.append(Finding(
            source="projectachilles",
            finding_type=ftype,
            severity=sev,
            title=f"{bname} on {host}: {verdict_label} ({passed}/{total} controls passed)",
            entity=ent,
            evidence=ev,
            references=[Reference(type="mitre", id=t) for t in sorted(techniques)],
            observed_at=ctrls[0].get("timestamp"),
        ))

    # Non-bundle rows keep the existing per-row security/hygiene vocabulary.
    for x in single_rows:
        host = x.get("hostname", "")
        name = x.get("test_name", "test")
        # PA runs two kinds of check (the `category` field). Cyber-hygiene rows are
        # configuration/hardening control checks — passed vs NOT passed — not attack
        # simulations, so the blocked/detected vocabulary does not apply (a config
        # check launches no attack; defender_detected is meaningless for it).
        # Normalize separators/case so a backend spelling tweak (cyber_hygiene,
        # "Cyber Hygiene") can't silently fall back to the "NOT blocked" branch.
        category = str(x.get("category", "")).strip().lower().replace("_", "-").replace(" ", "-")
        if category == "cyber-hygiene":
            kind = "cyber-hygiene"
            if x.get("is_protected"):
                sev, ftype, outcome = Severity.info, FindingType.posture, "passed"
            else:
                sev = _SEV.get(str(x.get("severity", "high")).lower(), Severity.high)
                ftype, outcome = FindingType.misconfig, "not passed"
        elif x.get("is_protected"):
            kind = "security"
            sev, ftype, outcome = Severity.info, FindingType.posture, "blocked"
        elif x.get("defender_detected"):
            kind = "security"
            sev, ftype, outcome = Severity.low, FindingType.misconfig, "detected, not blocked"
        else:
            kind = "security"
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
                evidence=[
                    Evidence(key="outcome", value=outcome),
                    Evidence(key="check_kind", value=kind),
                ],
                references=[Reference(type="mitre", id=t) for t in (x.get("techniques") or [])],
                observed_at=x.get("timestamp"),
            )
        )
    return out


async def list_risk_acceptances(pa: Any, status: str = "active", limit: int = 50) -> list[Finding]:
    limit = clamp_limit(limit)
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
    limit = clamp_limit(limit)
    params: dict[str, Any] = {"limit": limit, "online_only": str(online_only).lower()}
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
                Evidence(key="agents_online", value=str(online)),
                Evidence(key="agents_offline", value=str(m.get("offline", 0))),
                Evidence(key="agents_total", value=str(total)),
                Evidence(key="pending_tasks", value=str(m.get("pending_tasks", 0))),
            ],
        )
    ]
