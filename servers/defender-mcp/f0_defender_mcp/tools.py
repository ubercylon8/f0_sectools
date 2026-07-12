"""Microsoft Defender XDR read tools -> findings.

Read-only. Every tool catches a Graph 403 and returns a posture finding naming
the missing permission, so a partially-licensed/partially-consented tenant still
produces actionable guidance instead of failing.
"""
from __future__ import annotations

from typing import Any

from f0_sectools_core.auth.graph import GraphClient, GraphError
from f0_sectools_core.gating.actions import GatedAction, GateDenied
from f0_sectools_core.graph_errors import map_graph_error
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

# Graph severity strings -> our Severity.
_SEV = {
    "unknown": Severity.info,
    "informational": Severity.info,
    "low": Severity.low,
    "medium": Severity.medium,
    "high": Severity.high,
}

# Ordering used by severity_min filters.
_RANK = {
    Severity.info: 0,
    Severity.low: 1,
    Severity.medium: 2,
    Severity.high: 3,
    Severity.critical: 4,
}

# Cap rows/items returned to keep payloads small-model-safe.
_MAX_HUNT_ROWS = 50


def _sev(value: str) -> Severity:
    return _SEV.get(str(value).lower(), Severity.info)


def _meets(sev: Severity, minimum: str) -> bool:
    floor = _SEV.get(str(minimum).lower(), Severity.medium)
    return _RANK[sev] >= _RANK[floor]


async def get_secure_score(gc: GraphClient) -> list[Finding]:
    try:
        scores = await gc.get_all("/security/secureScores", params={"$top": 1})
    except GraphError as e:
        finding = map_graph_error(
            e, "defender", "SecurityEvents.Read.All", "Microsoft Secure Score"
        )
        if finding:
            return [finding]
        raise
    if not scores:
        return []
    s = scores[0]
    current = float(s.get("currentScore", 0) or 0)
    maximum = float(s.get("maxScore", 0) or 0)
    pct = (current / maximum * 100) if maximum else 0.0
    if pct < 40:
        sev = Severity.high
    elif pct < 70:
        sev = Severity.medium
    else:
        sev = Severity.low
    return [
        Finding(
            source="defender",
            finding_type=FindingType.posture,
            severity=sev,
            title=f"Microsoft Secure Score: {current:.0f}/{maximum:.0f} ({pct:.0f}%)",
            entity=Entity(kind=EntityKind.tenant, id="tenant"),
            evidence=[
                Evidence(key="current_score", value=f"{current:.1f}"),
                Evidence(key="max_score", value=f"{maximum:.1f}"),
            ],
            recommended_action=RecommendedAction(
                summary="Review Secure Score improvement actions to raise posture."
            ),
            observed_at=s.get("createdDateTime"),
        )
    ]


async def list_incidents(
    gc: GraphClient, severity_min: str = "medium", limit: int = 25
) -> list[Finding]:
    try:
        raw = await gc.get_all("/security/incidents", params={"$top": limit})
    except GraphError as e:
        finding = map_graph_error(e, "defender", "SecurityIncident.Read.All", "Defender incidents")
        if finding:
            return [finding]
        raise
    findings: list[Finding] = []
    for inc in raw:
        alerts = inc.get("alerts") or []
        sev = _sev(inc.get("severity", "medium"))
        # A high-severity incident correlating many alerts is treated as critical.
        if sev == Severity.high and len(alerts) > 3:
            sev = Severity.critical
        if not _meets(sev, severity_min):
            continue
        findings.append(
            Finding(
                source="defender",
                finding_type=FindingType.incident,
                severity=sev,
                title=inc.get("displayName", "Defender incident"),
                entity=Entity(kind=EntityKind.tenant, id=str(inc.get("id", "unknown"))),
                evidence=[
                    Evidence(key="alerts", value=str(len(alerts))),
                    Evidence(key="status", value=str(inc.get("status", ""))),
                ],
                recommended_action=RecommendedAction(
                    summary="Investigate the incident and its correlated alerts in Defender."
                ),
                observed_at=inc.get("createdDateTime"),
            )
        )
    return findings


async def list_alerts(
    gc: GraphClient, severity_min: str = "high", limit: int = 25
) -> list[Finding]:
    try:
        raw = await gc.get_all("/security/alerts_v2", params={"$top": limit})
    except GraphError as e:
        finding = map_graph_error(e, "defender", "SecurityAlert.Read.All", "Defender alerts")
        if finding:
            return [finding]
        raise
    findings: list[Finding] = []
    for alert in raw:
        sev = _sev(alert.get("severity", "medium"))
        if not _meets(sev, severity_min):
            continue
        refs = [Reference(type="mitre", id=t) for t in (alert.get("mitreTechniques") or [])]
        findings.append(
            Finding(
                source="defender",
                finding_type=FindingType.alert,
                severity=sev,
                title=alert.get("title", "Defender alert"),
                entity=Entity(kind=EntityKind.tenant, id=str(alert.get("id", "unknown"))),
                evidence=[
                    Evidence(key="status", value=str(alert.get("status", ""))),
                    Evidence(key="category", value=str(alert.get("category", ""))),
                ],
                references=refs,
                recommended_action=RecommendedAction(summary="Triage the alert in Defender."),
                observed_at=alert.get("createdDateTime"),
            )
        )
    return findings


async def run_hunting_query(gc: GraphClient, kql: str) -> list[Finding]:
    try:
        resp = await gc.post("/security/runHuntingQuery", {"Query": kql})
    except GraphError as e:
        finding = map_graph_error(e, "defender", "ThreatHunting.Read.All", "advanced hunting")
        if finding:
            return [finding]
        raise
    rows = resp.get("results") or []
    sample = rows[:_MAX_HUNT_ROWS]
    evidence = [Evidence(key=f"row_{i}", value=str(row)) for i, row in enumerate(sample)]
    return [
        Finding(
            source="defender",
            finding_type=FindingType.hunt_result,
            severity=Severity.info,
            title=f"Hunting query returned {len(rows)} row(s)"
            + (f" (showing first {_MAX_HUNT_ROWS})" if len(rows) > _MAX_HUNT_ROWS else ""),
            evidence=evidence,
            recommended_action=RecommendedAction(
                summary="Review the returned rows; refine the query to investigate further."
            ),
        )
    ]


def _intent_finding(action_name: str, verb: str, device_id: str, comment: str,
                    extra: list[Evidence]) -> Finding:
    return Finding(
        source="defender",
        finding_type=FindingType.action,
        severity=Severity.high,
        title=f"Pending action: {verb} host {device_id} (requires confirmation)",
        entity=Entity(kind=EntityKind.host, id=device_id),
        evidence=[Evidence(key="comment", value=comment), *extra],
        recommended_action=RecommendedAction(
            summary=(
                f"To execute, an operator must run: python scripts/confirm_action.py "
                f"{action_name.split('.')[-1]} {device_id} — then call this tool again "
                f"with the printed confirmation_token."
            ),
            gated_action=action_name,
            confidence="high",
        ),
    )


def _gate_refusal(action_name: str, device_id: str, exc: GateDenied) -> Finding:
    return Finding(
        source="defender",
        finding_type=FindingType.action,
        severity=Severity.info,
        title=f"Action {action_name} not taken for {device_id}: {exc}",
        entity=Entity(kind=EntityKind.host, id=device_id),
        recommended_action=RecommendedAction(
            summary=(
                "Set DEFENDER_ALLOW_WRITE=true and supply a fresh token from "
                "scripts/confirm_action.py, then retry."
            ),
            gated_action=action_name,
            confidence="high",
        ),
    )


async def _run_machine_action(
    sec: Any, gate: GatedAction, device_id: str, comment: str, confirmation_token: str,
    actor: str, path: str, body: dict[str, Any], verb: str, intent_extra: list[Evidence],
) -> list[Finding]:
    if not confirmation_token:
        return [_intent_finding(gate.name, verb, device_id, comment, intent_extra)]
    try:
        result = await gate.execute_async(
            target=device_id,
            actor=actor,
            token=confirmation_token,
            run=lambda: sec.post(path, body),
        )
    except GateDenied as e:
        return [_gate_refusal(gate.name, device_id, e)]
    except GraphError as e:
        finding = map_graph_error(e, "defender", "Machine.Isolate", f"host {verb}")
        if finding:
            return [finding]
        # Unmapped platform error (e.g. 404 unknown device, 400 already isolated):
        # degrade to a graceful finding rather than raising. The single-use token
        # was already consumed, so retrying requires a fresh confirmation token.
        return [
            Finding(
                source="defender",
                finding_type=FindingType.action,
                severity=Severity.info,
                title=f"Action not applied: {verb} host {device_id} (platform error {e.status})",
                entity=Entity(kind=EntityKind.host, id=device_id),
                evidence=[Evidence(key="error", value=e.message)],
                recommended_action=RecommendedAction(
                    summary=(
                        f"The Defender API rejected the {verb} request. Verify the "
                        "device_id and retry with a fresh confirmation token."
                    ),
                    gated_action=gate.name,
                    confidence="high",
                ),
            )
        ]
    return [
        Finding(
            source="defender",
            finding_type=FindingType.action,
            severity=Severity.info,
            title=f"Action completed: {verb} host {device_id}",
            entity=Entity(kind=EntityKind.host, id=device_id),
            evidence=[
                Evidence(key="machine_action_id", value=str(result.get("id", ""))),
                Evidence(key="status", value=str(result.get("status", "submitted"))),
            ],
            recommended_action=RecommendedAction(
                summary=f"Track the machine action in Defender; {verb} is asynchronous.",
                gated_action=gate.name,
                confidence="high",
            ),
        )
    ]


async def isolate_host(
    sec: Any, gate: GatedAction, device_id: str, comment: str,
    confirmation_token: str = "", actor: str = "mcp-operator",
) -> list[Finding]:
    """Isolate a device from the network (gated write). No token → intent only."""
    return await _run_machine_action(
        sec, gate, device_id, comment, confirmation_token, actor,
        path=f"/machines/{device_id}/isolate",
        body={"Comment": comment, "IsolationType": "Full"},
        verb="isolate",
        intent_extra=[Evidence(key="isolation_type", value="Full")],
    )


async def release_host(
    sec: Any, gate: GatedAction, device_id: str, comment: str,
    confirmation_token: str = "", actor: str = "mcp-operator",
) -> list[Finding]:
    """Release a device from isolation (gated write). No token → intent only."""
    return await _run_machine_action(
        sec, gate, device_id, comment, confirmation_token, actor,
        path=f"/machines/{device_id}/unisolate",
        body={"Comment": comment},
        verb="release",
        intent_extra=[],
    )
