"""Microsoft Entra ID read tools -> findings.

Read-only. Every tool catches a Graph 403 and returns a posture finding naming
the missing permission (or required license), so a partially-configured tenant
still produces actionable guidance instead of failing.
"""
from __future__ import annotations

from f0_sectools_core.auth.graph import GraphClient, GraphError
from f0_sectools_core.schema.findings import (
    Entity,
    EntityKind,
    Evidence,
    Finding,
    FindingType,
    RecommendedAction,
    Severity,
)

_RISK = {
    "none": Severity.info,
    "low": Severity.low,
    "medium": Severity.medium,
    "high": Severity.high,
}

# Directory roles treated as the highest privilege when found assigned.
_CRITICAL_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Privileged Authentication Administrator",
    "Security Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
}


def _risk(value: str) -> Severity:
    return _RISK.get(str(value).lower(), Severity.info)


async def list_risky_users(gc: GraphClient, limit: int = 25) -> list[Finding]:
    try:
        raw = await gc.get_all("/identityProtection/riskyUsers", params={"$top": limit})
    except GraphError as e:
        if e.status == 403:
            return [
                Finding.permission_missing(
                    "entra", "IdentityRiskyUser.Read.All", "Entra risky users"
                )
            ]
        raise
    out: list[Finding] = []
    for u in raw:
        upn = u.get("userPrincipalName") or u.get("id", "unknown")
        out.append(
            Finding(
                source="entra",
                finding_type=FindingType.risk,
                severity=_risk(u.get("riskLevel", "none")),
                title=f"Risky user: {upn}",
                entity=Entity(
                    kind=EntityKind.user, id=str(u.get("id", "")), name=u.get("userPrincipalName")
                ),
                evidence=[Evidence(key="risk_state", value=str(u.get("riskState", "")))],
                recommended_action=RecommendedAction(
                    summary="Review sign-in risk; consider risk-based CA or a password reset."
                ),
                observed_at=u.get("riskLastUpdatedDateTime"),
            )
        )
    return out


async def list_risk_detections(gc: GraphClient, limit: int = 25) -> list[Finding]:
    try:
        raw = await gc.get_all("/identityProtection/riskDetections", params={"$top": limit})
    except GraphError as e:
        if e.status == 403:
            return [
                Finding.permission_missing(
                    "entra", "IdentityRiskEvent.Read.All", "Entra risk detections"
                )
            ]
        raise
    out: list[Finding] = []
    for d in raw:
        upn = d.get("userPrincipalName") or d.get("id", "unknown")
        event = d.get("riskEventType", "risk detection")
        out.append(
            Finding(
                source="entra",
                finding_type=FindingType.risk,
                severity=_risk(d.get("riskLevel", "none")),
                title=f"Risk detection: {event} ({upn})",
                entity=Entity(
                    kind=EntityKind.user,
                    id=str(d.get("userId", "")),
                    name=d.get("userPrincipalName"),
                ),
                evidence=[
                    Evidence(key="risk_state", value=str(d.get("riskState", ""))),
                    Evidence(key="detected", value=str(d.get("detectedDateTime", ""))),
                ],
                recommended_action=RecommendedAction(
                    summary="Investigate the detection; correlate with sign-in logs."
                ),
                observed_at=d.get("detectedDateTime"),
            )
        )
    return out


async def list_conditional_access_policies(gc: GraphClient) -> list[Finding]:
    try:
        raw = await gc.get_all("/identity/conditionalAccess/policies")
    except GraphError as e:
        if e.status == 403:
            return [
                Finding.permission_missing(
                    "entra", "Policy.Read.All", "conditional access policies"
                )
            ]
        raise
    out: list[Finding] = []
    for p in raw:
        state = str(p.get("state", "")).lower()
        if state == "disabled":
            sev = Severity.medium
            note = "Policy is DISABLED — confirm this is intentional."
        elif state == "enabledforreportingbutnotenforced":
            sev = Severity.low
            note = "Policy is report-only — not enforced."
        else:
            sev = Severity.info
            note = "Policy is enabled."
        out.append(
            Finding(
                source="entra",
                finding_type=FindingType.misconfig if sev != Severity.info else FindingType.posture,
                severity=sev,
                title=f"CA policy: {p.get('displayName', 'policy')} [{state or 'unknown'}]",
                entity=Entity(
                    kind=EntityKind.policy, id=str(p.get("id", "")), name=p.get("displayName")
                ),
                evidence=[Evidence(key="state", value=state or "unknown")],
                recommended_action=RecommendedAction(summary=note),
            )
        )
    return out


async def list_privileged_role_assignments(gc: GraphClient, limit: int = 100) -> list[Finding]:
    params = {"$expand": "principal,roleDefinition", "$top": limit}
    try:
        raw = await gc.get_all("/roleManagement/directory/roleAssignments", params=params)
    except GraphError as e:
        if e.status == 403:
            return [
                Finding.permission_missing(
                    "entra", "RoleManagement.Read.Directory", "privileged role assignments"
                )
            ]
        raise
    out: list[Finding] = []
    for a in raw:
        role = (a.get("roleDefinition") or {}).get("displayName", "directory role")
        principal = a.get("principal") or {}
        who = (
            principal.get("userPrincipalName")
            or principal.get("displayName")
            or principal.get("id", "unknown")
        )
        sev = Severity.high if role in _CRITICAL_ROLES else Severity.medium
        out.append(
            Finding(
                source="entra",
                finding_type=FindingType.posture,
                severity=sev,
                title=f"{role} assigned to {who}",
                entity=Entity(kind=EntityKind.user, id=str(principal.get("id", "")), name=who),
                evidence=[Evidence(key="role", value=str(role))],
                recommended_action=RecommendedAction(
                    summary="Confirm this assignment is required; prefer PIM eligibility."
                ),
            )
        )
    return out
