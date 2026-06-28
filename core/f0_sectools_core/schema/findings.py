"""Normalized findings schema. Every f0_sectools tool returns Finding(s).

This is the single output contract shared across every platform server. Agents —
and small local models especially — can rely on a flat, predictable shape rather
than parsing platform-specific JSON.
"""
from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class EntityKind(StrEnum):
    host = "host"
    user = "user"
    file = "file"
    ip = "ip"
    account = "account"
    app = "app"
    service_principal = "service_principal"
    role = "role"
    policy = "policy"
    rule = "rule"
    tenant = "tenant"
    device = "device"


class FindingType(StrEnum):
    alert = "alert"
    incident = "incident"
    misconfig = "misconfig"
    risk = "risk"
    ioc = "ioc"
    posture = "posture"
    hunt_result = "hunt_result"
    action = "action"


class Entity(BaseModel):
    kind: EntityKind
    id: str
    name: str | None = None


class Evidence(BaseModel):
    key: str
    value: str


class Reference(BaseModel):
    type: str
    id: str
    url: str | None = None


class RecommendedAction(BaseModel):
    summary: str
    gated_action: str | None = None
    confidence: str = "medium"


class Finding(BaseModel):
    schema_version: str = "1.0"
    source: str
    finding_type: FindingType
    severity: Severity
    title: str
    entity: Entity | None = None
    evidence: list[Evidence] = Field(default_factory=list)
    recommended_action: RecommendedAction | None = None
    references: list[Reference] = Field(default_factory=list)
    observed_at: str | None = None

    @classmethod
    def permission_missing(cls, source: str, permission: str, capability: str) -> Finding:
        """Build a posture finding telling the operator which permission to grant.

        Used by servers when a platform returns 403, so a partially-configured
        tenant produces actionable guidance instead of a crash.
        """
        return cls(
            source=source,
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=f"Permission '{permission}' not granted — {capability} unavailable",
            recommended_action=RecommendedAction(
                summary=(
                    f"Grant the application permission '{permission}' (admin consent) "
                    f"to enable {capability}."
                ),
                confidence="high",
            ),
        )

    @classmethod
    def rate_limited(cls, source: str, capability: str) -> Finding:
        """Build a posture finding for a sustained platform throttle (HTTP 429).

        Used by servers when a platform keeps returning 429 after the client's
        retry budget, so a transient throttle degrades to actionable guidance
        instead of an exception reaching the agent.
        """
        return cls(
            source=source,
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=f"Rate limited by the platform — {capability} temporarily unavailable",
            recommended_action=RecommendedAction(
                summary=(
                    f"The platform throttled the request (HTTP 429). Retry {capability} "
                    "shortly; reduce call frequency if it persists."
                ),
                confidence="high",
            ),
        )
