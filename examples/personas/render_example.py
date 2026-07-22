"""One evidence base, five altitudes — render the same findings per persona.

Reproduces every output shown in this directory's README.md:

    uv run python examples/personas/render_example.py

Deterministic and model-free: `core/renderers/` builds these strings from the
structured findings; no LLM is involved. Same input, same output, every time.
"""
from f0_sectools_core.renderers import REGISTRY, render_findings
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

FINDINGS = [
    Finding(
        source="defender",
        finding_type=FindingType.alert,
        severity=Severity.high,
        title="Brute-force authentication against host web-01",
        entity=Entity(kind=EntityKind.host, id="web-01", name="web-01.corp.local"),
        evidence=[
            Evidence(key="failed_logins", value="142 in 5m"),
            Evidence(key="source_ip", value="203.0.113.44"),
            Evidence(key="account_targeted", value="svc-backup"),
        ],
        recommended_action=RecommendedAction(
            summary="Isolate host and reset affected credentials",
            gated_action="defender.isolate_host",
            confidence="medium",
        ),
        references=[Reference(type="mitre", id="T1110")],
        observed_at="2026-06-28T10:00:00Z",
    ),
    Finding(
        source="entra",
        finding_type=FindingType.risk,
        severity=Severity.medium,
        title="Risky sign-in for user svc-backup (unfamiliar location)",
        entity=Entity(kind=EntityKind.user, id="svc-backup", name="svc-backup@corp.local"),
        evidence=[
            Evidence(key="risk_state", value="atRisk"),
            Evidence(key="detection", value="unfamiliarFeatures"),
        ],
        recommended_action=RecommendedAction(
            summary="Review sign-in and consider credential reset", confidence="medium"
        ),
        references=[Reference(type="mitre", id="T1078")],
        observed_at="2026-06-28T10:02:00Z",
    ),
]


if __name__ == "__main__":
    for persona in REGISTRY:
        print(f"═══ {persona} " + "═" * (60 - len(persona)))
        print(render_findings(FINDINGS, persona))
        print()
