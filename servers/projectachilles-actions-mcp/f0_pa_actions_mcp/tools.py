"""Gated write tools + reads for the ProjectAchilles actions server.

Flow for every gated tool: resolve (pre-gate) -> no token? return intent ->
token? gate.execute_async (flag + single-use token + audit) -> result finding.
Every failure is a finding, never an exception.
"""
from __future__ import annotations

from typing import Any

from f0_sectools_core.gating.actions import GatedAction, GateDenied
from f0_sectools_core.schema.findings import (
    Entity,
    EntityKind,
    Evidence,
    Finding,
    FindingType,
    RecommendedAction,
    Severity,
)

from .client import ProjectAchillesError
from .errors import map_pa_error
from .resolve import ResolveFailed, resolve_agent, resolve_build, resolve_test

_SOURCE = "projectachilles"


def _intent(
    action_name: str,
    target: str,
    title: str,
    entity: Entity | None,
    evidence: list[Evidence],
) -> Finding:
    short = action_name.split(".")[-1]
    return Finding(
        source=_SOURCE,
        finding_type=FindingType.action,
        severity=Severity.high,
        title=f"Pending action: {title} (requires confirmation)",
        entity=entity,
        evidence=[*evidence, Evidence(key="confirmation_target", value=target)],
        recommended_action=RecommendedAction(
            summary=(
                f"To execute, an operator must run: python scripts/confirm_action.py "
                f'{short} "{target}" --platform projectachilles — then call this '
                f"tool again with the printed confirmation_token."
            ),
            gated_action=action_name,
            confidence="high",
        ),
    )


def _refusal(action_name: str, target: str, exc: GateDenied) -> Finding:
    return Finding(
        source=_SOURCE,
        finding_type=FindingType.action,
        severity=Severity.info,
        title=f"Action {action_name} not taken for {target}: {exc}",
        recommended_action=RecommendedAction(
            summary=(
                "Set PROJECTACHILLES_ALLOW_WRITE=true and supply a fresh token from "
                "scripts/confirm_action.py (--platform projectachilles), then retry."
            ),
            gated_action=action_name,
            confidence="high",
        ),
    )


def _after_gate_error(
    e: ProjectAchillesError, gate_name: str, target: str, capability: str
) -> list[Finding]:
    finding = map_pa_error(e, capability)
    if finding:
        return [finding]
    # Unmapped platform error after the token was consumed: degrade gracefully.
    return [
        Finding(
            source=_SOURCE,
            finding_type=FindingType.action,
            severity=Severity.info,
            title=f"Action not applied: {capability} for {target} "
            f"(platform error {e.status})",
            evidence=[Evidence(key="error", value=e.message)],
            recommended_action=RecommendedAction(
                summary=(
                    f"ProjectAchilles rejected the {capability} request. The "
                    "confirmation token was consumed; retry with a fresh one."
                ),
                gated_action=gate_name,
                confidence="high",
            ),
        )
    ]


async def run_test(
    pa: Any,
    gate: GatedAction,
    test_id: str,
    hostname: str,
    confirmation_token: str = "",
    actor: str = "mcp-operator",
) -> list[Finding]:
    """Run a validation test on ONE agent now (gated write). No token -> intent."""
    try:
        test = await resolve_test(pa, test_id)
        binary = await resolve_build(pa, test["test_uuid"])
        agent = await resolve_agent(pa, hostname)
    except ResolveFailed as e:
        return [e.finding]
    target = f"{test['test_uuid']}@{agent['hostname']}"
    entity = Entity(kind=EntityKind.host, id=agent["agent_id"], name=agent["hostname"])
    evidence = [
        Evidence(key="test_name", value=test["test_name"]),
        Evidence(key="test_uuid", value=test["test_uuid"]),
        Evidence(key="hostname", value=agent["hostname"]),
        Evidence(key="binary_name", value=binary),
    ]
    if not confirmation_token:
        return [
            _intent(
                gate.name, target,
                f"run test '{test['test_name']}' on {agent['hostname']}",
                entity, evidence,
            )
        ]
    body = {
        "org_id": agent["org_id"],
        "agent_ids": [agent["agent_id"]],
        "test_uuid": test["test_uuid"],
        "test_name": test["test_name"],
        "binary_name": binary,
        "metadata": test["metadata"],
    }
    try:
        result = await gate.execute_async(
            target=target,
            actor=actor,
            token=confirmation_token,
            run=lambda: pa.post("/agent/admin/tasks", json=body),
        )
    except GateDenied as e:
        return [_refusal(gate.name, target, e)]
    except ProjectAchillesError as e:
        return _after_gate_error(e, gate.name, target, "run test")
    task_ids = (result.get("data") or {}).get("task_ids") or []
    return [
        Finding(
            source=_SOURCE,
            finding_type=FindingType.action,
            severity=Severity.info,
            title=f"Action completed: run test '{test['test_name']}' "
            f"on {agent['hostname']}",
            entity=entity,
            evidence=[
                *evidence,
                *[Evidence(key="task_id", value=str(t)) for t in task_ids[:5]],
            ],
            recommended_action=RecommendedAction(
                summary="Track it with get_task_status; once completed, see the "
                "outcome with list_test_executions on the read server.",
                gated_action=gate.name,
                confidence="high",
            ),
        )
    ]
