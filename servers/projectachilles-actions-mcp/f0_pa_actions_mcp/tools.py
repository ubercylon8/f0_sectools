"""Gated write tools + reads for the ProjectAchilles actions server.

Flow for every gated tool: resolve (pre-gate) -> no token? return intent ->
token? gate.execute_async (flag + single-use token + audit) -> result finding.
Every failure is a finding, never an exception.
"""
from __future__ import annotations

import re
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
from .resolve import ResolveFailed, guidance, resolve_agent, resolve_build, resolve_test

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


_TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_DOW = {
    "sunday": 0, "monday": 1, "tuesday": 2, "wednesday": 3,
    "thursday": 4, "friday": 5, "saturday": 6,
}


def _schedule_config(
    schedule: str, run_time: str, run_date: str, day: str, day_of_month: int
) -> dict[str, Any]:
    """Map flat scalar args onto the backend's schedule_config union member.

    Exactly one type-specific extra is allowed per schedule type; anything
    missing, malformed, or stray raises ResolveFailed (pre-gate, no token cost).
    """
    if not _TIME_RE.match(run_time):
        raise ResolveFailed(guidance(
            f"run_time '{run_time}' is not valid",
            "Use 24h HH:MM, e.g. 02:30 or 23:00 (UTC).",
        ))
    stray: list[str] = []
    if schedule != "once" and run_date:
        stray.append("run_date")
    if schedule != "weekly" and day:
        stray.append("day")
    if schedule != "monthly" and day_of_month:
        stray.append("day_of_month")
    if stray:
        raise ResolveFailed(guidance(
            f"Arguments {', '.join(stray)} do not apply to schedule='{schedule}'",
            "once needs run_date; weekly needs day; monthly needs day_of_month; "
            "daily needs neither.",
        ))
    if schedule == "once":
        if not _DATE_RE.match(run_date):
            raise ResolveFailed(guidance(
                "A one-off schedule needs run_date as YYYY-MM-DD",
                "Example: schedule='once', run_date='2026-08-01', run_time='14:30'.",
            ))
        return {"date": run_date, "time": run_time}
    if schedule == "daily":
        return {"time": run_time}
    if schedule == "weekly":
        if day not in _DOW:
            raise ResolveFailed(guidance(
                "A weekly schedule needs day (monday..sunday)",
                "Example: schedule='weekly', day='sunday', run_time='23:00'.",
            ))
        return {"days": [_DOW[day]], "time": run_time}
    if schedule == "monthly":
        if not 1 <= day_of_month <= 31:
            raise ResolveFailed(guidance(
                "A monthly schedule needs day_of_month between 1 and 31",
                "Example: schedule='monthly', day_of_month=15, run_time='06:00'.",
            ))
        return {"dayOfMonth": day_of_month, "time": run_time}
    raise ResolveFailed(guidance(
        f"Unknown schedule type '{schedule}'",
        "Use one of: once, daily, weekly, monthly.",
    ))


def _describe_schedule(
    schedule: str, run_time: str, run_date: str, day: str, day_of_month: int
) -> str:
    if schedule == "once":
        return f"once on {run_date} at {run_time} UTC"
    if schedule == "weekly":
        return f"weekly on {day} at {run_time} UTC"
    if schedule == "monthly":
        return f"monthly on day {day_of_month} at {run_time} UTC"
    return f"daily at {run_time} UTC"


async def schedule_test(
    pa: Any,
    gate: GatedAction,
    test_id: str,
    hostname: str,
    schedule: str,
    run_time: str,
    run_date: str = "",
    day: str = "",
    day_of_month: int = 0,
    confirmation_token: str = "",
    actor: str = "mcp-operator",
) -> list[Finding]:
    """Schedule a validation test on ONE agent (gated write). No token -> intent."""
    try:
        cfg = _schedule_config(schedule, run_time, run_date, day, day_of_month)
        test = await resolve_test(pa, test_id)
        binary = await resolve_build(pa, test["test_uuid"])
        agent = await resolve_agent(pa, hostname)
    except ResolveFailed as e:
        return [e.finding]
    target = f"{test['test_uuid']}@{agent['hostname']}"
    desc = _describe_schedule(schedule, run_time, run_date, day, day_of_month)
    entity = Entity(kind=EntityKind.host, id=agent["agent_id"], name=agent["hostname"])
    evidence = [
        Evidence(key="test_name", value=test["test_name"]),
        Evidence(key="test_uuid", value=test["test_uuid"]),
        Evidence(key="hostname", value=agent["hostname"]),
        Evidence(key="schedule", value=desc),
    ]
    if not confirmation_token:
        return [
            _intent(
                gate.name, target,
                f"schedule test '{test['test_name']}' on {agent['hostname']} ({desc})",
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
        "schedule_type": schedule,
        "schedule_config": cfg,
        "timezone": "UTC",
        "name": f"{test['test_name']} @ {agent['hostname']}",
    }
    try:
        result = await gate.execute_async(
            target=target,
            actor=actor,
            token=confirmation_token,
            run=lambda: pa.post("/agent/admin/schedules", json=body),
        )
    except GateDenied as e:
        return [_refusal(gate.name, target, e)]
    except ProjectAchillesError as e:
        return _after_gate_error(e, gate.name, target, "schedule test")
    sched = result.get("data") or {}
    return [
        Finding(
            source=_SOURCE,
            finding_type=FindingType.action,
            severity=Severity.info,
            title=f"Action completed: scheduled '{test['test_name']}' "
            f"on {agent['hostname']} ({desc})",
            entity=entity,
            evidence=[
                *evidence,
                Evidence(key="schedule_id", value=str(sched.get("id", ""))),
                Evidence(key="next_run_at", value=str(sched.get("next_run_at") or "?")),
            ],
            recommended_action=RecommendedAction(
                summary="Verify with list_schedules; pause/resume later with "
                "set_schedule_status.",
                gated_action=gate.name,
                confidence="high",
            ),
        )
    ]


async def set_schedule_status(
    pa: Any,
    gate: GatedAction,
    schedule_id: str,
    status: str,
    confirmation_token: str = "",
    actor: str = "mcp-operator",
) -> list[Finding]:
    """Pause or resume a schedule (gated write). No token -> intent."""
    sid = schedule_id.strip()
    if not sid:
        return [guidance(
            "schedule_id is required",
            "Find the id with list_schedules first.",
        )]
    if status not in ("active", "paused"):
        return [guidance(
            f"Unknown status '{status}'",
            "Use status='paused' to pause or status='active' to resume.",
        )]
    target = f"{sid}:{status}"
    verb = "pause" if status == "paused" else "resume"
    entity = Entity(kind=EntityKind.rule, id=sid)
    evidence = [Evidence(key="schedule_id", value=sid),
                Evidence(key="new_status", value=status)]
    if not confirmation_token:
        return [_intent(gate.name, target, f"{verb} schedule {sid}", entity, evidence)]
    try:
        result = await gate.execute_async(
            target=target,
            actor=actor,
            token=confirmation_token,
            run=lambda: pa.patch(f"/agent/admin/schedules/{sid}", json={"status": status}),
        )
    except GateDenied as e:
        return [_refusal(gate.name, target, e)]
    except ProjectAchillesError as e:
        return _after_gate_error(e, gate.name, target, f"{verb} schedule")
    sched = result.get("data") or {}
    return [
        Finding(
            source=_SOURCE,
            finding_type=FindingType.action,
            severity=Severity.info,
            title=f"Action completed: {verb} schedule {sid}",
            entity=entity,
            evidence=[
                Evidence(key="status", value=str(sched.get("status", status))),
                Evidence(key="next_run_at", value=str(sched.get("next_run_at") or "—")),
            ],
            recommended_action=RecommendedAction(
                summary="Verify with list_schedules.",
                gated_action=gate.name,
                confidence="high",
            ),
        )
    ]


async def cancel_task(
    pa: Any,
    gate: GatedAction,
    task_id: str,
    confirmation_token: str = "",
    actor: str = "mcp-operator",
) -> list[Finding]:
    """Cancel a pending/running test task (gated write). No token -> intent."""
    tid = task_id.strip()
    if not tid:
        return [guidance(
            "task_id is required",
            "The task_id comes from run_test's result or get_task_status.",
        )]
    target = tid
    entity = Entity(kind=EntityKind.rule, id=tid)
    evidence = [Evidence(key="task_id", value=tid)]
    if not confirmation_token:
        return [_intent(gate.name, target, f"cancel task {tid}", entity, evidence)]
    try:
        result = await gate.execute_async(
            target=target,
            actor=actor,
            token=confirmation_token,
            run=lambda: pa.post(f"/agent/admin/tasks/{tid}/cancel"),
        )
    except GateDenied as e:
        return [_refusal(gate.name, target, e)]
    except ProjectAchillesError as e:
        return _after_gate_error(e, gate.name, target, "cancel task")
    task = result.get("data") or {}
    return [
        Finding(
            source=_SOURCE,
            finding_type=FindingType.action,
            severity=Severity.info,
            title=f"Action completed: cancel task {tid}",
            entity=entity,
            evidence=[Evidence(key="status", value=str(task.get("status", "expired")))],
            recommended_action=RecommendedAction(
                summary="Confirm with get_task_status.",
                gated_action=gate.name,
                confidence="high",
            ),
        )
    ]
