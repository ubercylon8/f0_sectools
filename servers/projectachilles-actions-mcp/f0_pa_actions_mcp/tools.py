"""Gated write tools + reads for the ProjectAchilles actions server.

Flow for every gated tool: resolve (pre-gate) -> no token? return intent ->
token? gate.execute_async (flag + single-use token + audit) -> result finding.
Every failure is a finding, never an exception.
"""
from __future__ import annotations

import datetime
import json
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
    Reference,
    Severity,
)

from .client import ProjectAchillesError
from .errors import map_pa_error
from .resolve import ResolveFailed, guidance, resolve_agent, resolve_build, resolve_test

_SOURCE = "projectachilles"
_ID_RE = re.compile(r"^[A-Za-z0-9._:@-]{1,64}$")


def _intent(
    action_name: str,
    target: str,
    title: str,
    entity: Entity | None,
    evidence: list[Evidence],
    confirm_mode: str = "token",
) -> Finding:
    short = action_name.split(".")[-1]
    if confirm_mode == "chat":
        summary = (
            "To execute: the operator replies 'approved' in the chat, then you "
            "call this tool again with confirmation_token set to the exact "
            f'target "{target}".'
        )
    else:
        summary = (
            "To execute: an operator approves this action in their "
            "confirm_action.py --watch terminal, then you call this tool again "
            "with the SAME arguments.\n"
            "Token fallback: python scripts/confirm_action.py "
            f'{short} "{target}" --platform projectachilles\n'
            "then pass the printed confirmation_token."
        )
    return Finding(
        source=_SOURCE,
        finding_type=FindingType.action,
        severity=Severity.high,
        title=f"Pending action: {title} (requires confirmation)",
        entity=entity,
        evidence=[*evidence, Evidence(key="confirmation_target", value=target)],
        recommended_action=RecommendedAction(
            summary=summary,
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
    if not confirmation_token and not gate.has_approval(target):
        gate.record_request(target)
        return [
            _intent(
                gate.name, target,
                f"run test '{test['test_name']}' on {agent['hostname']}",
                entity, evidence,
                confirm_mode=gate.confirm_mode,
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
                summary="Submitted as task "
                f"{task_ids[0] if task_ids else '(id pending)'}; it runs "
                "asynchronously (often minutes). Ask me later and I'll check once "
                "with get_task_status.",
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
        try:
            datetime.date.fromisoformat(run_date)
        except ValueError:
            raise ResolveFailed(guidance(
                f"run_date '{run_date}' is not a real calendar date",
                "Use a valid YYYY-MM-DD date, e.g. 2026-08-01.",
            )) from None
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
    if not confirmation_token and not gate.has_approval(target):
        gate.record_request(target)
        return [
            _intent(
                gate.name, target,
                f"schedule test '{test['test_name']}' on {agent['hostname']} ({desc})",
                entity, evidence,
                confirm_mode=gate.confirm_mode,
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
                Evidence(key="next_run_at", value=str(sched.get("next_run_at") or "—")),
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
    if not _ID_RE.match(sid):
        return [guidance(
            f"schedule_id '{sid}' contains unsupported characters",
            "Use the id exactly as shown by list_schedules.",
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
    if not confirmation_token and not gate.has_approval(target):
        gate.record_request(target)
        return [_intent(
            gate.name, target, f"{verb} schedule {sid}", entity, evidence,
            confirm_mode=gate.confirm_mode,
        )]
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
    if not _ID_RE.match(tid):
        return [guidance(
            f"task_id '{tid}' contains unsupported characters",
            "Use the id exactly as shown by run_test or get_task_status.",
        )]
    target = tid
    entity = Entity(kind=EntityKind.rule, id=tid)
    evidence = [Evidence(key="task_id", value=tid)]
    if not confirmation_token and not gate.has_approval(target):
        gate.record_request(target)
        return [_intent(
            gate.name, target, f"cancel task {tid}", entity, evidence,
            confirm_mode=gate.confirm_mode,
        )]
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


async def list_schedules(pa: Any, status: str = "") -> list[Finding]:
    """List recurring test schedules (read). status '' = all."""
    params: dict[str, Any] = {}
    if status:
        params["status"] = status
    try:
        resp = await pa.get("/agent/admin/schedules", params=params or None)
    except Exception as e:
        finding = map_pa_error(e, "list schedules")
        if finding:
            return [finding]
        raise
    rows = resp.get("data") if isinstance(resp, dict) else None
    rows = rows if isinstance(rows, list) else []
    if not rows:
        which = f"{status} " if status else ""
        return [
            Finding(
                source=_SOURCE,
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"0 {which}test schedules found",
                entity=Entity(kind=EntityKind.tenant, id="schedules"),
            )
        ]
    out: list[Finding] = []
    for s in rows[:50]:
        if not isinstance(s, dict):
            continue
        name = s.get("name") or s.get("test_name") or "schedule"
        out.append(
            Finding(
                source=_SOURCE,
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"Schedule: {name} ({s.get('schedule_type', '?')}, "
                f"{s.get('status', '?')})",
                entity=Entity(kind=EntityKind.rule, id=str(s.get("id", "")),
                              name=str(name)),
                evidence=[
                    Evidence(key="test_name", value=str(s.get("test_name") or "?")),
                    Evidence(key="next_run_at", value=str(s.get("next_run_at") or "—")),
                    Evidence(key="agent_count",
                             value=str(len(s.get("agent_ids") or []))),
                ],
            )
        )
    return out


_TASK_DONE_BAD = ("failed", "expired")
_HIGH_SEV = ("critical", "high")
_MAX_FAILING = 15


def _safe_int(value: Any) -> int:
    """Safe integer conversion; returns 0 on any failure."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return 0


def _as_dict(value: Any) -> dict[str, Any]:
    """Accept a dict or a JSON string; return {} on anything else/malformed."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _bundle_rollup(host: str, result: dict[str, Any]) -> Finding | None:
    """One rollup Finding from a completed task's pre-aggregated bundle_results,
    or None when the result is not a bundle (caller falls back to exit_code)."""
    # Try the "bundle_results" key first, then fall back to checking if result itself is a bundle.
    # Detect on "controls" (a list), NOT "total_controls" — the count fields can be
    # entirely absent while controls is still populated, and that must still be
    # recognized as a bundle rather than silently falling through to exit_code.
    br = _as_dict(result.get("bundle_results"))
    if not br and "bundle_name" in result and isinstance(result.get("controls"), list):
        # Result is the bundle data directly
        br = result
    if not br:
        return None
    name = str(br.get("bundle_name") or "bundle")
    total = _safe_int(br.get("total_controls"))
    passed = _safe_int(br.get("passed_controls"))
    failed = _safe_int(br.get("failed_controls"))
    controls_raw = br.get("controls")
    controls = controls_raw if isinstance(controls_raw, list) else []
    failing = [c for c in controls if isinstance(c, dict) and not c.get("compliant")]
    # The pre-aggregated counts can be missing/non-numeric (-> 0 via _safe_int).
    # When that happens but controls is populated, derive trustworthy counts from
    # it rather than reporting a bogus "0/0".
    if total == 0 and controls:
        total = len(controls)
        failed = len(failing)
        passed = total - failed
    # Guard: empty/signal-less bundle should fall through to exit_code path.
    # A bundle with no controls and no evaluable signal (total/failed/exit_code all 0)
    # must return None so get_task_status uses the exit_code verdict instead.
    if not controls and total == 0 and failed == 0 and _safe_int(br.get("overall_exit_code")) == 0:
        return None

    # A failing bundle must NEVER read COMPLIANT: fall back to the controls list
    # itself (not just the count fields) so a missing/non-numeric failed_controls
    # or overall_exit_code can't mask real failing controls in evidence.
    non_compliant = failed > 0 or _safe_int(br.get("overall_exit_code")) != 0 or bool(failing)
    if non_compliant:
        any_high = any(str(c.get("severity", "")).lower() in _HIGH_SEV for c in failing)
        sev = Severity.high if any_high else Severity.medium
        ftype = FindingType.misconfig
        verdict = "NON-COMPLIANT"
    else:
        sev, ftype, verdict = Severity.info, FindingType.posture, "COMPLIANT"
    ev = [
        Evidence(key="verdict", value=verdict),
        Evidence(key="passed", value=str(passed)),
        Evidence(key="failed", value=str(failed)),
        Evidence(key="total", value=str(total)),
    ]
    for i, c in enumerate(failing[:_MAX_FAILING]):
        ev.append(Evidence(
            key=f"failing_control_{i + 1}",
            value=f"{c.get('control_name', '?')} ({c.get('validator', '?')}) "
            f"— {c.get('severity', '?')}",
        ))
    if len(failing) > _MAX_FAILING:
        ev.append(Evidence(key="more_not_shown",
                           value=f"{len(failing) - _MAX_FAILING} more not shown"))
    techniques = {
        str(t) for c in failing for t in (c.get("techniques") or []) if t
    }
    where = f" on {host}" if host else ""
    return Finding(
        source=_SOURCE,
        finding_type=ftype,
        severity=sev,
        title=f"{name}{where}: {verdict} ({passed}/{total} controls passed)",
        entity=Entity(kind=EntityKind.host, id=host, name=host) if host else None,
        evidence=ev,
        references=[Reference(type="mitre", id=t) for t in sorted(techniques)],
    )


async def get_task_status(pa: Any, task_id: str) -> list[Finding]:
    """One-shot status-and-result check for one task_id (read).

    If the task is still running, report that status and STOP — do not call again
    until the user asks. On completion this returns the run's OUTCOME (bundle
    verdict or pass/not-passed), so there is no need to check again or to call
    the read server.
    """
    tid = task_id.strip()
    if not tid:
        return [guidance(
            "task_id is required",
            "The task_id comes from run_test's result finding.",
        )]
    try:
        resp = await pa.get(f"/agent/admin/tasks/{tid}")
    except Exception as e:
        finding = map_pa_error(e, "task status")
        if finding:
            return [finding]
        raise
    t = resp.get("data") if isinstance(resp, dict) else None
    t = t if isinstance(t, dict) else {}
    status = str(t.get("status", "unknown"))
    payload_obj = t.get("payload")
    payload = payload_obj if isinstance(payload_obj, dict) else {}
    host = str(t.get("agent_hostname") or "")
    test_name = str(payload.get("test_name") or "test")

    if status == "completed":
        result = _as_dict(t.get("result"))
        rollup = _bundle_rollup(host, result)
        if rollup is not None:
            return [rollup]
        # Non-bundle single test: use the exit code.
        exit_code = result.get("exit_code")
        where = f" on {host}" if host else ""
        if exit_code in (0, "0") and not isinstance(exit_code, bool):
            return [Finding(
                source=_SOURCE, finding_type=FindingType.posture, severity=Severity.info,
                title=f"{test_name}{where}: passed",
                entity=Entity(kind=EntityKind.host, id=host, name=host) if host else None,
                evidence=[Evidence(key="status", value="completed"),
                          Evidence(key="exit_code", value=str(exit_code))],
            )]
        if exit_code is not None:
            return [Finding(
                source=_SOURCE, finding_type=FindingType.misconfig, severity=Severity.medium,
                title=f"{test_name}{where}: not passed",
                entity=Entity(kind=EntityKind.host, id=host, name=host) if host else None,
                evidence=[Evidence(key="status", value="completed"),
                          Evidence(key="exit_code", value=str(exit_code))],
            )]
        # Completed but no parsable outcome — graceful, never a crash.
        return [Finding(
            source=_SOURCE, finding_type=FindingType.posture, severity=Severity.info,
            title=f"Task {tid}{where}: completed (outcome unavailable)",
            entity=Entity(kind=EntityKind.rule, id=tid),
            evidence=[Evidence(key="status", value="completed"),
                      Evidence(key="test_name", value=test_name)],
            recommended_action=RecommendedAction(
                summary="The task finished but returned no parsable result payload.",
                confidence="medium"),
        )]

    # Not completed (pending/assigned/.../failed/expired): status only.
    sev = Severity.medium if status in _TASK_DONE_BAD else Severity.info
    evidence = [
        Evidence(key="status", value=status),
        Evidence(key="test_name", value=test_name),
        Evidence(key="agent_id", value=str(t.get("agent_id") or "?")),
    ]
    if t.get("error"):
        evidence.append(Evidence(key="error", value=str(t["error"])))
    return [Finding(
        source=_SOURCE,
        finding_type=FindingType.posture,
        severity=sev,
        title=f"Task {tid}: {status}",
        entity=Entity(kind=EntityKind.rule, id=tid),
        evidence=evidence,
        recommended_action=RecommendedAction(
            summary=(
                "Still running (async, often minutes). I will not check again until "
                "you ask — say 'check the test' later."
            ) if status not in _TASK_DONE_BAD else
            "This task did not complete; run_test again if you still need the result.",
            confidence="high",
        ),
    )]
