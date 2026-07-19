"""ProjectAchilles actions MCP server (stdio). Gated writes + 2 reads.

Companion to the read-only projectachilles-mcp server. Every write is gated:
PROJECTACHILLES_ALLOW_WRITE=true AND a fresh single-use confirmation token
(scripts/confirm_action.py --platform projectachilles). Findings are redacted
before they leave the server.
"""
from __future__ import annotations

import os
from typing import Any, Literal

from dotenv import load_dotenv
from f0_sectools_core.auth.config import ProjectAchillesConfig
from f0_sectools_core.gating.actions import AuditLog, GatedAction, TokenStore
from f0_sectools_core.redaction.redact import redact_obj
from f0_sectools_core.schema.findings import Finding
from mcp.server.fastmcp import FastMCP

from . import tools
from .client import ProjectAchillesClient

load_dotenv(".env.projectachilles")

mcp = FastMCP("f0-pa-actions")


def _render(findings: list[Finding]) -> list[dict[str, Any]]:
    """Dump findings and redact every payload before it leaves the server."""
    return [redact_obj(f.model_dump()) for f in findings]


def _gate(name: str, cfg: ProjectAchillesConfig) -> GatedAction:
    return GatedAction(
        name,
        enabled=cfg.allow_write,
        audit=AuditLog(os.environ.get("PROJECTACHILLES_AUDIT_LOG_PATH") or None),
        token_store=TokenStore(),
        confirm_mode=cfg.confirm_mode,
    )


_ACTOR = os.environ.get("PROJECTACHILLES_AUDIT_ACTOR", "mcp-operator")

_Day = Literal[
    "", "monday", "tuesday", "wednesday", "thursday", "friday",
    "saturday", "sunday",
]


@mcp.tool()
async def run_test(
    test_id: str, hostname: str = "", tag: str = "", confirmation_token: str = ""
) -> list[dict[str, Any]]:
    """Run a ProjectAchilles validation test now on ONE host OR a FLEET (GATED WRITE).

    Target exactly one of: `hostname` (one exact agent), or `tag` (every agent
    carrying that tag — a fleet, fanned out in one action). test_id is the
    test's UUID. Call WITHOUT confirmation_token first to preview: the intent
    lists the hosts and count. For a fleet, the confirmation is bound to the
    host COUNT, so if the tag's membership changes before you confirm you must
    re-preview and re-approve. Requires PROJECTACHILLES_ALLOW_WRITE=true.
    """
    cfg = ProjectAchillesConfig.from_env()
    async with ProjectAchillesClient(cfg) as pa:
        return _render(
            await tools.run_test(
                pa, _gate("projectachilles.run_test", cfg),
                test_id, hostname, tag, confirmation_token, _ACTOR,
            )
        )


@mcp.tool()
async def schedule_test(
    test_id: str,
    hostname: str = "",
    schedule: Literal["once", "daily", "weekly", "monthly"] = "daily",
    run_time: str = "",
    run_date: str = "",
    day: _Day = "",
    day_of_month: int = 0,
    tag: str = "",
    confirmation_token: str = "",
) -> list[dict[str, Any]]:
    """Schedule a ProjectAchilles validation test on ONE host OR a FLEET (GATED WRITE).

    Target exactly one of `hostname` or `tag` (a fleet). run_time is 24h HH:MM
    UTC. schedule=once also needs run_date (YYYY-MM-DD); weekly also needs day;
    monthly also needs day_of_month (1-31). Same count-bound confirmation as
    run_test for fleets.
    """
    cfg = ProjectAchillesConfig.from_env()
    async with ProjectAchillesClient(cfg) as pa:
        return _render(
            await tools.schedule_test(
                pa, _gate("projectachilles.schedule_test", cfg),
                test_id, hostname, schedule, run_time, run_date, day,
                day_of_month, tag, confirmation_token, _ACTOR,
            )
        )


@mcp.tool()
async def set_schedule_status(
    schedule_id: str,
    status: Literal["active", "paused"],
    confirmation_token: str = "",
) -> list[dict[str, Any]]:
    """Pause (status=paused) or resume (status=active) a ProjectAchilles test
    schedule (GATED WRITE).

    Get schedule_id from list_schedules. Same two-step confirmation flow as
    run_test. Pausing is the supported way to stop a schedule (no delete).
    """
    cfg = ProjectAchillesConfig.from_env()
    async with ProjectAchillesClient(cfg) as pa:
        return _render(
            await tools.set_schedule_status(
                pa, _gate("projectachilles.set_schedule_status", cfg),
                schedule_id, status, confirmation_token, _ACTOR,
            )
        )


@mcp.tool()
async def cancel_task(
    task_id: str, confirmation_token: str = ""
) -> list[dict[str, Any]]:
    """Cancel a pending/running ProjectAchilles test task (GATED WRITE).

    task_id comes from run_test's result or get_task_status. Same two-step
    confirmation flow as run_test.
    """
    cfg = ProjectAchillesConfig.from_env()
    async with ProjectAchillesClient(cfg) as pa:
        return _render(
            await tools.cancel_task(
                pa, _gate("projectachilles.cancel_task", cfg),
                task_id, confirmation_token, _ACTOR,
            )
        )


@mcp.tool()
async def list_schedules(
    status: Literal["", "active", "paused", "completed"] = "",
) -> list[dict[str, Any]]:
    """List ProjectAchilles recurring test schedules (read-only).

    Scheduled future runs — not past results (use list_test_executions on the
    read server for those). status '' = all.
    """
    cfg = ProjectAchillesConfig.from_env()
    async with ProjectAchillesClient(cfg) as pa:
        return _render(await tools.list_schedules(pa, status))


@mcp.tool()
async def get_task_status(task_id: str) -> list[dict[str, Any]]:
    """One-shot status check for a ProjectAchilles test-run task (read-only).

    One task by task_id (from run_test). If still running, report that status
    and do not call again until the user asks. On completion, returns the run's
    OUTCOME (bundle verdict or pass/not-passed) — no need to check again or call
    list_test_executions.
    """
    cfg = ProjectAchillesConfig.from_env()
    async with ProjectAchillesClient(cfg) as pa:
        return _render(await tools.get_task_status(pa, task_id))


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
