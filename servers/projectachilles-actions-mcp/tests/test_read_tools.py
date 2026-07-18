"""Ungated reads: list_schedules and get_task_status."""
from __future__ import annotations

import httpx
import pytest
import respx
from f0_pa_actions_mcp.client import ProjectAchillesClient
from f0_pa_actions_mcp.tools import get_task_status, list_schedules
from f0_sectools_core.auth.config import ProjectAchillesConfig
from f0_sectools_core.schema.findings import Severity

BASE = "https://org.agent.example.com"


def _cfg() -> ProjectAchillesConfig:
    return ProjectAchillesConfig(base_url=BASE, api_key="pa_test")


SCHEDULES = {"data": [
    {"id": "sched-1", "name": "BF nightly", "test_name": "Brute Force SSH",
     "schedule_type": "daily", "status": "active",
     "next_run_at": "2026-07-19T02:30:00Z", "agent_ids": ["ag-1"]},
    {"id": "sched-2", "name": None, "test_name": "Ransomware Sim",
     "schedule_type": "weekly", "status": "paused",
     "next_run_at": None, "agent_ids": ["ag-1", "ag-2"]},
]}


@pytest.mark.asyncio
async def test_list_schedules_one_finding_per_schedule():
    with respx.mock() as router:
        route = router.get(f"{BASE}/api/agent/admin/schedules").mock(
            return_value=httpx.Response(200, json=SCHEDULES)
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await list_schedules(pa)
    assert route.calls[0].request.url.params.get("status") is None
    assert len(findings) == 2
    assert "BF nightly" in findings[0].title
    assert any(ev.key == "next_run_at" for ev in findings[0].evidence)
    assert any(ev.key == "agent_count" and ev.value == "2" for ev in findings[1].evidence)


@pytest.mark.asyncio
async def test_list_schedules_status_filter_passed_through():
    with respx.mock() as router:
        route = router.get(f"{BASE}/api/agent/admin/schedules").mock(
            return_value=httpx.Response(200, json={"data": []})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await list_schedules(pa, status="paused")
    assert route.calls[0].request.url.params["status"] == "paused"
    assert len(findings) == 1                     # honest empty summary finding
    assert "0" in findings[0].title


@pytest.mark.asyncio
async def test_get_task_status_completed_is_info():
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/tasks/task-1").mock(
            return_value=httpx.Response(200, json={"data": {
                "id": "task-1", "status": "completed", "agent_id": "ag-1",
                "payload": {"test_name": "Brute Force SSH"},
            }})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await get_task_status(pa, "task-1")
    f = findings[0]
    assert f.severity == Severity.info
    assert "completed" in f.title
    assert any(ev.key == "test_name" and "Brute Force" in ev.value for ev in f.evidence)


@pytest.mark.asyncio
async def test_get_task_status_failed_is_medium():
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/tasks/task-2").mock(
            return_value=httpx.Response(200, json={"data": {
                "id": "task-2", "status": "failed", "error": "timeout",
                "payload": {"test_name": "Ransomware Sim"},
            }})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await get_task_status(pa, "task-2")
    assert findings[0].severity == Severity.medium


@pytest.mark.asyncio
async def test_get_task_status_404_is_graceful():
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/tasks/gone").mock(
            return_value=httpx.Response(404, json={"error": "Task not found"})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await get_task_status(pa, "gone")
    assert len(findings) == 1
    assert "404" in findings[0].title


@pytest.mark.asyncio
async def test_get_task_status_empty_id_guides():
    async with ProjectAchillesClient(_cfg()) as pa:
        findings = await get_task_status(pa, " ")
    assert "task_id" in findings[0].title
