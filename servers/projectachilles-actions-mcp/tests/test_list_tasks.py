"""list_tasks read-tool tests."""
from __future__ import annotations

import httpx
import pytest
import respx
from f0_pa_actions_mcp.client import ProjectAchillesClient
from f0_pa_actions_mcp.tools import list_tasks
from f0_sectools_core.auth.config import ProjectAchillesConfig

BASE = "https://org.agent.example.com"


def _cfg() -> ProjectAchillesConfig:
    return ProjectAchillesConfig(base_url=BASE, api_key="pa_test", allow_write=True)


def _tasks_response(tasks, total):
    return httpx.Response(200, json={"success": True, "data": {"tasks": tasks, "total": total}})


@pytest.mark.asyncio
async def test_list_tasks_returns_summary_and_per_task():
    tasks = [
        {"id": "t1", "status": "pending", "agent_hostname": "web-01",
         "payload": {"test_name": "Kerberoast"}, "created_at": "2026-07-19T10:00:00Z"},
        {"id": "t2", "status": "running", "agent_hostname": "web-02",
         "payload": {"test_name": "Kerberoast"}, "created_at": "2026-07-19T10:00:01Z"},
    ]
    with respx.mock as router:
        route = router.get(f"{BASE}/api/agent/admin/tasks").mock(
            return_value=_tasks_response(tasks, 2))
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await list_tasks(pa, status="", search="", limit=25)
    assert route.called
    # First finding is the summary; then one per task.
    assert "2" in findings[0].title
    titles = [f.title for f in findings[1:]]
    assert "Kerberoast on web-01: pending" in titles
    assert "Kerberoast on web-02: running" in titles


@pytest.mark.asyncio
async def test_list_tasks_passes_status_and_search():
    with respx.mock as router:
        route = router.get(f"{BASE}/api/agent/admin/tasks").mock(
            return_value=_tasks_response([], 0))
        async with ProjectAchillesClient(_cfg()) as pa:
            await list_tasks(pa, status="pending", search="web-01", limit=10)
    sent = route.calls[0].request.url
    assert "status=pending" in str(sent)
    assert "search=web-01" in str(sent)
    assert "limit=10" in str(sent)


@pytest.mark.asyncio
async def test_list_tasks_clamps_oversized_limit():
    with respx.mock as router:
        route = router.get(f"{BASE}/api/agent/admin/tasks").mock(
            return_value=_tasks_response([], 0))
        async with ProjectAchillesClient(_cfg()) as pa:
            await list_tasks(pa, limit=5000)
    assert "limit=100" in str(route.calls[0].request.url)


@pytest.mark.asyncio
async def test_list_tasks_empty_is_clean():
    with respx.mock as router:
        router.get(f"{BASE}/api/agent/admin/tasks").mock(
            return_value=_tasks_response([], 0))
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await list_tasks(pa)
    assert len(findings) == 1  # summary only, no error
    assert findings[0].finding_type.value == "posture"


@pytest.mark.asyncio
async def test_list_tasks_permission_error_is_finding():
    with respx.mock as router:
        router.get(f"{BASE}/api/agent/admin/tasks").mock(
            return_value=httpx.Response(403, json={"error": "forbidden"}))
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await list_tasks(pa)
    assert findings[0].finding_type.value in ("posture", "misconfig")
    assert "permission" in (findings[0].title + findings[0].recommended_action.summary).lower()


@pytest.mark.asyncio
async def test_list_tasks_rejects_control_char_search():
    with respx.mock(assert_all_called=False) as router:
        route = router.get(f"{BASE}/api/agent/admin/tasks")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await list_tasks(pa, search="bad\nsearch")
    assert route.called is False
    assert findings[0].finding_type.value == "posture"
