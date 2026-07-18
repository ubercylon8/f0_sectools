"""Client tests: /api prefixing, error wrapping, post/patch bodies."""
from __future__ import annotations

import httpx
import pytest
import respx
from f0_pa_actions_mcp.client import ProjectAchillesClient, ProjectAchillesError
from f0_sectools_core.auth.config import ProjectAchillesConfig

BASE = "https://org.agent.example.com"


def _cfg(**kw) -> ProjectAchillesConfig:
    return ProjectAchillesConfig(base_url=BASE, api_key="pa_test", **kw)


@pytest.mark.asyncio
async def test_get_prefixes_api_and_returns_json():
    with respx.mock(assert_all_called=True) as router:
        router.get(f"{BASE}/api/agent/admin/schedules").mock(
            return_value=httpx.Response(200, json={"success": True, "data": []})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            d = await pa.get("/agent/admin/schedules")
    assert d == {"success": True, "data": []}


@pytest.mark.asyncio
async def test_post_sends_json_body():
    with respx.mock(assert_all_called=True) as router:
        route = router.post(f"{BASE}/api/agent/admin/tasks").mock(
            return_value=httpx.Response(201, json={"success": True, "data": {"task_ids": ["t1"]}})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            d = await pa.post("/agent/admin/tasks", json={"org_id": "o1"})
    assert d["data"]["task_ids"] == ["t1"]
    import json as _json
    assert _json.loads(route.calls[0].request.content) == {"org_id": "o1"}


@pytest.mark.asyncio
async def test_patch_sends_json_body():
    with respx.mock(assert_all_called=True) as router:
        route = router.patch(f"{BASE}/api/agent/admin/schedules/s1").mock(
            return_value=httpx.Response(200, json={"success": True, "data": {"id": "s1"}})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            d = await pa.patch("/agent/admin/schedules/s1", json={"status": "paused"})
    assert d["data"]["id"] == "s1"
    import json as _json
    assert _json.loads(route.calls[0].request.content) == {"status": "paused"}


@pytest.mark.asyncio
async def test_error_status_raises_wrapped_error_with_message():
    with respx.mock() as router:
        router.post(f"{BASE}/api/agent/admin/tasks").mock(
            return_value=httpx.Response(403, json={"error": "Missing permission"})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            with pytest.raises(ProjectAchillesError) as ei:
                await pa.post("/agent/admin/tasks", json={})
    assert ei.value.status == 403
    assert "Missing permission" in ei.value.message


@pytest.mark.asyncio
async def test_empty_body_returns_empty_dict():
    with respx.mock() as router:
        router.post(f"{BASE}/api/agent/admin/tasks/t1/cancel").mock(
            return_value=httpx.Response(200)
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            d = await pa.post("/agent/admin/tasks/t1/cancel")
    assert d == {}
