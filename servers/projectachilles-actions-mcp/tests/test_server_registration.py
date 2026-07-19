"""Registration test: 6 tools, Literal enums surface in the schema."""
from __future__ import annotations

import pytest
from f0_pa_actions_mcp import server


@pytest.mark.asyncio
async def test_exactly_six_tools_registered():
    tools = await server.mcp.list_tools()
    assert {t.name for t in tools} == {
        "run_test", "schedule_test", "set_schedule_status",
        "cancel_task", "list_schedules", "get_task_status",
    }


@pytest.mark.asyncio
async def test_schedule_enum_is_closed_in_schema():
    tools = {t.name: t for t in await server.mcp.list_tools()}
    props = tools["schedule_test"].inputSchema["properties"]
    assert set(props["schedule"]["enum"]) == {"once", "daily", "weekly", "monthly"}
    assert set(props["day"]["enum"]) == {
        "", "monday", "tuesday", "wednesday", "thursday", "friday",
        "saturday", "sunday",
    }


@pytest.mark.asyncio
async def test_status_enums_closed():
    tools = {t.name: t for t in await server.mcp.list_tools()}
    set_props = tools["set_schedule_status"].inputSchema["properties"]
    assert set(set_props["status"]["enum"]) == {"active", "paused"}
    list_props = tools["list_schedules"].inputSchema["properties"]
    assert set(list_props["status"]["enum"]) == {"", "active", "paused", "completed"}


@pytest.mark.asyncio
async def test_run_and_schedule_expose_tag_param():
    tools = {t.name: t for t in await server.mcp.list_tools()}
    assert "tag" in tools["run_test"].inputSchema["properties"]
    assert "tag" in tools["schedule_test"].inputSchema["properties"]
