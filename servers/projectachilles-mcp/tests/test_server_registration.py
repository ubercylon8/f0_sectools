"""The catalog tools must be registered on the FastMCP server."""
import pytest
from f0_projectachilles_mcp import server


@pytest.mark.asyncio
async def test_catalog_tools_registered():
    names = {t.name for t in await server.mcp.list_tools()}
    assert {"find_tests", "get_test"} <= names
    # server stays within the small-model tool budget
    assert len(names) == 8


@pytest.mark.asyncio
async def test_risk_acceptance_and_find_tests_enums_closed():
    tools = {t.name: t for t in await server.mcp.list_tools()}
    status_enum = tools["list_risk_acceptances"].inputSchema["properties"]["status"]["enum"]
    assert set(status_enum) == {"active", "revoked"}
    by_enum = tools["find_tests"].inputSchema["properties"]["by"]["enum"]
    assert set(by_enum) == {
        "technique", "actor", "tactic", "category", "tag", "keyword"}


@pytest.mark.asyncio
async def test_open_passthrough_params_stay_free_strings():
    tools = {t.name: t for t in await server.mcp.list_tools()}
    # list_agents.status is an unvalidated passthrough filter — must NOT be a closed enum.
    assert "enum" not in tools["list_agents"].inputSchema["properties"]["status"]
