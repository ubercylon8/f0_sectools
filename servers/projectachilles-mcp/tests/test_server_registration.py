"""The catalog tools must be registered on the FastMCP server."""
import pytest
from f0_projectachilles_mcp import server


@pytest.mark.asyncio
async def test_catalog_tools_registered():
    names = {t.name for t in await server.mcp.list_tools()}
    assert {"find_tests", "get_test"} <= names
    # server stays within the small-model tool budget
    assert len(names) == 8
