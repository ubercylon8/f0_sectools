"""Server-registration contract: tool count, names, and routing docstrings."""
from __future__ import annotations

from f0_sentinel_mcp import server

EXPECTED = {
    "list_data_sources", "hunt_firewall", "hunt_dns_web", "search_office_activity",
    "list_sentinel_incidents", "get_detection_coverage", "run_kql",
}


async def _tools():
    return {t.name: t for t in await server.mcp.list_tools()}


async def test_registers_exactly_the_seven_tools():
    assert set(await _tools()) == EXPECTED


async def test_no_tool_name_collides_with_another_server():
    # f0-defender already owns list_incidents and run_hunting_query.
    names = set(await _tools())
    assert "list_incidents" not in names
    assert "run_hunting_query" not in names


async def test_arguments_are_flat_scalars_only():
    for name, t in (await _tools()).items():
        for arg, spec in (t.input_schema or {}).get("properties", {}).items():
            assert spec.get("type") != "object", f"{name}.{arg} is a nested object"
            assert spec.get("type") != "array", f"{name}.{arg} is an array"


async def test_routing_docstrings_name_the_neighbouring_tool():
    tools = await _tools()
    assert "hunt_dns_web" in (tools["hunt_firewall"].description or "")
    assert "run_hunting_query" in (tools["run_kql"].description or "")
    assert "list_incidents" in (tools["list_sentinel_incidents"].description or "")
    assert "search_audit_log" in (tools["search_office_activity"].description or "")
