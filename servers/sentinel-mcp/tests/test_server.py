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


async def test_transport_failure_returns_a_finding_not_a_raw_exception(monkeypatch):
    """End-to-end through the real registration path: a DNS/TLS failure used to
    reach the MCP client as a bare ConnectError string, bypassing redaction."""
    class Boom:
        retention_days = 30
        has_arm = True
        workspace_id = "ws"

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def query(self, *a, **k):
            raise ConnectionError("failed to resolve internal-collector.example")

    monkeypatch.setattr(server, "_client", lambda: Boom())
    out = await server.list_data_sources()
    assert out[0]["finding_type"] == "posture"
    assert "temporarily unavailable" in out[0]["title"]
