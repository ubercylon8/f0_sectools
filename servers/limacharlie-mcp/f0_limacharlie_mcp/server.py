"""LimaCharlie MCP server (stdio). Read-only tools over the limacharlie SDK.

The SDK is synchronous, so each tool runs in a worker thread to avoid blocking
the event loop. Findings are redacted before they leave the server.
"""
from __future__ import annotations

import asyncio

from dotenv import load_dotenv
from f0_sectools_core.auth.config import LimaCharlieConfig
from f0_sectools_core.redaction.redact import redact_obj
from f0_sectools_core.schema.findings import Finding
from mcp.server.fastmcp import FastMCP

from . import tools
from .client import LimaCharlieClient

load_dotenv(".env.limacharlie")

mcp = FastMCP("f0-limacharlie")


def _render(findings: list[Finding]) -> list[dict]:
    return [redact_obj(f.model_dump()) for f in findings]


def _client() -> LimaCharlieClient:
    return LimaCharlieClient(LimaCharlieConfig.from_env())


@mcp.tool()
async def get_org_overview() -> list[dict]:
    """LimaCharlie org posture: sensor counts, D&R rule count, recent detection volume."""
    return _render(await asyncio.to_thread(tools.get_org_overview, _client()))


@mcp.tool()
async def list_sensors(online_only: bool = False, limit: int = 50) -> list[dict]:
    """List LimaCharlie sensors (endpoints): hostname, platform, online status."""
    return _render(await asyncio.to_thread(tools.list_sensors, _client(), online_only, limit))


@mcp.tool()
async def get_sensor(hostname: str) -> list[dict]:
    """Get LimaCharlie sensor detail by hostname."""
    return _render(await asyncio.to_thread(tools.get_sensor, _client(), hostname))


@mcp.tool()
async def list_dr_rules(namespace: str = "general", limit: int = 50) -> list[dict]:
    """List Detection & Response (D&R) rules in the org (coverage). namespace: general|managed."""
    return _render(await asyncio.to_thread(tools.list_dr_rules, _client(), namespace, limit))


@mcp.tool()
async def list_detections(
    hours_back: int = 24, limit: int = 50, category: str | None = None
) -> list[dict]:
    """List recent LimaCharlie detections (D&R hits) within the last hours_back hours."""
    return _render(
        await asyncio.to_thread(tools.list_detections, _client(), hours_back, limit, category)
    )


@mcp.tool()
async def query_telemetry(lcql: str, hours_back: int = 24, limit: int = 50) -> list[dict]:
    """Run a bounded LCQL endpoint-telemetry query over the last hours_back hours.

    Use for ANY "hunt / query telemetry" request. Construct an `lcql` query of the
    shape `time | sensor-selector | event-types | filter | projection`. Common
    event types: NEW_PROCESS (processes), DNS_REQUEST, NETWORK_CONNECTIONS.
    Example: `-24h | plat == windows | NEW_PROCESS | * | event/FILE_PATH`.
    """
    return _render(
        await asyncio.to_thread(tools.query_telemetry, _client(), lcql, hours_back, limit)
    )


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
