"""LimaCharlie MCP server (stdio). Read-only tools over the limacharlie SDK.

The SDK is synchronous, so each tool runs in a worker thread to avoid blocking
the event loop. Findings are redacted before they leave the server.
"""
from __future__ import annotations

import asyncio
from typing import Any, Literal

from dotenv import load_dotenv
from f0_sectools_core.auth.config import LimaCharlieConfig
from f0_sectools_core.redaction.redact import redact_obj
from f0_sectools_core.schema.findings import Finding
from mcp.server.fastmcp import FastMCP

from . import tools
from .client import LimaCharlieClient

load_dotenv(".env.limacharlie")

mcp = FastMCP("f0-limacharlie")


def _render(findings: list[Finding]) -> list[dict[str, Any]]:
    return [redact_obj(f.model_dump()) for f in findings]


def _client() -> LimaCharlieClient:
    return LimaCharlieClient(LimaCharlieConfig.from_env())


@mcp.tool()
async def get_org_overview() -> list[dict[str, Any]]:
    """LimaCharlie EDR deployment posture: sensor counts, D&R rule count, recent detection volume.

    The LimaCharlie endpoint/detection deployment — not Microsoft tenant config
    (use get_secure_score) or the ProjectAchilles validation fleet (use get_fleet_health).
    """
    return _render(await asyncio.to_thread(tools.get_org_overview, _client()))


@mcp.tool()
async def list_sensors(online_only: bool = False, limit: int = 50) -> list[dict[str, Any]]:
    """List LimaCharlie sensors (endpoints): hostname, platform, online status."""
    return _render(await asyncio.to_thread(tools.list_sensors, _client(), online_only, limit))


@mcp.tool()
async def get_sensor(hostname: str) -> list[dict[str, Any]]:
    """Get LimaCharlie sensor detail by hostname (prefix match): platform, online status, sid."""
    return _render(await asyncio.to_thread(tools.get_sensor, _client(), hostname))


@mcp.tool()
async def list_dr_rules(namespace: str = "general", limit: int = 50) -> list[dict[str, Any]]:
    """List Detection & Response (D&R) rules in the org (coverage). namespace: general|managed."""
    return _render(await asyncio.to_thread(tools.list_dr_rules, _client(), namespace, limit))


@mcp.tool()
async def list_detections(
    hours_back: float = 24, limit: int = 50, category: str | None = None
) -> list[dict[str, Any]]:
    """List recent LimaCharlie detections (D&R hits) within the last hours_back hours.

    hours_back may be fractional for short windows (e.g. 0.25 = last 15 minutes)."""
    return _render(
        await asyncio.to_thread(tools.list_detections, _client(), hours_back, limit, category)
    )


@mcp.tool()
async def query_telemetry(
    hunt: Literal[
        "new_processes", "powershell_activity", "dns_requests", "network_connections"
    ] = "new_processes",
    hours_back: float = 24,
    limit: int = 50,
    hostname: str | None = None,
    domain: str | None = None,
    lcql: str | None = None,
) -> list[dict[str, Any]]:
    """Hunt LimaCharlie endpoint (EDR sensor) telemetry with a guided preset — no LCQL needed.

    For Microsoft Defender / KQL hunts, use run_hunting_query instead — this tool
    is LimaCharlie sensor telemetry only. Pick a `hunt` preset: new_processes,
    powershell_activity, dns_requests, or network_connections. hours_back bounds the
    window and may be fractional (0.25 = last 15 minutes). Set `hostname` to scope to
    ONE sensor (e.g. "top processes on host X"). Set `domain` to check whether a host
    resolved a domain (e.g. "does host X connect to microsoft.com") — it routes to DNS
    lookups filtered by that domain (NETWORK_CONNECTIONS has IPs, not domains). The
    domain filter is a SUBSTRING match, so the summary flags that lookalike domains
    (microsoft.com.evil.net) can also match — confirm the returned domains are real.
    Returns a count plus one finding per event. Advanced: pass a raw `lcql` query to
    override the preset (shape: time | sensor-selector | event-types | filter | projection).
    """
    return _render(
        await asyncio.to_thread(
            tools.query_telemetry, _client(), hunt, hours_back, limit, hostname, domain, lcql
        )
    )


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
