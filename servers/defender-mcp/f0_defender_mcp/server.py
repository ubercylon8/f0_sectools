"""Defender MCP server (stdio). Read-only tools over Microsoft Graph.

Each tool loads credentials from the DEFENDER_* environment (typically a
`.env.defender` file), opens a short-lived Graph client, maps the result to
findings, and redacts every payload before returning it to the agent.
"""
from __future__ import annotations

from dotenv import load_dotenv
from f0_sectools_core.auth.config import PlatformConfig
from f0_sectools_core.auth.graph import GraphClient
from f0_sectools_core.redaction.redact import redact_obj
from f0_sectools_core.schema.findings import Finding
from mcp.server.fastmcp import FastMCP

from . import tools

# Load .env.defender from the working directory if present (no-op otherwise).
load_dotenv(".env.defender")

mcp = FastMCP("f0-defender")


def _render(findings: list[Finding]) -> list[dict]:
    """Dump findings and redact every payload before it leaves the server."""
    return [redact_obj(f.model_dump()) for f in findings]


@mcp.tool()
async def get_secure_score() -> list[dict]:
    """Get the current Microsoft Secure Score (overall security posture %)."""
    cfg = PlatformConfig.from_env("DEFENDER")
    async with GraphClient(cfg) as gc:
        return _render(await tools.get_secure_score(gc))


@mcp.tool()
async def list_incidents(severity_min: str = "medium", limit: int = 25) -> list[dict]:
    """List Defender XDR incidents (correlated alert groups).

    severity_min: one of info|low|medium|high|critical. limit: max incidents.
    """
    cfg = PlatformConfig.from_env("DEFENDER")
    async with GraphClient(cfg) as gc:
        return _render(await tools.list_incidents(gc, severity_min, limit))


@mcp.tool()
async def list_alerts(severity_min: str = "high", limit: int = 25) -> list[dict]:
    """List Defender XDR alerts (alerts_v2).

    severity_min: one of info|low|medium|high|critical. limit: max alerts.
    """
    cfg = PlatformConfig.from_env("DEFENDER")
    async with GraphClient(cfg) as gc:
        return _render(await tools.list_alerts(gc, severity_min, limit))


@mcp.tool()
async def run_hunting_query(kql: str) -> list[dict]:
    """Run a Microsoft Defender advanced hunting (KQL) query over the last 30 days."""
    cfg = PlatformConfig.from_env("DEFENDER")
    async with GraphClient(cfg) as gc:
        return _render(await tools.run_hunting_query(gc, kql))


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
