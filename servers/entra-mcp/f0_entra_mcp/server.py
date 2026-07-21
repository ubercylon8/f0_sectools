"""Entra ID MCP server (stdio). Read-only tools over Microsoft Graph.

Each tool loads credentials from the ENTRA_* environment (typically a
`.env.entra` file), opens a short-lived Graph client, maps the result to
findings, and redacts every payload before returning it to the agent.
"""
from __future__ import annotations

from typing import Any

from dotenv import load_dotenv
from f0_sectools_core.auth.config import PlatformConfig
from f0_sectools_core.auth.graph import GraphClient
from f0_sectools_core.redaction.redact import redact_obj
from f0_sectools_core.schema.findings import Finding
from mcp.server.fastmcp import FastMCP

from . import tools

# Load .env.entra from the working directory if present (no-op otherwise).
load_dotenv(".env.entra")

mcp = FastMCP("f0-entra")


def _render(findings: list[Finding]) -> list[dict[str, Any]]:
    """Dump findings and redact every payload before it leaves the server."""
    return [redact_obj(f.model_dump()) for f in findings]


@mcp.tool()
async def list_risky_users(limit: int = 25) -> list[dict[str, Any]]:
    """List Entra ID Protection risky users (requires Entra ID P2)."""
    cfg = PlatformConfig.from_env("ENTRA")
    async with GraphClient(cfg) as gc:
        return _render(await tools.list_risky_users(gc, limit))


@mcp.tool()
async def list_risk_detections(limit: int = 25) -> list[dict[str, Any]]:
    """List Entra ID Protection risk detections (requires Entra ID P2)."""
    cfg = PlatformConfig.from_env("ENTRA")
    async with GraphClient(cfg) as gc:
        return _render(await tools.list_risk_detections(gc, limit))


@mcp.tool()
async def list_conditional_access_policies() -> list[dict[str, Any]]:
    """List Conditional Access policies, flagging disabled and report-only ones."""
    cfg = PlatformConfig.from_env("ENTRA")
    async with GraphClient(cfg) as gc:
        return _render(await tools.list_conditional_access_policies(gc))


@mcp.tool()
async def list_privileged_role_assignments(limit: int = 25) -> list[dict[str, Any]]:
    """List directory role assignments, highlighting critical privileged roles.

    Critical roles first; returns one bounded page with a "more available" note.
    """
    cfg = PlatformConfig.from_env("ENTRA")
    async with GraphClient(cfg) as gc:
        return _render(await tools.list_privileged_role_assignments(gc, limit))


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
