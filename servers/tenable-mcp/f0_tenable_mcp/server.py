"""Tenable MCP server (stdio). Read-only tools over the Tenable VM Workbenches API.

Findings are redacted before they leave the server.
"""
from __future__ import annotations

from typing import Any

from dotenv import load_dotenv
from f0_sectools_core.auth.config import TenableConfig
from f0_sectools_core.redaction.redact import redact_obj
from f0_sectools_core.schema.findings import Finding
from mcp.server.fastmcp import FastMCP

from . import tools
from .client import TenableClient

load_dotenv(".env.tenable")

mcp = FastMCP("f0-tenable")


def _render(findings: list[Finding]) -> list[dict[str, Any]]:
    return [redact_obj(f.model_dump()) for f in findings]


def _client() -> TenableClient:
    return TenableClient(TenableConfig.from_env())


@mcp.tool()
async def get_vulnerability_summary() -> list[dict[str, Any]]:
    """Tenable environment-wide vulnerability posture — counts by severity.

    Use for "what's our exposure / overall vulnerability posture" questions.
    Returns one posture finding with per-severity instance counts.
    """
    async with _client() as tio:
        return _render(await tools.get_vulnerability_summary(tio))


@mcp.tool()
async def list_top_vulnerabilities(
    severity_min: str = "high", limit: int = 10
) -> list[dict[str, Any]]:
    """Tenable worst vulnerabilities to fix first — ranked by severity then VPR.

    severity_min: low|medium|high|critical (default high). Use for
    "what should we patch first / top risks" questions.
    """
    async with _client() as tio:
        return _render(await tools.list_top_vulnerabilities(tio, severity_min, limit))


@mcp.tool()
async def list_assets(hostname: str = "", limit: int = 25) -> list[dict[str, Any]]:
    """Tenable asset inventory — hosts Tenable has scanned.

    Optional hostname substring filter. Use to find or enumerate assets; for a
    specific host's vulnerabilities use get_asset_vulnerabilities.
    """
    async with _client() as tio:
        return _render(await tools.list_assets(tio, hostname, limit))


@mcp.tool()
async def get_asset_vulnerabilities(
    asset: str, severity_min: str = "high", limit: int = 25
) -> list[dict[str, Any]]:
    """Tenable vulnerabilities on ONE host. `asset` is a hostname, IP, or asset UUID.

    Use for "what's wrong with host X / vulnerabilities on X". severity_min:
    low|medium|high|critical (default high).
    """
    async with _client() as tio:
        return _render(
            await tools.get_asset_vulnerabilities(tio, asset, severity_min, limit))


@mcp.tool()
async def get_vulnerability_info(plugin_id: str) -> list[dict[str, Any]]:
    """Tenable detail for one plugin/vulnerability: CVSS, VPR, description, remediation.

    Use to explain a specific Tenable plugin id or get its fix.
    """
    async with _client() as tio:
        return _render(await tools.get_vulnerability_info(tio, plugin_id))


@mcp.tool()
async def list_scans(limit: int = 25) -> list[dict[str, Any]]:
    """Tenable scan inventory — each scan's status and last-run time (coverage freshness)."""
    async with _client() as tio:
        return _render(await tools.list_scans(tio, limit))


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
