"""Intune MCP server (stdio). Read-only tools over Microsoft Graph.

Loads credentials from the INTUNE_* environment (typically a `.env.intune` file),
opens a short-lived Graph client, maps results to findings, and redacts every payload
before returning it to the agent.
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

load_dotenv(".env.intune")

mcp = FastMCP("f0-intune")


def _render(findings: list[Finding]) -> list[dict[str, Any]]:
    return [redact_obj(f.model_dump()) for f in findings]


@mcp.tool()
async def list_managed_devices(compliance: str = "all", limit: int = 25) -> list[dict[str, Any]]:
    """List Intune-managed devices with compliance/encryption/owner/sync state.

    compliance: one of all|compliant|noncompliant|ingraceperiod|unknown. limit: max devices.
    """
    cfg = PlatformConfig.from_env("INTUNE")
    async with GraphClient(cfg) as gc:
        return _render(await tools.list_managed_devices(gc, compliance, limit))


@mcp.tool()
async def get_compliance_summary() -> list[dict[str, Any]]:
    """Intune device-compliance rollup: how many managed devices are compliant vs not."""
    cfg = PlatformConfig.from_env("INTUNE")
    async with GraphClient(cfg) as gc:
        return _render(await tools.get_compliance_summary(gc))


@mcp.tool()
async def get_managed_device(device_name: str) -> list[dict[str, Any]]:
    """Get one Intune-managed device by its device name (compliance, encryption, owner, sync)."""
    cfg = PlatformConfig.from_env("INTUNE")
    async with GraphClient(cfg) as gc:
        return _render(await tools.get_managed_device(gc, device_name))


@mcp.tool()
async def list_stale_devices(days: int = 30, limit: int = 25) -> list[dict[str, Any]]:
    """List Intune devices not synced in the last `days` (coverage drift / abandoned)."""
    cfg = PlatformConfig.from_env("INTUNE")
    async with GraphClient(cfg) as gc:
        return _render(await tools.list_stale_devices(gc, days, limit))


@mcp.tool()
async def list_compliance_policies(limit: int = 25) -> list[dict[str, Any]]:
    """List Intune device COMPLIANCE POLICIES.

    Rules that define whether a device is compliant.
    """
    cfg = PlatformConfig.from_env("INTUNE")
    async with GraphClient(cfg) as gc:
        return _render(await tools.list_compliance_policies(gc, limit))


@mcp.tool()
async def list_configuration_profiles(limit: int = 25) -> list[dict[str, Any]]:
    """List Intune device CONFIGURATION PROFILES.

    Settings pushed to devices (not the compliance rules).
    """
    cfg = PlatformConfig.from_env("INTUNE")
    async with GraphClient(cfg) as gc:
        return _render(await tools.list_configuration_profiles(gc, limit))


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
