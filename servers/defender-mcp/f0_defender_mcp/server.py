"""Defender MCP server (stdio). Read-only tools over Microsoft Graph.

Each tool loads credentials from the DEFENDER_* environment (typically a
`.env.defender` file), opens a short-lived Graph client, maps the result to
findings, and redacts every payload before returning it to the agent.
"""
from __future__ import annotations

import os
from typing import Any

from dotenv import load_dotenv
from f0_sectools_core.auth.config import PlatformConfig
from f0_sectools_core.auth.graph import GraphClient
from f0_sectools_core.gating.actions import AuditLog, GatedAction, TokenStore
from f0_sectools_core.redaction.redact import redact_obj
from f0_sectools_core.schema.findings import Finding
from mcp.server.fastmcp import FastMCP

from . import tools

# Load .env.defender from the working directory if present (no-op otherwise).
load_dotenv(".env.defender")

mcp = FastMCP("f0-defender")


def _render(findings: list[Finding]) -> list[dict[str, Any]]:
    """Dump findings and redact every payload before it leaves the server."""
    return [redact_obj(f.model_dump()) for f in findings]


_SECURITY_BASE = "https://api.security.microsoft.com/api"
_SECURITY_SCOPE = "https://api.security.microsoft.com/.default"


def _sec_client(cfg: PlatformConfig) -> GraphClient:
    return GraphClient(cfg, base_url=_SECURITY_BASE, scope=_SECURITY_SCOPE)


def _gate(name: str, cfg: PlatformConfig) -> GatedAction:
    return GatedAction(
        name,
        enabled=cfg.allow_write,
        audit=AuditLog(os.environ.get("DEFENDER_AUDIT_LOG_PATH") or None),
        token_store=TokenStore(),
    )


_ACTOR = os.environ.get("DEFENDER_AUDIT_ACTOR", "mcp-operator")


@mcp.tool()
async def get_secure_score() -> list[dict[str, Any]]:
    """Get the Microsoft Secure Score — Microsoft 365 / Defender config-hardening posture (%).

    Microsoft tenant configuration only — not the LimaCharlie endpoint deployment
    (use get_org_overview) or the ProjectAchilles validation fleet (use get_fleet_health).
    """
    cfg = PlatformConfig.from_env("DEFENDER")
    async with GraphClient(cfg) as gc:
        return _render(await tools.get_secure_score(gc))


@mcp.tool()
async def list_incidents(severity_min: str = "medium", limit: int = 25) -> list[dict[str, Any]]:
    """List Defender XDR incidents (correlated alert groups).

    severity_min: one of info|low|medium|high|critical. limit: max incidents.
    """
    cfg = PlatformConfig.from_env("DEFENDER")
    async with GraphClient(cfg) as gc:
        return _render(await tools.list_incidents(gc, severity_min, limit))


@mcp.tool()
async def list_alerts(severity_min: str = "high", limit: int = 25) -> list[dict[str, Any]]:
    """List Defender XDR alerts (alerts_v2).

    severity_min: one of info|low|medium|high|critical. limit: max alerts.
    """
    cfg = PlatformConfig.from_env("DEFENDER")
    async with GraphClient(cfg) as gc:
        return _render(await tools.list_alerts(gc, severity_min, limit))


@mcp.tool()
async def run_hunting_query(kql: str) -> list[dict[str, Any]]:
    """Run a Microsoft Defender advanced hunting query (KQL) over M365 / Entra / devices (30d).

    For LimaCharlie endpoint (EDR sensor) telemetry, use query_telemetry instead —
    this tool is Microsoft/Defender + KQL only. Construct a `kql` query string.
    For common hunts prefer the `hunt` tool (it builds the KQL for you); use this
    only for a CUSTOM KQL query you provide. Key tables & fields: DeviceNetworkEvents
    (Timestamp, RemoteUrl, RemoteIP, RemotePort), DeviceProcessEvents (Timestamp,
    DeviceName, FileName, ProcessCommandLine, AccountName), DeviceLogonEvents
    (Timestamp, ActionType, AccountName, DeviceName), EmailEvents (Timestamp,
    SenderFromAddress, Subject, ThreatTypes). Always bound results with `| take 50`.
    """
    cfg = PlatformConfig.from_env("DEFENDER")
    async with GraphClient(cfg) as gc:
        return _render(await tools.run_hunting_query(gc, kql))


@mcp.tool()
async def hunt(
    category: str, indicator: str = "", time_window_hours: int = 24
) -> list[dict[str, Any]]:
    """Guided Microsoft Defender hunt — the server builds correct KQL, so you don't have to.

    category: network | process | logon | email.
    indicator: what to look for — a domain/IP (network), a process name or
    command-line fragment (process); optional for logon/email. Prefer this over
    run_hunting_query unless the user gives you custom KQL.
    """
    cfg = PlatformConfig.from_env("DEFENDER")
    async with GraphClient(cfg) as gc:
        return _render(await tools.hunt(gc, category, indicator, time_window_hours))


@mcp.tool()
async def isolate_host(
    device_id: str, comment: str, confirmation_token: str = ""
) -> list[dict[str, Any]]:
    """Isolate a device from the network (GATED WRITE).

    Call WITHOUT confirmation_token first: returns the intended action only. An
    operator then approves it in `confirm_action.py --watch` and you call again
    with the SAME arguments — or supplies a token from confirm_action.py as
    confirmation_token. Requires DEFENDER_ALLOW_WRITE=true.
    """
    cfg = PlatformConfig.from_env("DEFENDER")
    async with _sec_client(cfg) as sec:
        return _render(
            await tools.isolate_host(
                sec, _gate("defender.isolate_host", cfg), device_id, comment,
                confirmation_token, _ACTOR,
            )
        )


@mcp.tool()
async def release_host(
    device_id: str, comment: str, confirmation_token: str = ""
) -> list[dict[str, Any]]:
    """Release a device from isolation (GATED WRITE).

    Same two-step flow as isolate_host: call without confirmation_token to
    preview, then either an operator approves it in `confirm_action.py --watch`
    and you call again with the SAME arguments, or supply a token from
    confirm_action.py as confirmation_token.
    """
    cfg = PlatformConfig.from_env("DEFENDER")
    async with _sec_client(cfg) as sec:
        return _render(
            await tools.release_host(
                sec, _gate("defender.release_host", cfg), device_id, comment,
                confirmation_token, _ACTOR,
            )
        )


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
