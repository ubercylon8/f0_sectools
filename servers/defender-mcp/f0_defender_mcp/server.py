"""Defender MCP server (stdio). Read tools over Microsoft Graph, plus two
gated write actions (host isolate/release, disabled unless DEFENDER_ALLOW_WRITE
and human-confirmed).

Each tool loads credentials from the DEFENDER_* environment (typically a
`.env.defender` file), opens a short-lived Graph client, maps the result to
findings, and redacts every payload before returning it to the agent.
"""
from __future__ import annotations

import os
from typing import Any, Literal

from f0_sectools_core.auth.config import PlatformConfig
from f0_sectools_core.auth.env import load_platform_env
from f0_sectools_core.auth.graph import GraphClient
from f0_sectools_core.gating.actions import AuditLog, GatedAction, TokenStore
from f0_sectools_core.redaction.boundary import guarded_tool
from f0_sectools_core.redaction.redact import redact_finding
from f0_sectools_core.schema.findings import Finding
from mcp.server import MCPServer

from . import tools

# Locate .env.defender by searching upward from the working directory (no-op if absent).
load_platform_env("defender")

mcp = MCPServer("f0-defender")


def _render(findings: list[Finding]) -> list[dict[str, Any]]:
    """Dump findings and redact every payload before it leaves the server."""
    return [redact_finding(f).model_dump() for f in findings]


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
@guarded_tool("defender")
async def get_secure_score() -> list[dict[str, Any]]:
    """Get the Microsoft Secure Score — Microsoft 365 / Defender config-hardening posture (%).

    Microsoft tenant configuration only — not the LimaCharlie endpoint deployment
    (use get_org_overview) or the ProjectAchilles validation fleet (use get_fleet_health).
    """
    cfg = PlatformConfig.from_env("DEFENDER")
    async with GraphClient(cfg) as gc:
        return _render(await tools.get_secure_score(gc))


@mcp.tool()
@guarded_tool("defender")
async def list_incidents(
    severity_min: Literal["info", "low", "medium", "high", "critical"] = "medium",
    limit: int = 25,
    state: Literal["open", "all"] = "open",
) -> list[dict[str, Any]]:
    """List unresolved Defender XDR incidents (correlated alert groups), newest first.

    severity_min: one of info|low|medium|high|critical. limit: max incidents.
    Defaults to state="open" — excludes resolved incidents and ones redirected
    into another incident, which Defender retains indefinitely and which are
    already handled. Use state="all" for incident history.

    If a Sentinel workspace is configured, for the Sentinel SOC queue view of
    the same incidents — with MITRE tactics, SOC status and owner — use
    f0-sentinel's list_sentinel_incidents.
    """
    cfg = PlatformConfig.from_env("DEFENDER")
    async with GraphClient(cfg) as gc:
        return _render(await tools.list_incidents(gc, severity_min, limit, state))


@mcp.tool()
@guarded_tool("defender")
async def list_alerts(
    severity_min: Literal["info", "low", "medium", "high", "critical"] = "high",
    limit: int = 25,
    state: Literal["open", "all"] = "open",
) -> list[dict[str, Any]]:
    """List unresolved Defender XDR alerts (alerts_v2), newest first.

    severity_min: one of info|low|medium|high|critical. limit: max alerts.
    Defaults to state="open" — excludes resolved alerts, which are already
    handled and which dominate a mature tenant. Use state="all" for alert history.
    """
    cfg = PlatformConfig.from_env("DEFENDER")
    async with GraphClient(cfg) as gc:
        return _render(await tools.list_alerts(gc, severity_min, limit, state))


@mcp.tool()
@guarded_tool("defender")
async def run_hunting_query(kql: str) -> list[dict[str, Any]]:
    """Run a Microsoft Defender advanced hunting query (KQL) — a READ-ONLY search of
    M365 / Entra / device telemetry (30d).

    This only reads. To contain or reconnect a device use isolate_host /
    release_host; this tool never changes a device's state.
    For LimaCharlie endpoint (EDR sensor) telemetry, use query_telemetry instead —
    this tool is Microsoft/Defender + KQL only. Construct a `kql` query string.
    For common hunts prefer the `hunt` tool (it builds the KQL for you); use this
    only for a CUSTOM KQL query you provide. Key tables & fields: DeviceNetworkEvents
    (Timestamp, RemoteUrl, RemoteIP, RemotePort), DeviceProcessEvents (Timestamp,
    DeviceName, FileName, ProcessCommandLine, AccountName), DeviceLogonEvents
    (Timestamp, ActionType, AccountName, DeviceName), EmailEvents (Timestamp,
    SenderFromAddress, Subject, ThreatTypes). Always bound results with `| take 50`.

    This is Defender advanced hunting (device, email and identity tables), not
    Sentinel workspace KQL. If a Sentinel workspace is configured, for
    firewall, DNS, syslog or other Log Analytics tables use f0-sentinel's
    run_kql.
    """
    cfg = PlatformConfig.from_env("DEFENDER")
    async with GraphClient(cfg) as gc:
        return _render(await tools.run_hunting_query(gc, kql))


@mcp.tool()
@guarded_tool("defender")
async def hunt(
    category: Literal["network", "process", "logon", "email"],
    indicator: str = "",
    time_window_hours: int = 24,
) -> list[dict[str, Any]]:
    """SEARCH raw Defender telemetry for suspicious activity — the server writes the KQL.

    Searches the raw event tables, NOT the alerts Defender already raised (for
    those use list_alerts). Choose the category by what you are looking for:
      logon   — failed sign-ins, sign-in failures, brute force, password spray
      network — traffic to a domain or IP
      process — a process name or command line
      email   — phishing or malware-bearing mail

    indicator: REQUIRED for network (the domain or IP to match) and REQUIRED for
    process (the process name or command-line fragment to match) — name the thing
    the user asked about. Only logon and email take no indicator; they sweep on
    their own. Prefer this over run_hunting_query unless the user gives you
    custom KQL.
    """
    cfg = PlatformConfig.from_env("DEFENDER")
    async with GraphClient(cfg) as gc:
        return _render(await tools.hunt(gc, category, indicator, time_window_hours))


@mcp.tool()
@guarded_tool("defender")
async def isolate_host(
    device_id: str, comment: str, confirmation_token: str = ""
) -> list[dict[str, Any]]:
    """CONTAIN a device: cut it off the network so it cannot communicate (GATED WRITE).

    Use when asked to isolate, contain, quarantine, cut off, or take a host
    offline — e.g. "isolate dev-1, I think it's compromised". This ACTS on the
    device; it does not search or investigate. For telemetry use `hunt` or
    `run_hunting_query`.

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
@guarded_tool("defender")
async def release_host(
    device_id: str, comment: str, confirmation_token: str = ""
) -> list[dict[str, Any]]:
    """RECONNECT a device: undo isolation so it can reach the network again (GATED WRITE).

    Use when asked to release, un-isolate, restore, reconnect, or take a host back
    out of isolation — e.g. "release dev-1, it's been cleaned". This ACTS on the
    device; it does not search or investigate.

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
