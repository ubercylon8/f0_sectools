"""Sentinel MCP server (stdio). Read-only tools over Microsoft Sentinel.

Loads credentials from the SENTINEL_* environment (typically `.env.sentinel`),
opens a short-lived client per call, maps results to findings, and redacts every
payload before returning it to the agent.
"""
from __future__ import annotations

from typing import Any, Literal

from dotenv import load_dotenv
from f0_sectools_core.auth.config import SentinelConfig
from f0_sectools_core.redaction.redact import redact_obj
from f0_sectools_core.schema.findings import Finding
from mcp.server import MCPServer

from . import tools
from .client import SentinelClient

load_dotenv(".env.sentinel")

mcp = MCPServer("f0-sentinel")


def _render(findings: list[Finding]) -> list[dict[str, Any]]:
    return [redact_obj(f.model_dump()) for f in findings]


def _client() -> SentinelClient:
    return SentinelClient(SentinelConfig.from_env("SENTINEL"))


@mcp.tool()
async def list_data_sources() -> list[dict[str, Any]]:
    """List which security telemetry this Sentinel workspace actually ingests.

    Start here when you do not know what data exists — every workspace is
    different. Returns each table with data in the last 30 days and a family
    label (firewall, dns_web, office, identity, incident, custom). Use it to
    pick which hunt tool can answer a question before you call one."""
    async with _client() as c:
        return _render(await tools.list_data_sources(c))


@mcp.tool()
async def hunt_firewall(
    action: Literal["allowed", "blocked", "detected", "any"] = "any",
    indicator: str = "",
    hours: float = 24,
    limit: int = 25,
) -> list[dict[str, Any]]:
    """SEARCH firewall traffic (Check Point / Fortinet) for an IP or port.

    Use for questions about network connections, blocked traffic, or a
    suspicious IP talking through the perimeter. `indicator` must be an IP
    ADDRESS or PORT NUMBER — this table carries almost no URLs or usernames, so
    a domain here finds nothing: for domains, URLs and web categories use
    hunt_dns_web instead. Without an indicator this returns an aggregate
    (top talkers by action), not individual events."""
    async with _client() as c:
        return _render(await tools.hunt_firewall(c, action, indicator, hours, limit))


@mcp.tool()
async def hunt_dns_web(
    surface: Literal["dns", "web", "vpn"] = "dns",
    action: Literal["allowed", "blocked", "detected", "any"] = "any",
    indicator: str = "",
    hours: float = 24,
    limit: int = 25,
) -> list[dict[str, Any]]:
    """SEARCH DNS, web-proxy, or remote-access VPN activity (Cisco Umbrella).

    Choose surface by what you are looking for: dns — a domain was resolved or
    blocked (C2, newly-registered domains, blocked categories); web — a URL was
    fetched, a file downloaded, or a proxy verdict applied; vpn — remote-access
    VPN sessions and failures. `indicator` is a domain, URL fragment or IP.
    Without an indicator this returns an aggregate, not individual events. For
    perimeter firewall connections by IP/port use hunt_firewall."""
    async with _client() as c:
        return _render(await tools.hunt_dns_web(c, surface, action, indicator, hours, limit))


@mcp.tool()
async def search_office_activity(
    workload: Literal["sharepoint", "onedrive", "exchange", "teams", "any"] = "any",
    operation: str = "",
    user: str = "",
    hours: float = 24,
    limit: int = 25,
) -> list[dict[str, Any]]:
    """Search Microsoft 365 audit activity: who accessed, downloaded, or shared what.

    Answers "who downloaded X", "who read that mailbox", "what did this user do
    in SharePoint". Call it FIRST without `operation` to get the list of
    operations that actually occurred, then again with an exact operation name
    (e.g. FileDownloaded, MailItemsAccessed, FileAccessed). This is the fast
    path for M365 audit — prefer it over f0-purview's search_audit_log, which
    submits an asynchronous query that takes 5-15 minutes to return."""
    async with _client() as c:
        return _render(
            await tools.search_office_activity(c, workload, operation, user, hours, limit)
        )


@mcp.tool()
async def list_sentinel_incidents(
    severity_min: Literal["informational", "low", "medium", "high"] = "low",
    status: Literal["new", "active", "closed", "any"] = "any",
    hours: float = 168,
    limit: int = 25,
) -> list[dict[str, Any]]:
    """List the Sentinel SOC incident queue with MITRE tactics, status and owner.

    Use when asked about the SOC queue, incident workload, unassigned incidents,
    or which ATT&CK tactics are showing up. This is the Sentinel-side view; for
    the Defender XDR-native incident view (with its own alert and device
    context) use f0-defender's list_incidents. Not an alert list — for
    individual alerts use f0-defender's list_alerts."""
    async with _client() as c:
        return _render(await tools.list_sentinel_incidents(c, severity_min, status, hours, limit))


@mcp.tool()
async def get_detection_coverage() -> list[dict[str, Any]]:
    """Report Sentinel's analytics-rule inventory and which MITRE tactics are UNCOVERED.

    Answers "what do we actually detect?", "where are our detection gaps?",
    "how many analytics rules are enabled?". Reports TWO coverage numbers, never
    conflated: tactics covered by ALL enabled rules (including Microsoft's
    built-in Fusion correlation rule) versus tactics covered by CUSTOM
    (operator-authored, non-Fusion) rules alone -- a workspace can show broad
    coverage overall while its own rules cover almost nothing, and that gap is
    the point of this tool. Requires the ARM coordinates in .env.sentinel;
    without them it says so."""
    async with _client() as c:
        return _render(await tools.get_detection_coverage(c))


@mcp.tool()
async def run_kql(kql: str, hours: float = 24, limit: int = 25) -> list[dict[str, Any]]:
    """Run a CUSTOM read-only KQL query against the Sentinel Log Analytics workspace.

    Use only when no guided tool fits — prefer hunt_firewall, hunt_dns_web,
    search_office_activity or list_sentinel_incidents, which build correct KQL
    for you. Call list_data_sources first to learn which tables exist in this
    workspace. This queries the SENTINEL workspace; for Microsoft Defender
    device/email advanced-hunting tables use f0-defender's run_hunting_query
    instead. The query is force-bounded if it carries no `take`."""
    async with _client() as c:
        return _render(await tools.run_kql(c, kql, hours, limit))


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
