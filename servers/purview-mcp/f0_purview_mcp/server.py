"""Purview MCP server (stdio). Read-only data-risk tools over Microsoft Graph.

Loads credentials from the PURVIEW_* environment (typically `.env.purview`),
opens a short-lived Graph client per call, maps results to findings, and
redacts every payload before returning it to the agent.
"""
from __future__ import annotations

from typing import Any, Literal

from dotenv import load_dotenv
from f0_sectools_core.auth.config import PlatformConfig
from f0_sectools_core.auth.graph import GraphClient
from f0_sectools_core.redaction.redact import redact_obj
from f0_sectools_core.schema.findings import Finding
from mcp.server.fastmcp import FastMCP

from . import tools

load_dotenv(".env.purview")

mcp = FastMCP("f0-purview")


def _render(findings: list[Finding]) -> list[dict[str, Any]]:
    return [redact_obj(f.model_dump()) for f in findings]


def _client() -> GraphClient:
    return GraphClient(PlatformConfig.from_env("PURVIEW"))


@mcp.tool()
async def get_dlp_summary(hours_back: float = 168) -> list[dict[str, Any]]:
    """Purview data-loss (DLP) alert rollup: counts by severity and status.

    The data-risk posture headline — not Defender incidents (use list_incidents)
    or Secure Score (use get_secure_score). hours_back may be fractional."""
    async with _client() as gc:
        return _render(await tools.get_dlp_summary(gc, hours_back))


@mcp.tool()
async def list_dlp_alerts(
    hours_back: float = 168,
    severity_min: Literal["low", "medium", "high"] = "low",
    limit: int = 25,
) -> list[dict[str, Any]]:
    """List recent Purview DLP alerts (data-loss policy matches), bounded.

    severity_min filters to that severity and above."""
    async with _client() as gc:
        return _render(await tools.list_dlp_alerts(gc, hours_back, severity_min, limit))


@mcp.tool()
async def list_insider_risk_alerts(
    hours_back: float = 168, limit: int = 25
) -> list[dict[str, Any]]:
    """List recent Purview Insider Risk Management alerts (potential data theft,
    leaks, risky departing users). Users may appear pseudonymized by design."""
    async with _client() as gc:
        return _render(await tools.list_insider_risk_alerts(gc, hours_back, limit))


@mcp.tool()
async def list_sensitivity_labels() -> list[dict[str, Any]]:
    """List the organization's Purview sensitivity labels (classification
    inventory) — answers whether data classification is actually deployed."""
    async with _client() as gc:
        return _render(await tools.list_sensitivity_labels(gc))


@mcp.tool()
async def search_audit_log(
    activity: str = "",
    user: str = "",
    hours_back: float = 24,
    limit: int = 25,
) -> list[dict[str, Any]]:
    """Search the Microsoft 365 unified audit log: who did what, when.

    Optional flat filters: activity (an EXACT operation name like "FileDeleted",
    "FileDownloaded", "MailItemsAccessed" — when unsure, search once with no
    activity filter and read the operation names that return) and user (a UPN).
    The search is asynchronous and typically takes 5-15 MINUTES: this call polls
    briefly, then returns an audit_query_id — fetch later with
    get_audit_results. NEVER resubmit the same search while one is running
    (identical resubmissions are deduplicated to the in-flight query)."""
    async with _client() as gc:
        return _render(await tools.search_audit_log(gc, activity, user, hours_back, limit))


@mcp.tool()
async def get_audit_results(audit_query_id: str, limit: int = 25) -> list[dict[str, Any]]:
    """Fetch the results of a previously submitted audit search (the
    audit_query_id returned by search_audit_log when it was still running).

    May pause briefly (~15s) polling the query before returning; if it is still
    not ready, returns a 'still running' finding — wait a few minutes and call
    this ONCE more, do not loop on it."""
    async with _client() as gc:
        return _render(await tools.get_audit_results(gc, audit_query_id, limit))


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
