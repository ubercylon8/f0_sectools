"""ProjectAchilles MCP server (stdio). Read-only tools over the PA REST API.

Findings are redacted before they leave the server.
"""
from __future__ import annotations

from typing import Any

from dotenv import load_dotenv
from f0_sectools_core.auth.config import ProjectAchillesConfig
from f0_sectools_core.redaction.redact import redact_obj
from f0_sectools_core.schema.findings import Finding
from mcp.server.fastmcp import FastMCP

from . import tools
from .client import ProjectAchillesClient

load_dotenv(".env.projectachilles")

mcp = FastMCP("f0-projectachilles")


def _render(findings: list[Finding]) -> list[dict[str, Any]]:
    return [redact_obj(f.model_dump()) for f in findings]


def _client() -> ProjectAchillesClient:
    return ProjectAchillesClient(ProjectAchillesConfig.from_env())


@mcp.tool()
async def get_defense_score(
    days: int = 30, over_time: bool = False, interval: str = "day"
) -> list[dict[str, Any]]:
    """ProjectAchilles defense score — how well controls block/detect simulated attacks.

    over_time=false (default) returns the CURRENT score (a snapshot). over_time=true
    returns the TREND over the period — use it for any "improving", "declining",
    "over time", or "history" question. interval (day|hour) applies only to the trend.
    """
    async with _client() as pa:
        if over_time:
            return _render(await tools.get_defense_score_trend(pa, days, interval))
        return _render(await tools.get_defense_score(pa, days))


@mcp.tool()
async def get_weak_techniques(days: int = 30, limit: int = 10) -> list[dict[str, Any]]:
    """Lowest-scoring MITRE techniques — where defenses most often fail."""
    async with _client() as pa:
        return _render(await tools.get_weak_techniques(pa, days, limit))


@mcp.tool()
async def list_test_executions(days: int = 7, limit: int = 25) -> list[dict[str, Any]]:
    """Recent test executions — which simulated attacks were blocked vs not, per host."""
    async with _client() as pa:
        return _render(await tools.list_test_executions(pa, days, limit))


@mcp.tool()
async def list_risk_acceptances(status: str = "active", limit: int = 50) -> list[dict[str, Any]]:
    """Risks deliberately accepted (not remediated). status: active|revoked."""
    async with _client() as pa:
        return _render(await tools.list_risk_acceptances(pa, status, limit))


@mcp.tool()
async def list_agents(
    status: str | None = None, online_only: bool = False, limit: int = 50
) -> list[dict[str, Any]]:
    """List ProjectAchilles test agents (endpoints): hostname, OS, status."""
    async with _client() as pa:
        return _render(await tools.list_agents(pa, status, online_only, limit))


@mcp.tool()
async def get_fleet_health() -> list[dict[str, Any]]:
    """ProjectAchilles validation-agent fleet health: attack-simulation agents online/offline.

    The ProjectAchilles breach-&-attack-simulation validation fleet — not LimaCharlie
    endpoint sensors (use get_org_overview) or Microsoft tenant posture (use get_secure_score).
    """
    async with _client() as pa:
        return _render(await tools.get_fleet_health(pa))


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
