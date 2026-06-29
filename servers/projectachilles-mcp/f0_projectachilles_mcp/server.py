"""ProjectAchilles MCP server (stdio). Read-only tools over the PA REST API.

Findings are redacted before they leave the server.
"""
from __future__ import annotations

from dotenv import load_dotenv
from f0_sectools_core.auth.config import ProjectAchillesConfig
from f0_sectools_core.redaction.redact import redact_obj
from f0_sectools_core.schema.findings import Finding
from mcp.server.fastmcp import FastMCP

from . import tools
from .client import ProjectAchillesClient

load_dotenv(".env.projectachilles")

mcp = FastMCP("f0-projectachilles")


def _render(findings: list[Finding]) -> list[dict]:
    return [redact_obj(f.model_dump()) for f in findings]


def _client() -> ProjectAchillesClient:
    return ProjectAchillesClient(ProjectAchillesConfig.from_env())


@mcp.tool()
async def get_defense_score(days: int = 30) -> list[dict]:
    """CURRENT (point-in-time) ProjectAchilles defense score — how well controls
    block/detect simulated attacks right now. For change OVER TIME or whether it
    is improving, use get_defense_score_trend instead."""
    async with _client() as pa:
        return _render(await tools.get_defense_score(pa, days))


@mcp.tool()
async def get_defense_score_trend(days: int = 30, interval: str = "day") -> list[dict]:
    """Defense-score TREND over time — use for ANY question about whether posture
    is improving, declining, regressing, or its history/direction over a period.
    interval: day|hour."""
    async with _client() as pa:
        return _render(await tools.get_defense_score_trend(pa, days, interval))


@mcp.tool()
async def get_weak_techniques(days: int = 30, limit: int = 10) -> list[dict]:
    """Lowest-scoring MITRE techniques — where defenses most often fail."""
    async with _client() as pa:
        return _render(await tools.get_weak_techniques(pa, days, limit))


@mcp.tool()
async def list_test_executions(days: int = 7, limit: int = 25) -> list[dict]:
    """Recent test executions — which simulated attacks were blocked vs not, per host."""
    async with _client() as pa:
        return _render(await tools.list_test_executions(pa, days, limit))


@mcp.tool()
async def list_risk_acceptances(status: str = "active", limit: int = 50) -> list[dict]:
    """Risks deliberately accepted (not remediated). status: active|revoked."""
    async with _client() as pa:
        return _render(await tools.list_risk_acceptances(pa, status, limit))


@mcp.tool()
async def list_agents(
    status: str | None = None, online_only: bool = False, limit: int = 50
) -> list[dict]:
    """List ProjectAchilles test agents (endpoints): hostname, OS, status."""
    async with _client() as pa:
        return _render(await tools.list_agents(pa, status, online_only, limit))


@mcp.tool()
async def get_fleet_health() -> list[dict]:
    """Test-agent fleet health: online/offline counts and uptime."""
    async with _client() as pa:
        return _render(await tools.get_fleet_health(pa))


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
