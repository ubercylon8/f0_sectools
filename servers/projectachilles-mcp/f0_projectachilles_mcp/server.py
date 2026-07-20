"""ProjectAchilles MCP server (stdio). Read-only tools over the PA REST API.

Findings are redacted before they leave the server.
"""
from __future__ import annotations

from typing import Any, Literal

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
async def list_test_executions(
    days: int = 7, limit: int = 25,
    test: str = "", tag: str = "", hostname: str = "",
) -> list[dict[str, Any]]:
    """Recent test executions per host. Two kinds (see the `check_kind` evidence):
    attack simulations — blocked vs NOT blocked; and cyber-hygiene control checks —
    passed vs not passed. Bundle runs roll up into one per-run COMPLIANT/NON-COMPLIANT
    finding (X/Y controls). Pass `test` (and/or `tag`/`hostname`) to scope results to
    ONE run instead of a raw time window (avoids unrelated hosts appearing)."""
    async with _client() as pa:
        return _render(await tools.list_test_executions(pa, days, limit, test, tag, hostname))


@mcp.tool()
async def list_risk_acceptances(
    status: Literal["active", "revoked"] = "active", limit: int = 50
) -> list[dict[str, Any]]:
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


@mcp.tool()
async def find_tests(
    by: Literal["technique", "actor", "tactic", "category", "tag", "keyword"],
    value: str,
    limit: int = 25,
) -> list[dict[str, Any]]:
    """Search the ProjectAchilles TEST CATALOG — the library of tests that CAN be run,
    not run history (use list_test_executions for history). by selects the dimension:
    technique|actor|tactic|category|tag|keyword. Returns a match count plus the matching
    tests (name, MITRE techniques, threat actor, OS, severity)."""
    async with _client() as pa:
        return _render(await tools.find_tests(pa, by, value, limit))


@mcp.tool()
async def get_test(test_id: str) -> list[dict[str, Any]]:
    """Full detail for ONE catalog test — description, OS/target, complexity, tactics,
    tags, MITRE techniques. test_id is a test uuid or an exact test name."""
    async with _client() as pa:
        return _render(await tools.get_test(pa, test_id))


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
