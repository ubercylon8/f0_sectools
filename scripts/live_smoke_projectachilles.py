"""Live smoke test for the ProjectAchilles MCP server against a real instance.

Usage (from the repo root):
    1. Copy servers/projectachilles-mcp/.env.projectachilles.example to
       ./.env.projectachilles and fill in PROJECTACHILLES_BASE_URL and a read-scope
       PROJECTACHILLES_API_KEY (pa_...).
    2. uv run python scripts/live_smoke_projectachilles.py

Calls each read tool against live ProjectAchilles and prints REDACTED findings.
Secrets are never printed. Auth / permission / rate-limit issues show up as
posture findings (graceful degradation), not crashes.
"""
from __future__ import annotations

import asyncio
import json

from dotenv import load_dotenv
from f0_projectachilles_mcp import tools
from f0_projectachilles_mcp.client import ProjectAchillesClient
from f0_sectools_core.auth.config import ProjectAchillesConfig
from f0_sectools_core.redaction.redact import redact_obj

load_dotenv(".env.projectachilles")


def _show(label: str, findings) -> None:
    print(f"\n=== {label}: {len(findings)} finding(s) ===")
    for f in findings[:8]:
        print(json.dumps(redact_obj(f.model_dump()), indent=2, default=str))
    if len(findings) > 8:
        print(f"... ({len(findings) - 8} more)")


async def main() -> None:
    cfg = ProjectAchillesConfig.from_env()  # raises clearly if creds missing
    print(f"Instance {cfg.base_url}  (api key not shown)")
    async with ProjectAchillesClient(cfg) as pa:
        for label, coro in [
            ("get_defense_score", tools.get_defense_score(pa, days=90)),
            ("get_defense_score_trend", tools.get_defense_score_trend(pa, days=90)),
            ("get_weak_techniques", tools.get_weak_techniques(pa, days=90, limit=5)),
            ("list_test_executions", tools.list_test_executions(pa, days=30, limit=5)),
            ("list_risk_acceptances", tools.list_risk_acceptances(pa, limit=5)),
            ("list_agents", tools.list_agents(pa, limit=5)),
            ("get_fleet_health", tools.get_fleet_health(pa)),
        ]:
            try:
                _show(label, await coro)
            except Exception as e:  # noqa: BLE001 — smoke test: report and continue
                print(f"\n=== {label}: ERROR ===\n{type(e).__name__}: {e}")


if __name__ == "__main__":
    asyncio.run(main())
