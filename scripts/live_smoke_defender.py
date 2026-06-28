"""Live smoke test for the Defender MCP server against a real tenant.

Usage (from the repo root):
    1. Copy servers/defender-mcp/.env.defender.example to ./.env.defender
       and fill in DEFENDER_TENANT_ID / DEFENDER_CLIENT_ID / DEFENDER_CLIENT_SECRET.
    2. uv run python scripts/live_smoke_defender.py

This calls each read tool against live Microsoft Graph and prints REDACTED
findings. Secrets are never printed. A missing permission/license shows up as a
posture finding (graceful degradation), not a crash.
"""
from __future__ import annotations

import asyncio
import json

from dotenv import load_dotenv
from f0_defender_mcp import tools
from f0_sectools_core.auth.config import PlatformConfig
from f0_sectools_core.auth.graph import GraphClient
from f0_sectools_core.redaction.redact import redact_obj

load_dotenv(".env.defender")

# A harmless, bounded hunting query to validate ThreatHunting.Read.All.
SMOKE_KQL = "DeviceInfo | take 1"


def _show(label: str, findings) -> None:
    print(f"\n=== {label}: {len(findings)} finding(s) ===")
    for f in findings:
        redacted = redact_obj(f.model_dump())
        print(json.dumps(redacted, indent=2, default=str))


async def main() -> None:
    cfg = PlatformConfig.from_env("DEFENDER")  # raises clearly if creds missing
    print(f"Tenant {cfg.tenant_id[:8]}…  client {cfg.client_id[:8]}…  (secrets not shown)")
    async with GraphClient(cfg) as gc:
        for label, coro in [
            ("get_secure_score", tools.get_secure_score(gc)),
            ("list_incidents", tools.list_incidents(gc, severity_min="low", limit=5)),
            ("list_alerts", tools.list_alerts(gc, severity_min="low", limit=5)),
            ("run_hunting_query", tools.run_hunting_query(gc, SMOKE_KQL)),
        ]:
            try:
                _show(label, await coro)
            except Exception as e:  # noqa: BLE001 — smoke test: report and continue
                print(f"\n=== {label}: ERROR ===\n{type(e).__name__}: {e}")


if __name__ == "__main__":
    asyncio.run(main())
