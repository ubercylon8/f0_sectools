"""Live smoke test for the Entra MCP server against a real tenant.

Usage (from the repo root):
    1. Copy servers/entra-mcp/.env.entra.example to ./.env.entra and fill in
       ENTRA_TENANT_ID / ENTRA_CLIENT_ID / ENTRA_CLIENT_SECRET.
    2. uv run python scripts/live_smoke_entra.py

Calls each read tool against live Microsoft Graph and prints REDACTED findings.
Secrets are never printed. A missing permission/license shows up as a posture
finding (graceful degradation), not a crash.
"""
from __future__ import annotations

import asyncio
import json

from dotenv import load_dotenv
from f0_entra_mcp import tools
from f0_sectools_core.auth.config import PlatformConfig
from f0_sectools_core.auth.graph import GraphClient
from f0_sectools_core.redaction.redact import redact_obj

load_dotenv(".env.entra")


def _show(label: str, findings) -> None:
    print(f"\n=== {label}: {len(findings)} finding(s) ===")
    for f in findings[:10]:  # cap console output
        print(json.dumps(redact_obj(f.model_dump()), indent=2, default=str))
    if len(findings) > 10:
        print(f"... ({len(findings) - 10} more)")


async def main() -> None:
    cfg = PlatformConfig.from_env("ENTRA")  # raises clearly if creds missing
    print(f"Tenant {cfg.tenant_id[:8]}…  client {cfg.client_id[:8]}…  (secrets not shown)")
    async with GraphClient(cfg) as gc:
        for label, coro in [
            ("list_risky_users", tools.list_risky_users(gc, limit=5)),
            ("list_risk_detections", tools.list_risk_detections(gc, limit=5)),
            ("list_conditional_access_policies", tools.list_conditional_access_policies(gc)),
            (
                "list_privileged_role_assignments",
                tools.list_privileged_role_assignments(gc, limit=25),
            ),
        ]:
            try:
                _show(label, await coro)
            except Exception as e:  # noqa: BLE001 — smoke test: report and continue
                print(f"\n=== {label}: ERROR ===\n{type(e).__name__}: {e}")


if __name__ == "__main__":
    asyncio.run(main())
