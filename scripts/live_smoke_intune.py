"""Live smoke test for the Intune MCP server against a real tenant.

Usage (from the repo root):
    1. Copy servers/intune-mcp/.env.intune.example to ./.env.intune and fill in
       INTUNE_TENANT_ID / INTUNE_CLIENT_ID / INTUNE_CLIENT_SECRET (an Entra app with
       DeviceManagementManagedDevices.Read.All + DeviceManagementConfiguration.Read.All).
    2. uv run python scripts/live_smoke_intune.py

Calls each read tool against live Microsoft Graph and prints REDACTED findings.
Secrets are never printed. A missing permission/license shows up as a posture finding
(graceful degradation), not a crash.
"""
from __future__ import annotations

import asyncio
import json

from dotenv import load_dotenv
from f0_intune_mcp import tools
from f0_sectools_core.auth.config import PlatformConfig
from f0_sectools_core.auth.graph import GraphClient
from f0_sectools_core.redaction.redact import redact_obj

load_dotenv(".env.intune")


def _show(label: str, findings) -> None:
    print(f"\n=== {label}: {len(findings)} finding(s) ===")
    for f in findings[:8]:
        print(json.dumps(redact_obj(f.model_dump()), indent=2, default=str))
    if len(findings) > 8:
        print(f"... ({len(findings) - 8} more)")


async def main() -> None:
    cfg = PlatformConfig.from_env("INTUNE")
    print(f"Tenant {cfg.tenant_id[:8]}…  client {cfg.client_id[:8]}…  (secrets not shown)")
    async with GraphClient(cfg) as gc:
        _show("get_compliance_summary", await tools.get_compliance_summary(gc))
        _show("list_managed_devices", await tools.list_managed_devices(gc, limit=5))
        _show(
            "list_managed_devices(noncompliant)",
            await tools.list_managed_devices(gc, "noncompliant", 5),
        )
        _show("list_stale_devices", await tools.list_stale_devices(gc, days=30, limit=5))
        _show("list_compliance_policies", await tools.list_compliance_policies(gc, limit=5))
        _show("list_configuration_profiles", await tools.list_configuration_profiles(gc, limit=5))


if __name__ == "__main__":
    asyncio.run(main())
