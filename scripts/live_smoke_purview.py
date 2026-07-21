"""Live smoke test for the Purview MCP server against a real tenant.

Usage (from the repo root):
    1. Copy servers/purview-mcp/.env.purview.example to ./.env.purview and fill
       in PURVIEW_TENANT_ID / PURVIEW_CLIENT_ID / PURVIEW_CLIENT_SECRET.
       Required app permissions: SecurityAlert.Read.All, AuditLogsQuery.Read.All,
       InformationProtectionPolicy.Read.All (labels, Graph beta).
    2. uv run python scripts/live_smoke_purview.py

Read-only. Missing permission / licensing shows up as a posture finding
(graceful degradation), not a crash. Secrets are never printed.
"""
from __future__ import annotations

import asyncio
import json

from dotenv import load_dotenv
from f0_purview_mcp import tools
from f0_sectools_core.auth.config import PlatformConfig
from f0_sectools_core.auth.graph import GraphClient
from f0_sectools_core.redaction.redact import redact_obj

load_dotenv(".env.purview")


def _show(label: str, findings) -> None:
    print(f"\n=== {label}: {len(findings)} finding(s) ===")
    for f in findings[:6]:
        print(json.dumps(redact_obj(f.model_dump()), indent=2, default=str))
    if len(findings) > 6:
        print(f"... ({len(findings) - 6} more)")


async def main() -> None:
    cfg = PlatformConfig.from_env("PURVIEW")  # raises clearly if creds missing
    print(f"tenant {cfg.tenant_id[:8]}…  (secret not shown)")
    async with GraphClient(cfg) as gc:
        _show("get_dlp_summary", await tools.get_dlp_summary(gc))
        _show("list_dlp_alerts", await tools.list_dlp_alerts(gc, limit=3))
        _show("list_insider_risk_alerts", await tools.list_insider_risk_alerts(gc, limit=3))
        _show("list_sensitivity_labels", await tools.list_sensitivity_labels(gc))
        # Audit search exercises the async two-phase path end-to-end.
        _show("search_audit_log", await tools.search_audit_log(gc, hours_back=4, limit=3))


if __name__ == "__main__":
    asyncio.run(main())
