"""Live smoke test for the Tenable MCP server against a real Tenable VM instance.

Usage (from the repo root):
    1. Copy servers/tenable-mcp/.env.tenable.example to ./.env.tenable and fill in
       TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY.
    2. uv run python scripts/live_smoke_tenable.py [--persona ciso]

Calls each read tool against live Tenable and prints REDACTED findings. Secrets are
never printed. Auth / permission / rate-limit issues show up as posture findings
(graceful degradation), not crashes.
"""
from __future__ import annotations

import argparse
import asyncio
import json

from dotenv import load_dotenv
from f0_sectools_core.auth.config import TenableConfig
from f0_sectools_core.redaction.redact import redact_obj
from f0_sectools_core.renderers import Persona, render_findings
from f0_tenable_mcp import tools
from f0_tenable_mcp.client import TenableClient

load_dotenv(".env.tenable")


def _show(label: str, findings, persona: str | None = None) -> None:
    print(f"\n=== {label}: {len(findings)} finding(s) ===")
    for f in findings[:8]:
        print(json.dumps(redact_obj(f.model_dump()), indent=2, default=str))
    if len(findings) > 8:
        print(f"... ({len(findings) - 8} more)")
    if persona is not None:
        print(f"\n--- {persona} view ---")
        print(render_findings(findings, persona))


async def main(persona: str | None = None) -> None:
    cfg = TenableConfig.from_env()  # raises clearly if creds missing
    print(f"Instance {cfg.base_url}  (api keys not shown)")
    async with TenableClient(cfg) as tio:
        # get an asset id for the per-asset call from the asset list
        assets = await tools.list_assets(tio, limit=1)
        first_asset = assets[0].entity.name if assets and assets[0].entity else "localhost"
        for label, coro in [
            ("get_vulnerability_summary", tools.get_vulnerability_summary(tio)),
            (
                "list_top_vulnerabilities",
                tools.list_top_vulnerabilities(tio, limit=5),
            ),
            ("list_assets", tools.list_assets(tio, limit=5)),
            (
                "get_asset_vulnerabilities",
                tools.get_asset_vulnerabilities(tio, first_asset, limit=5),
            ),
            ("list_scans", tools.list_scans(tio, limit=5)),
        ]:
            try:
                _show(label, await coro, persona)
            except Exception as e:  # noqa: BLE001 — smoke test: report and continue
                print(f"\n=== {label}: ERROR ===\n{type(e).__name__}: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live smoke test for the Tenable MCP server.")
    parser.add_argument(
        "--persona",
        choices=[p.value for p in Persona],
        default=None,
        help="Also print findings rendered for this persona (raw JSON is always shown).",
    )
    args = parser.parse_args()
    asyncio.run(main(args.persona))
