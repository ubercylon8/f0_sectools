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

import argparse
import asyncio
import json

from dotenv import load_dotenv
from f0_defender_mcp import tools
from f0_sectools_core.auth.config import PlatformConfig
from f0_sectools_core.auth.graph import GraphClient
from f0_sectools_core.redaction.redact import redact_obj
from f0_sectools_core.renderers import Persona, render_findings

load_dotenv(".env.defender")

# A harmless, bounded hunting query to validate ThreatHunting.Read.All.
SMOKE_KQL = "DeviceInfo | take 1"


def _show(label: str, findings, persona: str | None = None) -> None:
    print(f"\n=== {label}: {len(findings)} finding(s) ===")
    for f in findings:
        redacted = redact_obj(f.model_dump())
        print(json.dumps(redacted, indent=2, default=str))
    if persona is not None:
        print(f"\n--- {persona} view ---")
        print(render_findings(findings, persona))


async def main(persona: str | None = None) -> None:
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
                _show(label, await coro, persona)
            except Exception as e:  # noqa: BLE001 — smoke test: report and continue
                print(f"\n=== {label}: ERROR ===\n{type(e).__name__}: {e}")

    # ── Gated-write DRY RUN (no device is ever isolated) ──────────────
    from f0_sectools_core.gating.actions import AuditLog, GatedAction, TokenStore

    sec = GraphClient(
        cfg,
        base_url="https://api.security.microsoft.com/api",
        scope="https://api.security.microsoft.com/.default",
    )
    async with sec:
        gate_off = GatedAction(
            "defender.isolate_host", enabled=False,
            audit=AuditLog("audit-logs/actions.log"), token_store=TokenStore(),
        )
        # 1) intent only (no token) — must NOT call the API
        _show("isolate_host INTENT (no token)",
              await tools.isolate_host(sec, gate_off, "smoke-device", "dry run"), persona)
        # 2) flag-off refusal (fake token) — must refuse, no state change
        _show("isolate_host REFUSAL (flag off)",
              await tools.isolate_host(sec, gate_off, "smoke-device", "dry run",
                                       confirmation_token="not-a-real-token"), persona)  # noqa: S106 — dummy refusal token, not a credential
    print("\nDRY RUN complete — no device was isolated.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live smoke test for the Defender MCP server.")
    parser.add_argument(
        "--persona",
        choices=[p.value for p in Persona],
        default=None,
        help="Also print findings rendered for this persona (raw JSON is always shown).",
    )
    args = parser.parse_args()
    asyncio.run(main(args.persona))
