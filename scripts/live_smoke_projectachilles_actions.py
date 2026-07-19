"""Live smoke test for the ProjectAchilles ACTIONS server against a real instance.

Usage (from the repo root):
    1. Ensure ./.env.projectachilles has PROJECTACHILLES_BASE_URL and a
       READ-WRITE-scope PROJECTACHILLES_API_KEY (pa_...). Writes additionally
       need PROJECTACHILLES_ALLOW_WRITE=true.
    2. uv run python scripts/live_smoke_projectachilles_actions.py
       # reads + INTENT-ONLY gated calls (no state change, no token needed)
    3. Full write pass (creates a real task!):
       uv run python scripts/live_smoke_projectachilles_actions.py \
           --execute --test-uuid <uuid> --hostname <host> --token <token>
       # token from: python scripts/confirm_action.py run_test \
       #   "<uuid>@<host>" --platform projectachilles

Prints REDACTED findings. Secrets are never printed.
"""
from __future__ import annotations

import argparse
import asyncio
import json

from dotenv import load_dotenv
from f0_pa_actions_mcp import tools
from f0_pa_actions_mcp.client import ProjectAchillesClient
from f0_sectools_core.auth.config import ProjectAchillesConfig
from f0_sectools_core.gating.actions import AuditLog, GatedAction, TokenStore
from f0_sectools_core.redaction.redact import redact_obj

load_dotenv(".env.projectachilles")


def _show(label: str, findings) -> None:
    print(f"\n=== {label}: {len(findings)} finding(s) ===")
    for f in findings[:8]:
        print(json.dumps(redact_obj(f.model_dump()), indent=2, default=str))
    if len(findings) > 8:
        print(f"... ({len(findings) - 8} more)")


def _gate(name: str, cfg: ProjectAchillesConfig) -> GatedAction:
    return GatedAction(name, enabled=cfg.allow_write, audit=AuditLog(),
                       token_store=TokenStore())


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--execute", action="store_true",
                    help="run the FULL write pass (creates a real task)")
    ap.add_argument("--test-uuid", default="")
    ap.add_argument("--hostname", default="")
    ap.add_argument("--token", default="")
    args = ap.parse_args()

    cfg = ProjectAchillesConfig.from_env()
    print(f"Instance {cfg.base_url}  allow_write={cfg.allow_write}")
    async with ProjectAchillesClient(cfg) as pa:
        _show("list_schedules", await tools.list_schedules(pa))
        # Intent-only gated calls: no token -> no state change, verifies the
        # resolution chain (test lookup, build lookup, agent match) live.
        if args.test_uuid and args.hostname:
            _show(
                "run_test INTENT",
                await tools.run_test(
                    pa, _gate("projectachilles.run_test", cfg),
                    args.test_uuid, args.hostname,
                ),
            )
            _show(
                "schedule_test INTENT (daily 02:30)",
                await tools.schedule_test(
                    pa, _gate("projectachilles.schedule_test", cfg),
                    args.test_uuid, args.hostname, "daily", "02:30",
                ),
            )
        if args.execute:
            if not (args.test_uuid and args.hostname and args.token):
                print("--execute needs --test-uuid, --hostname and --token")
                return
            findings = await tools.run_test(
                pa, _gate("projectachilles.run_test", cfg),
                args.test_uuid, args.hostname, confirmation_token=args.token,
            )
            _show("run_test EXECUTE", findings)
            task_ids = [
                ev.value for f in findings for ev in f.evidence
                if ev.key == "task_id"
            ]
            if task_ids:
                _show("get_task_status", await tools.get_task_status(pa, task_ids[0]))


if __name__ == "__main__":
    asyncio.run(main())
