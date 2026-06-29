"""Live smoke test for the LimaCharlie MCP server against a real org.

Usage (from the repo root):
    1. Copy servers/limacharlie-mcp/.env.limacharlie.example to ./.env.limacharlie
       and fill in LIMACHARLIE_OID / LIMACHARLIE_API_KEY.
    2. uv run python scripts/live_smoke_limacharlie.py

Calls each read tool against live LimaCharlie and prints REDACTED findings.
Secrets are never printed. A missing permission / rate-limit / auth issue shows
up as a posture finding (graceful degradation), not a crash.
"""
from __future__ import annotations

import json

from dotenv import load_dotenv
from f0_limacharlie_mcp import tools
from f0_limacharlie_mcp.client import LimaCharlieClient
from f0_sectools_core.auth.config import LimaCharlieConfig
from f0_sectools_core.redaction.redact import redact_obj

load_dotenv(".env.limacharlie")



def _show(label: str, findings) -> None:
    print(f"\n=== {label}: {len(findings)} finding(s) ===")
    for f in findings[:10]:
        print(json.dumps(redact_obj(f.model_dump()), indent=2, default=str))
    if len(findings) > 10:
        print(f"... ({len(findings) - 10} more)")


def main() -> None:
    cfg = LimaCharlieConfig.from_env()  # raises clearly if creds missing
    print(f"OID {cfg.oid[:8]}…  (api key not shown)")
    lc = LimaCharlieClient(cfg)
    for label, fn in [
        ("get_org_overview", lambda: tools.get_org_overview(lc)),
        ("list_sensors", lambda: tools.list_sensors(lc, limit=5)),
        ("list_dr_rules", lambda: tools.list_dr_rules(lc, limit=5)),
        ("list_detections", lambda: tools.list_detections(lc, hours_back=168, limit=5)),
        ("query_telemetry", lambda: tools.query_telemetry(lc, hunt="new_processes", limit=3)),
    ]:
        try:
            _show(label, fn())
        except Exception as e:  # noqa: BLE001 — smoke test: report and continue
            print(f"\n=== {label}: ERROR ===\n{type(e).__name__}: {e}")


if __name__ == "__main__":
    main()
