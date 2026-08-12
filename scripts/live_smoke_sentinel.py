"""Live smoke test for the Sentinel MCP server against a real workspace.

Usage (from the repo root):
    1. Copy servers/sentinel-mcp/.env.sentinel.example to ./.env.sentinel and fill
       it in. Required Azure roles on the Log Analytics workspace resource:
       Log Analytics Reader (all telemetry tools) and, optionally, Microsoft
       Sentinel Reader (get_detection_coverage only -- everything else still
       works without it).
    2. uv run python scripts/live_smoke_sentinel.py [--hours 24] [--persona hunter]

Calls all seven read tools against live Sentinel and prints REDACTED findings.
Secrets are never printed -- every finding goes through core's redaction layer
before it reaches stdout. Auth / permission / missing-table / rate-limit issues
show up as posture findings (graceful degradation), not crashes; this script
additionally wraps each call in try/except so an *unmapped* exception is
reported and the run continues rather than aborting -- the point of a smoke
test is to observe behaviour across all seven tools in one pass.

Read-only by construction: this script only imports and calls the seven `list_*`
/ `hunt_*` / `search_*` / `get_*` / `run_kql` read functions from
`f0_sentinel_mcp.tools`. `run_kql` is exercised with a trivially safe,
aggregate-only query (`Heartbeat | summarize ... by Computer`); the tool itself
rejects any query starting with a Kusto control-command prefix (`.`), so
nothing here -- or a careless edit of the `--kql` example -- can mutate the
workspace. Bounded by design: default `--hours` is a short 24h window (168h /
7d only for the incident queue, which is a small management table, not raw
telemetry), and every call relies on each tool's own default `limit` (25) --
this workspace ingests on the order of 100M+ rows per 7 days in its busiest
table, so nothing here requests an unbounded or default-wide scan.
"""
from __future__ import annotations

import argparse
import asyncio
import json

from dotenv import load_dotenv
from f0_sectools_core.auth.config import SentinelConfig
from f0_sectools_core.redaction.redact import redact_finding
from f0_sectools_core.renderers import Persona, render_findings
from f0_sentinel_mcp import tools
from f0_sentinel_mcp.client import SentinelClient

# Mirrors every other live_smoke_*.py script: reads local env vars into this
# process only. Never printed, logged, or otherwise surfaced below.
load_dotenv(".env.sentinel")


def _show(label: str, findings, persona: str | None = None, show: int = 6) -> None:
    """Print up to `show` REDACTED findings for one tool call.

    `show` is bumped above the 6-item default for calls whose whole point is
    an inventory a human needs to scan in full (e.g. list_data_sources, to
    confirm specific tables are present) rather than a spot-check sample.
    """
    print(f"\n=== {label}: {len(findings)} finding(s) ===")
    for f in findings[:show]:
        print(json.dumps(redact_finding(f).model_dump(), indent=2, default=str))
    if len(findings) > show:
        print(f"... ({len(findings) - show} more)")
    if persona is not None:
        print(f"\n--- {persona} view ---")
        print(render_findings(findings, persona))


async def _run(label: str, coro, persona: str | None, show: int = 6) -> None:
    """Await one tool call and show it; an unmapped exception is reported, not raised.

    Every tool already maps known platform failures (missing table, 403, rate
    limit) to a posture finding -- that is a SUCCESSFUL smoke-test outcome and
    prints normally via `_show`. This wrapper is the backstop for anything a
    tool did *not* map, so one surprising failure mode does not abort the
    other six tools' worth of observation in the same run.
    """
    try:
        findings = await coro
    except Exception as e:  # noqa: BLE001 — smoke test: report and continue
        print(f"\n=== {label}: ERROR (unmapped) ===\n{type(e).__name__}: {e}")
        return
    _show(label, findings, persona, show=show)


async def main(hours: float, persona: str | None) -> None:
    cfg = SentinelConfig.from_env("SENTINEL")  # raises clearly if creds missing
    print(
        f"Workspace {cfg.workspace_id[:8]}…  ARM={'yes' if cfg.has_arm else 'no'}  "
        f"retention={cfg.retention_days}d  (secrets not shown)"
    )

    async with SentinelClient(cfg) as c:
        # 1. Capability inventory -- shown in full (not the 6-item default) so
        #    a human can scan for OfficeActivity / SecurityIncident /
        #    SecurityAlert specifically. Live-confirmed 2026-08-11: the
        #    Usage-based, no-IsBillable-filter probe returns all 27 ingesting
        #    tables including these three (OfficeActivity at 34.79 GB/30d) --
        #    the workspace-metadata-endpoint fallback discussed in probe.py's
        #    docstring is NOT needed.
        await _run("list_data_sources", tools.list_data_sources(c), persona, show=60)

        # 2. Firewall (CommonSecurityLog) -- aggregate only (no indicator), so
        #    this is a `summarize` over the window, never a row-level dump.
        await _run(
            "hunt_firewall (aggregate)",
            tools.hunt_firewall(c, action="blocked", hours_back=hours),
            persona,
        )

        # 3-5. Cisco Umbrella: dns, web, vpn. The vpn call passes no `action`
        #    (defaults to "any"), which forces the aggregate path that groups
        #    by the surface's action_field (Event_Type_s) and shows the real
        #    top values -- this is what confirms or corrects the provisional
        #    connected/failed guess in normalize.SURFACE_SPECS["vpn"].
        await _run(
            "hunt_dns_web dns (aggregate)",
            tools.hunt_dns_web(c, surface="dns", action="blocked", hours_back=hours),
            persona,
        )
        await _run(
            "hunt_dns_web web (aggregate)",
            tools.hunt_dns_web(c, surface="web", action="blocked", hours_back=hours),
            persona,
        )
        await _run(
            "hunt_dns_web vpn (aggregate, action values)",
            tools.hunt_dns_web(c, surface="vpn", hours_back=hours),
            persona,
        )

        # 6-7. OfficeActivity: discovery mode (no operation -> operation
        #    vocabulary) and a concrete operation, which projects
        #    _OA_PROJECT's column list (UserId, ClientIP, OfficeObjectId,
        #    ResultStatus). If any of those columns don't exist on this
        #    workspace, the KQL fails and that surfaces here as either a
        #    mapped posture finding or an "ERROR (unmapped)" line above.
        await _run(
            "search_office_activity (discovery)",
            tools.search_office_activity(c, hours_back=hours),
            persona,
        )
        await _run(
            "search_office_activity FileDownloaded",
            tools.search_office_activity(c, operation="FileDownloaded", hours_back=hours),
            persona,
        )

        # 8. Incident queue. hours_back=168 (7d) is the tool's own default and is a
        #    small management table, not raw telemetry, so it stays cheap.
        #    Shown at a higher cap than the 6-item default so IncidentNumber
        #    values can be eyeballed for duplicates -- the arg_max dedup
        #    collapses to one row per IncidentNumber by construction, but this
        #    is where a human confirms the displayed queue actually reads as
        #    one-incident-per-row rather than one-row-per-update.
        await _run(
            "list_sentinel_incidents",
            tools.list_sentinel_incidents(c, hours_back=168),
            persona,
            show=25,
        )

        # 9. Detection coverage (ARM half). Either a rule inventory or a
        #    posture finding explaining missing ARM config / a 403 -- both are
        #    a successful outcome for this smoke test.
        await _run("get_detection_coverage", tools.get_detection_coverage(c), persona)

        # 10. run_kql with a trivially safe, aggregate-only example query.
        await _run(
            "run_kql",
            tools.run_kql(c, "Heartbeat | summarize n=count() by Computer", hours_back=hours),
            persona,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live smoke test for the Sentinel MCP server.")
    parser.add_argument(
        "--hours",
        type=float,
        default=24.0,
        help="Lookback window for telemetry calls (clamped to workspace retention). "
        "Default 24h -- keep this short on large workspaces.",
    )
    parser.add_argument(
        "--persona",
        choices=[p.value for p in Persona],
        default=None,
        help="Also print findings rendered for this persona (raw JSON is always shown).",
    )
    args = parser.parse_args()
    asyncio.run(main(args.hours, args.persona))
