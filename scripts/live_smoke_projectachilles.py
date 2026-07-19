"""Live smoke test for the ProjectAchilles MCP server against a real instance.

Usage (from the repo root):
    1. Copy servers/projectachilles-mcp/.env.projectachilles.example to
       ./.env.projectachilles and fill in PROJECTACHILLES_BASE_URL and a read-scope
       PROJECTACHILLES_API_KEY (pa_...).
    2. uv run python scripts/live_smoke_projectachilles.py
       # Always runs a wire-field audit of /analytics/executions/paginated —
       # confirms PR #28's 3 tenant checks: (a) snake_case keys present (no
       # camelCase drift), (b) `category` populated for cyber-hygiene rows,
       # (c) most-recent-first ordering. Widen the window with --audit-days N
       # if it reports no rows / no cyber-hygiene bundle.
       # Pass --test <name-or-uuid> to also probe the scoped list_test_executions
       # path (confirms the live ?tests= filter semantics — name or uuid).

Calls each read tool against live ProjectAchilles and prints REDACTED findings.
Secrets are never printed. Auth / permission / rate-limit issues show up as
posture findings (graceful degradation), not crashes.
"""
from __future__ import annotations

import argparse
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


# Branch-critical fields of an EnrichedTestExecution row. list_test_executions'
# rollup + security/cyber-hygiene vocabulary only work if these are present with
# these exact (snake_case) keys — the backend's mapHitToExecution returns snake
# literals, but a camelCase wire would silently mislabel EVERY row and stay
# invisible to snake_case contract mocks. camel_hint is the variant to watch for.
_EXEC_FIELDS = [
    ("category", "category"),            # (b) drives passed/not-passed vs blocked
    ("is_protected", "isProtected"),
    ("defender_detected", "defenderDetected"),
    ("severity", "severity"),
    ("techniques", "techniques"),
    ("is_bundle_control", "isBundleControl"),  # bundle rollup grouping
    ("bundle_name", "bundleName"),
    ("hostname", "hostname"),
    ("timestamp", "timestamp"),          # (c) ordering
]


async def _audit_executions_wire(pa, days: int) -> None:
    """Confirm PR #28's three tenant checks against the LIVE wire, not the
    rendered findings: (a) snake_case keys present, (b) category populated for
    cyber-hygiene rows, (c) most-recent-first ordering. Prints raw (redacted)
    field presence — the whole point is to see the response shape the tool maps.
    """
    from datetime import UTC, datetime, timedelta

    to = datetime.now(UTC).date().isoformat()
    frm = (datetime.now(UTC) - timedelta(days=days)).date().isoformat()
    print(f"\n=== wire audit: /analytics/executions/paginated (last {days}d) ===")
    resp = await pa.get(
        "/analytics/executions/paginated",
        params={"from": frm, "to": to, "pageSize": 25,
                "sortField": "routing.event_time", "sortOrder": "desc"},
    )
    rows = (resp.get("data") if isinstance(resp, dict) else None) or []
    if not rows:
        print(f"  no executions in the last {days}d — widen with --audit-days N to "
              "audit fields (need at least one row, ideally a cyber-hygiene bundle).")
        return
    sample = redact_obj(rows[0]) if isinstance(rows[0], dict) else {}

    # (a) key presence + camelCase-drift detector
    print(f"  rows fetched: {len(rows)}")
    print("  (a) branch-critical keys on row[0]:")
    for snake, camel in _EXEC_FIELDS:
        if snake in sample:
            val = json.dumps(sample[snake], default=str)[:60]
            print(f"      OK   {snake:<18} = {val}")
        elif camel != snake and camel in sample:
            print(f"      DRIFT {snake:<18} MISSING — found camelCase '{camel}' "
                  "(this would mislabel every row!)")
        else:
            print(f"      --   {snake:<18} absent on this row")

    # (b) cyber-hygiene rows present & categorized?
    def _cat(r: dict) -> str:
        return str(r.get("category", "")).strip().lower().replace("_", "-").replace(" ", "-")
    hygiene = [r for r in rows if isinstance(r, dict) and _cat(r) == "cyber-hygiene"]
    bundle = [r for r in rows if isinstance(r, dict) and r.get("is_bundle_control")]
    cats = sorted({_cat(r) for r in rows if isinstance(r, dict) and _cat(r)})
    print(f"  (b) distinct category values seen: {cats or '(none — category is empty!)'}")
    print(f"      cyber-hygiene rows: {len(hygiene)} | bundle-control rows: {len(bundle)}")
    if not hygiene:
        print("      note: no cyber-hygiene rows in window — run a hygiene bundle, "
              "then re-audit to confirm they render 'passed/not passed'.")

    # (c) ordering: timestamps should be descending
    ts = [r.get("timestamp") for r in rows[:5] if isinstance(r, dict)]
    print(f"  (c) first 5 timestamps (want descending): {ts}")
    if len([t for t in ts if t]) >= 2:
        desc = all(str(a) >= str(b) for a, b in zip(ts, ts[1:], strict=False) if a and b)
        print(f"      most-recent-first: {'OK' if desc else 'NOT descending — check sort'}")


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--test", default="",
        help="test name or uuid to scope the list_test_executions probe to "
             "(confirms live ?tests= filter semantics); omitted -> probe skipped",
    )
    ap.add_argument(
        "--audit-days", type=int, default=30,
        help="window (days) for the executions wire-field audit (PR #28 checks: "
             "snake_case keys, category populated, ordering). Widen if the window "
             "has no rows or no cyber-hygiene bundle.",
    )
    args = ap.parse_args()

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
            # Catalog reads — the FIRST of these confirms /browser/tests auth
            # reachability with the pa_ key (the top live-validation risk).
            (
                "find_tests(technique=T1110)",
                tools.find_tests(pa, by="technique", value="T1110", limit=5),
            ),
            ("find_tests(actor=APT29)", tools.find_tests(pa, by="actor", value="APT29", limit=5)),
        ]:
            try:
                _show(label, await coro)
            except Exception as e:  # noqa: BLE001 — smoke test: report and continue
                print(f"\n=== {label}: ERROR ===\n{type(e).__name__}: {e}")

        # PR #28 tenant checks — audit the RAW wire fields, not the rendered
        # findings (a dead branch is invisible in the mapped output).
        try:
            await _audit_executions_wire(pa, days=args.audit_days)
        except Exception as e:  # noqa: BLE001 — smoke test: report and continue
            print(f"\n=== wire audit: ERROR ===\n{type(e).__name__}: {e}")

        if args.test:
            try:
                _show(
                    f"list_test_executions(test={args.test})",
                    await tools.list_test_executions(pa, days=30, limit=10, test=args.test),
                )
            except Exception as e:  # noqa: BLE001 — smoke test: report and continue
                print(f"\n=== list_test_executions(test=...): ERROR ===\n{type(e).__name__}: {e}")
        else:
            print("\n(skipping scoped list_test_executions probe — pass --test <name-or-uuid>)")


if __name__ == "__main__":
    asyncio.run(main())
