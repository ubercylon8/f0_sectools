# Bounded Output + Tenable plugin→hosts — Design Spec

**Date:** 2026-07-14
**Status:** Approved for planning
**Type:** Server capability + cross-server bounding fix (touches `core/`, `defender`, `entra`, `tenable`)
**Origin:** Surfaced by the 2026-07-14 pi live-run (see `memory/pi-live-validation-followups.md`). Corroborated by the PR #23 Claude review as a Critical Rule 5 priority.

## Goal

Close the two server-side gaps the pi live-run exposed:

1. **Capability gap** — no tool maps a Tenable plugin/vulnerability to its affected hosts. Asked "which hosts have plugin X," the model brute-forced `list_assets` and hung. **Add** `list_vulnerability_assets`.
2. **Bounding bug (Critical Rule 5)** — four Graph tools return the *entire* result set instead of `limit`, because they use `get_all(...$top=limit)` (which follows `@odata.nextLink` to the end; `$top` is only page size). **Bound** them to a single page + slice, and **clamp** `limit` across all list tools.

## Verified facts (ground truth)

- **Tenable endpoint** (confirmed via docs): `GET /workbenches/vulnerabilities/{plugin_id}/outputs` — "List Plugin Outputs" returns the assets affected by a plugin (≤5000, <450 days). Source: https://developer.tenable.com/reference/workbenches-vulnerability-output
- **The unbounded tools** (only these four — verified by reading the code):
  - `servers/defender-mcp/.../tools.py`: `list_incidents` (`/security/incidents`), `list_alerts` (`/security/alerts_v2`)
  - `servers/entra-mcp/.../tools.py`: `list_risky_users` (`/identityProtection/riskyUsers`), `list_risk_detections` (`/identityProtection/riskDetections`)
  - All call `gc.get_all(path, params={"$top": limit})` and map **every** returned row (no slice).
- **Tenable list tools are already bounded** — they slice (`rows[:limit]`, `if len(out) >= limit: break`). They only need the `limit` clamp, not a get_all fix.
- `GraphClient.get()` returns the raw page dict (`{"value": [...], "@odata.nextLink": ...}`) — same call the merged `get_secure_score` fix now uses.
- `TenableClient.get()` is a single request (no pagination helper).
- `core/f0_sectools_core/paging/` exists but is a **stub** (docstring only) — the natural home for shared bounding helpers (Critical Rule 6: cross-cutting logic lives in `core/`).

## Design decisions (approved)

- **Bounding approach:** single-page `get(...$top=limit)` + existing severity filter + slice to `limit`. Rely on the API's default order (incidents/alerts are recent-first). Accepted tradeoff: a high-severity item scattered beyond the fetched page may be missed for a broad "list" query — mitigated by the *"more available"* note (below). Server-side `$filter`/`$orderby` is a future refinement, out of scope.
- **`limit` clamp:** bound caller-supplied `limit` to `[1, 100]` across every list tool (defender/entra/tenable). This is the actual mechanism behind the pi hang (a model cranked `limit`).
- **Packaging:** one focused PR. The new Tenable tool is **live-validation-pending** until validated against the operator's tenant.

## Components

### C1 — `core/paging` helpers (new, shared)

Flesh out the stub with two helpers + `core/tests` coverage:

- `clamp_limit(limit, default=25, maximum=100) -> int` — coerce to int (invalid → `default`), bound to `[1, maximum]`.
- `more_available_finding(source, shown, total=None, hint="") -> Finding` — an `info`/`posture` finding signalling truncation:
  - with `total`: `"Showing {shown} of {total} — narrow the filter or raise limit (max 100) to see more."`
  - without: `"Showing {shown}; more results available — narrow the filter or raise limit (max 100)."`
  Its purpose is behavioural: it tells a small model the set is (in)complete so it stops re-querying (the pi run re-queried incidents 3×).

`core/paging` may import `core/schema` (that's the intended layering); no server may re-implement these.

### C2 — Bounding fix for the four Graph tools

For each of `list_incidents`, `list_alerts`, `list_risky_users`, `list_risk_detections`:

```python
limit = clamp_limit(limit)
page = await gc.get(path, params={"$top": limit})     # single page, NOT get_all
raw = page.get("value", [])
has_more = bool(page.get("@odata.nextLink"))
# ... existing severity filter + mapping, building `findings` ...
findings = findings[:limit]
if has_more:
    findings.append(more_available_finding("<source>", shown=len(findings)))
return findings
```

Behaviour change: from "every matching row in the tenant" → "up to `limit` from the first page, plus a truncation note when more exist." Error handling (auth/403/429) is unchanged.

### C3 — New Tenable tool `list_vulnerability_assets`

`servers/tenable-mcp/.../tools.py`:

```python
async def list_vulnerability_assets(tio, plugin_id: str, limit: int = 25) -> list[Finding]:
    limit = clamp_limit(limit)
    try:
        d = await tio.get(f"/workbenches/vulnerabilities/{plugin_id}/outputs")
    except Exception as e:
        finding = map_tenable_error(e, "Tenable plugin affected hosts")
        if finding: return [finding]
        raise
    # Walk outputs[] -> states[] -> results[] -> assets[]; dedupe by asset id.
    # (EXACT field names/nesting are LIVE-VALIDATED — recipe step 9.)
    assets = _plugin_output_assets(d)          # helper, returns list[dict]
    if not assets:
        return [<graceful "no affected assets for plugin {plugin_id}" posture finding>]
    out = [ <host Finding per asset: entity host (fqdn/ipv4/id), evidence ipv4/last_seen,
             references tenable_plugin> for a in assets[:limit] ]
    if len(assets) > limit:
        out.append(more_available_finding("tenable", shown=limit, total=len(assets)))
    return out
```

- `finding_type = misconfig`, severity from the result/plugin severity if present else `info`.
- Register in `server.py` (`@mcp.tool()`), one-sentence description: *"List the hosts affected by a specific Tenable vulnerability (plugin_id). Use after list_top_vulnerabilities to see which assets carry a finding."* Tenable goes 6 → **7** tools (≤8, OK).

### C4 — `limit` clamp on the already-bounded tools

Add `limit = clamp_limit(limit)` to `list_top_vulnerabilities`, `list_assets`, `get_asset_vulnerabilities`, `list_scans` (tenable). Pure hardening; behaviour otherwise unchanged.

## Testing

- **`core/tests`** — `clamp_limit` (invalid/negative/over-max/normal); `more_available_finding` (with/without total → schema-valid Finding).
- **defender/entra contract tests** — for each of the four tools: (a) a **paginated mock** (page 1 has `@odata.nextLink`) asserting the second page is **not** fetched and a truncation note is appended (mirrors the merged `test_get_secure_score_does_not_paginate_history`); (b) slice-to-`limit`; (c) existing error-path tests still pass.
- **tenable contract tests** — `list_vulnerability_assets`: a mocked `/outputs` payload → N host findings; the no-assets case → graceful finding; truncation note when assets > limit; error path → `map_tenable_error`.
- **Full suite + ruff + mypy** stay green.

## Live validation (operator-driven; recipe step 9)

I cannot call the live platform (auto-mode gate). So:
- Add the new tool to `scripts/live_smoke_tenable.py` (a real `plugin_id` from the tenant, e.g. from `list_top_vulnerabilities`).
- The operator runs the smoke with network enabled; we **fix-forward** any field-name/nesting mismatch in `_plugin_output_assets`. Mark live-validated once clean.
- The bounding fix is behaviour-preserving + mock-proven; it does not require live validation, though the operator's next pi run will exercise it.

## Docs & counts to update

- Tool count rises **34 → 35** (33 read + 2 gated). Update every reference: `README.md`, `docs/user-guide/README.md` support matrix (Tenable tool list), `CLAUDE.md` Platform Integrations, and the `CHANGELOG.md` (new `Unreleased`/next section). Grep for `34` / `32 read` and fix each.
- Tenable skill `tenable/host-vulnerability-triage` (and/or `exposure-posture-review`) — add a line: to list hosts affected by a plugin, use `list_vulnerability_assets`.
- `evals/tenable/tasks.yaml` — add ≥1 task for the new tool.

## Non-goals (YAGNI)

- Server-side `$filter`/`$orderby` for the Graph tools (single-page + note is enough now).
- A real stateful cursor / `next_cursor` token (the truncation note covers the small-model need; true cursors are a later enhancement if needed).
- Tenable export-request API for >5000 outputs.
- Touching the gated write path, redaction, or the findings schema shape.

## Constraints

- Read-only; no gating/redaction/schema changes. Every failure still becomes a finding, never an exception.
- Shared logic (`clamp_limit`, `more_available_finding`) lives in `core/` only (Rule 6).
- Keep Tenable ≤ 8 tools (now 7). Flat scalar args, short descriptions (small-model-safe).
- Push is user-gated. Tenable tool stays live-validation-pending until the operator validates.
