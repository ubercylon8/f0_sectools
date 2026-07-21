# purview-mcp — Microsoft Purview Data-Risk Server Design

**Date:** 2026-07-21 · **Status:** approved-pending-review · **Server #8**

Read-only MCP server over **Microsoft Purview's data-security surface** — the
**data-risk pillar** (DLP pressure, insider risk, audit posture, classification
coverage), which no current server covers. Follows the CLAUDE.md
add-a-platform recipe; the eighth thin server over the shared `core/`.

## What a CISO/analyst gets

- "How much data-loss pressure are we under?" — DLP alert rollup by severity /
  status / policy.
- "Show me this week's DLP alerts" / "insider-risk alerts" — bounded lists.
- "Is classification actually deployed?" — sensitivity-label inventory.
- "Who deleted/shared/accessed X in the last 24h?" — guided unified-audit
  search.

**Explicit non-goals** (documented in the README so nobody hunts for them):
- **Compliance Manager compliance score — NO public API exists** (portal-only).
  The API-accessible alternative is Defender for Cloud's regulatory-compliance
  ARM surface — a separate roadmap item, not this server.
- Deep per-event DLP forensics (legacy O365 Management Activity API blob model)
  — out of scope; the alerts carry the operational signal.
- eDiscovery, retention, communication compliance — out of scope (write-heavy
  or case-centric; no small-model-safe read story yet).

## API surface (grounded 2026-07-21 via Microsoft Learn)

| Capability | Endpoint | Status | App permission |
|---|---|---|---|
| DLP + IRM alerts | `GET /v1.0/security/alerts_v2?$filter=serviceSource eq '…'` | GA | `SecurityAlert.Read.All` (already granted to the tenant app for defender-mcp) |
| Audit search (async) | `POST /v1.0/security/auditLog/queries` → poll → `…/records` | GA | **`AuditLogsQuery.Read.All`** — NEW, needs admin consent |
| Sensitivity labels | `GET /beta/security/informationProtection/sensitivityLabels` | **beta** | `InformationProtectionPolicy.Read.All` (verify exact name at build) — NEW |

Live-verification items (recipe step 9 always finds 1–3): the exact
`serviceSource` enum values for DLP/IRM alerts; the beta labels path +
permission name; audit-query completion latency on the real tenant; whether
DLP/IRM licensing exists on the tenant (if not → graceful
`permission_missing`/empty findings, which is itself the posture answer).

## Tools (6, flat args, bounded output)

1. `get_dlp_summary(hours_back: float = 168)` — one posture finding: DLP alert
   counts by severity and status, top policies observed (bounded), plus an
   explicit "0 alerts can mean no DLP policies / no Purview licensing" note
   when empty.
2. `list_dlp_alerts(hours_back: float = 168, severity_min: Literal[low|medium|high] = "low", limit: int = 25)`
   — one alert finding per DLP alert (title, severity, user/entity, policy,
   status), bounded + "more available" note.
3. `list_insider_risk_alerts(hours_back: float = 168, limit: int = 25)` — IRM
   alerts (users may be pseudonymized by IRM's own privacy design — surfaced
   as-is, never "un-anonymized").
4. `list_sensitivity_labels()` — the org's label inventory (name, priority,
   active), classification-coverage posture.
5. `search_audit_log(activity: str = "", user: str = "", hours_back: float = 24, limit: int = 25)`
   — guided unified-audit search. Submits an async query and polls up to ~50s
   server-side; if complete → one finding per record (operation, user,
   service, time, object). If still running → a posture finding carrying
   `audit_query_id` and instructing: call `get_audit_results` with it.
   `activity`/`user` are optional flat filters (operation name, UPN);
   charset-guarded; both empty = recent-activity sample.
6. `get_audit_results(audit_query_id: str, limit: int = 25)` — fetch results
   of a previously submitted audit query (the second phase of the async
   model). Not-ready → posture finding "still running, try again shortly".

The async two-phase design keeps every arg a flat scalar and never blocks a
small model's tool call beyond ~50s. No other state is carried between calls.

## Architecture (identical recipe)

- `core/auth/config.py`: `PurviewConfig` = `PlatformConfig.from_env("PURVIEW")`
  (tenant/client/secret; reuses the existing Graph client-credentials flow —
  no core change beyond the config alias + test).
- `.env.purview` (gitignored; example file documents required permissions).
  Same tenant app as defender/entra/intune may be reused by the operator —
  per-platform isolation still holds (separate env file, separate server).
- `servers/purview-mcp/f0_purview_mcp/{client,errors,tools,server}.py` —
  async httpx GraphClient (existing core client), `map_purview_error` →
  findings, redaction at the boundary. The beta labels call sets the beta
  base path explicitly for that one request.
- Evals: `evals/purview/tasks.yaml` (≥1 task per tool → +7-8 tasks, update
  `test_combined` counts + `SERVERS`/`SERVER_MODULES`), smoke script
  `scripts/live_smoke_purview.py`.
- Skills (step 10, after live validation): `skills/purview/` —
  `data-risk-review` (default: DLP summary + IRM + labels → data-risk
  posture), `dlp-alert-triage`, `audit-investigation`. Wire into personas
  (CISO favours data-risk-review) + runtime templates (pi mcp.json, Hermes
  config.example + distribution config, opencode.json — all drift-guarded, so
  CI enforces this).

## Operator prerequisites (flag before live-testing)

Grant to the tenant app (admin consent): **`AuditLogsQuery.Read.All`**
(application) and the labels permission (beta; verify name at build).
`SecurityAlert.Read.All` is already in place. DLP/IRM alert content depends on
Purview licensing + configured policies — absence degrades to findings, not
errors.

## Order of work

Recipe steps 1–9 (config → scaffold → client → errors → tools TDD → server →
evals → smoke → live-validate + fix-forward), then skills + docs + runtime
wiring (step 10–11), ship (step 12). Contract tests first throughout; the
`serviceSource` enums and beta paths are encoded only after the live smoke
confirms them.
