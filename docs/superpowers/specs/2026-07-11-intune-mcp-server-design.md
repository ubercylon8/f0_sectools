# Design: Microsoft Intune MCP server (server #5)

**Date:** 2026-07-11
**Status:** Approved (design), pending spec review
**Scope:** One implementation plan — a new read-only `servers/intune-mcp/`.

## Problem

f0_sectools covers EDR (Defender), identity (Entra), SecOps/EDR (LimaCharlie), and security
validation (ProjectAchilles), but not **device management / compliance coverage** — the "are our
endpoints actually managed, compliant, and encrypted, and which aren't?" question. Microsoft
Intune answers it, and it's the missing device-posture leg of the Microsoft security stack
already built here.

## Why this is the lowest-risk new server

Intune **is the Microsoft Graph API** (`GET /deviceManagement/managedDevices`, Bearer token,
`DeviceManagementManagedDevices.Read.All` application permission, admin consent). So it reuses
what already exists:

- **`core/auth.GraphClient`** (standard `graph.microsoft.com/v1.0` base + scope — Intune is core
  Graph, no special audience), **`PlatformConfig`**, client-credentials auth, `gc.get_all`
  pagination (`$top`/`@odata.nextLink`), and the `map_graph_error` → posture-finding degradation.
- **The existing Entra app** on the live `sb.gob.do` tenant — one admin-consent grant of the
  read permission (like the Entra ID Protection P2 grants) and it's live-validatable.
- **`core/` does not change** (the recipe lists "Microsoft Graph OAuth client-credentials" as an
  already-handled auth model). The server is essentially `entra-mcp` with different endpoints.

## Architecture — mirror `entra-mcp` exactly

`servers/intune-mcp/f0_intune_mcp/` with `server.py` (FastMCP, one `@mcp.tool()` per tool, builds
`PlatformConfig.from_env("INTUNE")` + `GraphClient(cfg)`, redacts at the boundary via
`redact_obj(f.model_dump())`) and `tools.py` (each tool `async (gc, …) -> list[Finding]`, catches
`GraphError` → `map_graph_error(e, "intune", "<permission>", "<capability>")` else re-raises,
defensive dict access). Credentials in a **gitignored `.env.intune`** (`INTUNE_TENANT_ID` /
`INTUNE_CLIENT_ID` / `INTUNE_CLIENT_SECRET` — same Entra-app values as `.env.entra` but its own
isolated file, per Critical Rule 7). No new `core/` code, no `errors.py` (reuses `graph_errors`).

## Read tools (6, flat, small-model-safe, read-only)

All read-only. Flat scalar args, closed enums, bounded/paginated. Graph endpoints under
`/deviceManagement`. Permission for all: `DeviceManagementManagedDevices.Read.All` (policies also
accept `DeviceManagementConfiguration.Read.All`).

1. **`list_managed_devices(compliance="all", limit=25)`** — `/deviceManagement/managedDevices`.
   Security-relevant fields per device: `deviceName`, `operatingSystem`/`osVersion`,
   `complianceState`, `isEncrypted`, `managedDeviceOwnerType` (company/personal),
   `lastSyncDateTime`, `userPrincipalName`. `compliance` is a **closed enum**
   (`all|compliant|noncompliant|ingraceperiod|unknown`); non-`all` applies a `$filter` on
   `complianceState`.
2. **`get_compliance_summary()`** — posture rollup finding: total managed, counts by compliance
   state, encrypted count, stale count (not synced in 30d). Preferred: the direct aggregate
   endpoint `/deviceManagement/deviceCompliancePolicyDeviceStateSummary` (returns
   compliant/nonCompliant/inGracePeriod/… counts); fallback: compute client-side from a bounded
   `managedDevices` query (`$select` the small fields, page-cap). Exact endpoint/field names are a
   live-validation item.
3. **`get_managed_device(device_name)`** — one device's full detail (compliance, encryption, OS,
   owner, last sync, user, and Defender protection state where present). Match by `deviceName`
   (`$filter`); if not found, a graceful "no managed device named X" finding. **The cross-platform
   triage pivot** (a Defender incident's device → its Intune compliance/encryption state).
4. **`list_stale_devices(days=30, limit=25)`** — devices whose `lastSyncDateTime` is older than
   `days`. Prefer a server-side `$filter` on `lastSyncDateTime`; if `managedDevices` doesn't
   support that filter (a known Graph quirk on some device fields — a live-validation item), fall
   back to fetching a bounded page and filtering client-side by the cutoff. Coverage-drift /
   possibly-abandoned signal.
5. **`list_compliance_policies(limit=25)`** — `/deviceManagement/deviceCompliancePolicies`. The
   **rules that define "compliant"** (name, description, platform). The coverage-engineering view:
   what compliance is even being enforced.
6. **`list_configuration_profiles(limit=25)`** — `/deviceManagement/deviceConfigurations`. The
   **settings pushed to devices** (name, description, platform). Distinct from #5 (compliance
   *rules* vs configuration *settings*) — named/described distinctly to avoid the small-model
   routing collision the multi-server eval surfaced.

## Error handling

Every failure is a Finding, never an exception (house rule): `403` → `Finding.permission_missing`
naming `DeviceManagementManagedDevices.Read.All`; **Intune-not-licensed** on the tenant surfaces
as a `403`/`4xx` → the same graceful posture finding (so an unlicensed tenant produces actionable
guidance, not a crash); `429` → `rate_limited`; `502/503/504` → `api_unavailable`; all via the
existing `map_graph_error`. Redaction runs on every path including errors.

## Testing & validation (recipe order)

1. **Contract tests** (`servers/intune-mcp/tests/test_tools.py`) — mock Graph with `respx`
   (mirroring the entra/defender tests): each tool returns correctly-shaped findings; the
   compliance enum → `$filter` mapping; 403 → permission finding; stale-device filter; redaction.
2. **Evals** — `evals/intune/tasks.yaml` (≥1 task per tool) + add `intune` to `SERVERS` in
   `evals/test_eval_coverage.py` and `SERVER_MODULES` in `evals/run.py` (and it auto-joins the
   combined 22→28-tool registry).
3. **Live smoke** — `scripts/live_smoke_intune.py`; create `.env.intune`, grant
   `DeviceManagementManagedDevices.Read.All`, run with the sandbox/network enabled, fix-forward
   the 1-3 field-shape mismatches live data always reveals. Mark live-validated once clean.
4. **Skills** (after validation) — 3 `SKILL.md` under `skills/intune/`: a device-compliance
   posture skill, a coverage-gap skill (stale/non-compliant/unencrypted), and one that enriches
   the cross-platform triage (device → Intune state). Wire into personas if relevant.
5. **Docs** — Platform Integrations table + Architecture tree in CLAUDE.md, README status,
   user-guide support matrix + a workflow.

## CI / repo mechanics

- `uv sync --all-packages` picks up the new workspace member; the new contract tests run in the
  existing CI (offline, no creds). `.env.intune` stays gitignored (the existing `.env*` ignore
  covers it) — the secret-scan CI guards it.
- The Platform Integrations table gains an **Intune** row (Identity/Endpoint mgmt, Entra app auth,
  read: devices/compliance/policies, gated write: — ).

## Out of scope (YAGNI)

- **No gated writes.** Intune writes are remote wipe/retire/passcode-reset (very high impact); the
  value is the compliance/coverage read story. A future low-risk "force device sync" could be
  added later.
- No `core/` change, no new client, no new auth model.
- Tenable One (exposure/vuln mgmt) is the **next** server (#6) — a new category, pending an API key.

## Files touched (new server, per recipe)

| File | Change |
|---|---|
| `servers/intune-mcp/pyproject.toml`, `README.md`, `.env.intune.example` | new — scaffold |
| `servers/intune-mcp/f0_intune_mcp/{__init__,server,tools}.py` | new — 6 read tools |
| `servers/intune-mcp/tests/test_tools.py` | new — contract tests (mock Graph) |
| `evals/intune/tasks.yaml` | new — eval task set |
| `evals/test_eval_coverage.py`, `evals/run.py` | add `intune` to SERVERS / SERVER_MODULES |
| `scripts/live_smoke_intune.py` | new — live validation |
| `skills/intune/*` (after validation) | new — 3 skills |
| `CLAUDE.md`, `README.md`, `docs/user-guide/*` | Platform table, tree, status, workflow |
