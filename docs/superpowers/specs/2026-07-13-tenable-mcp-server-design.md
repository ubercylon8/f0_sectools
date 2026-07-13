# tenable-mcp — Platform Server #6 Design

**Status:** Approved (brainstorming) — ready for implementation plan.
**Date:** 2026-07-13
**Author:** James Pichardo + Claude

## Goal

Add `tenable-mcp`, the sixth f0_sectools platform server: a thin, **read-only**
Model Context Protocol server over **Tenable Vulnerability Management** (formerly
Tenable.io) that lets a small local model assess vulnerability exposure, prioritize
remediation, and enumerate a specific host's vulnerabilities — returning the
normalized findings schema through the shared `core/` safety layer.

## Non-Goals

- **No write actions.** Tenable is read-only in the Platform Integrations roadmap;
  no `core/gating` wiring at all.
- **No Exports API.** The async, bulk `/vulns/export` + `/assets/export` flow is
  wrong for interactive tool-calling. We use the synchronous, bounded **Workbenches**
  endpoints. (Revisit only if a future skill genuinely needs >5,000-row bulk pulls.)
- **No `core/` changes.** Like the four prior servers, `core/` is unchanged except
  adding one `TenableConfig` dataclass (the established per-platform pattern).
- Not covering Web App Scanning, Cloud Security, or Tenable.sc/Nessus in this server.

## Context & Precedent

This is the **fifth replication of the identical thin-server pattern**
(`defender`, `entra`, `limacharlie`, `projectachilles`, `intune`). The direct
template is **`projectachilles-mcp`**: static-key REST, async `httpx`, a single
`get(path, params)` helper, tools returning `list[Finding]`, errors mapped to
graceful findings. Follow the "Adding a New Platform Server" recipe in `CLAUDE.md`.

## Platform Facts (Tenable VM)

- **Base URL:** `https://cloud.tenable.com` (configurable).
- **Auth header:** `X-ApiKeys: accessKey=<ACCESS_KEY>;secretKey=<SECRET_KEY>`.
- **Surface:** Workbenches endpoints —
  - `GET /workbenches/vulnerabilities` — recorded vulnerabilities (≤5,000 rows,
    ≤450 days), per-plugin with severity + affected count. Supports `date_range`
    and `filter.N.*` query filters (`GET /filters/workbenches/vulnerabilities`
    lists available filters).
  - `GET /workbenches/assets` / `GET /workbenches/assets/vulnerabilities` — assets,
    optionally with vuln counts (≤5,000).
  - `GET /workbenches/assets/{uuid}/vulnerabilities` — one asset's vulnerabilities.
  - `GET /workbenches/vulnerabilities/{plugin_id}/info` — plugin detail (CVSS, VPR,
    description, solution, CVEs).
  - `GET /scans` — scan inventory + status + last-run.
- **Severity:** integer `0–4` = info / low / medium / high / critical → maps directly
  to our `Severity` enum.
- **VPR** (Vulnerability Priority Rating) is Tenable's prioritization score — used to
  rank "fix first".

> Exact response field names and the summary-endpoint-vs-client-aggregation choice
> are confirmed at **live validation** (recipe step 9) — mocks encode assumptions,
> live data is truth. Expect 1–3 field-name fix-forwards.

## Architecture

```
servers/tenable-mcp/
  pyproject.toml                 # deps: f0-sectools-core, mcp, httpx
  README.md                      # required scopes/keys, tool list
  .env.tenable.example           # TENABLE_ACCESS_KEY / _SECRET_KEY / _BASE_URL / _VERIFY_TLS
  f0_tenable_mcp/
    __init__.py
    client.py                    # async httpx, X-ApiKeys header, get(path, params)
    errors.py                    # map_tenable_error -> graceful Finding
    tools.py                     # 6 flat read tools -> list[Finding]
    server.py                    # FastMCP; redact at boundary
  tests/
    test_tools.py                # contract tests (fake client)
```

`core/` gets only: **`TenableConfig`** in `core/auth/config.py` + a test in
`core/tests/test_config.py`.

### Config — `TenableConfig`

Dataclass + `from_env(prefix="TENABLE")`.

- **Required:** `TENABLE_ACCESS_KEY`, `TENABLE_SECRET_KEY`.
- **Optional:** `TENABLE_BASE_URL` (default `https://cloud.tenable.com`),
  `TENABLE_VERIFY_TLS` (default `true`).
- **No `allow_write`** (read-only server).
- Secrets never logged; missing-var error names the variables, not values.

### Client — `client.py`

- `httpx.AsyncClient(verify=config.verify_tls, timeout=60.0, headers={"X-ApiKeys": f"accessKey={access};secretKey={secret}"})`.
- `async get(path, params=None) -> dict` — GETs `{base_url}{path}`; non-2xx raises
  `TenableError(status, message)` with `redact_text(message)`.
- `__aenter__` / `__aexit__` to close the client.

### Errors — `errors.py`

`map_tenable_error(e: TenableError, capability: str) -> Finding`:

| Status | Finding |
|---|---|
| 401 | auth/posture finding ("check API keys") |
| 403 | `Finding.permission_missing(capability)` |
| 429 | `Finding.rate_limited(capability)` |
| 502 / 503 / 504 | posture finding ("Tenable API unavailable") |
| other | re-raise (unexpected) |

Every mapped failure is a **Finding, never an exception** surfaced to the model.

## The 6 Tools

All args flat scalars / short closed enums; output bounded + paginated; each tool
catches `TenableError` → graceful finding (else re-raise); defensive dict access.
`severity_min` enum is `low | medium | high | critical` everywhere it appears.

| # | Tool | Args | Returns |
|---|---|---|---|
| 1 | `get_vulnerability_summary` | — | 1 `posture` Finding — env-wide counts by severity (entity: tenant); evidence = per-severity counts; severity = worst present |
| 2 | `list_top_vulnerabilities` | `severity_min="high"`, `limit=10` | N `misconfig`/`risk` per plugin, sorted by severity then VPR; evidence = affected_hosts, VPR, CVSS; references = CVE(s), plugin_id |
| 3 | `list_assets` | `hostname=""`, `severity_min=""`, `limit=25` | N `posture` per asset (entity: host); evidence = last_seen, severity counts |
| 4 | `get_asset_vulnerabilities` | `asset`, `severity_min="high"`, `limit=25` | N per vuln on ONE host; `asset` resolves UUID-or-hostname/ip (see below); references = CVE(s) |
| 5 | `get_vulnerability_info` | `plugin_id` | 1 detailed `misconfig` — CVSS/VPR, description, remediation; references = CVEs, plugin_id |
| 6 | `list_scans` | `limit=25` | N `posture` per scan — name, status, last-run freshness |

### Asset resolution (tool 4)

Operators think in hostnames; Tenable keys assets by UUID. `get_asset_vulnerabilities`
takes a single flat `asset: str`:

- If `asset` matches a UUID shape → use directly against
  `/workbenches/assets/{uuid}/vulnerabilities`.
- Else → resolve via an assets lookup filtered by hostname/ipv4, take the first
  match, then fetch its vulnerabilities. If no match → a single `posture` Finding
  ("no asset matches '<asset>'"), not an exception.

This keeps the argument small-model-safe (one string, not "supply a UUID").

### Findings mapping (all tools)

- `severity`: Tenable `0–4` → `Severity` (`info/low/medium/high/critical`).
- `source`: `"tenable"`.
- `recommended_action.gated_action`: always `null` (read-only).
- `observed_at`: asset `last_seen` / vuln `last_found` when present, else omitted.
- `references`: CVE ids (`type: "cve"`) and `plugin_id` (`type: "tenable_plugin"`).

## Server — `server.py`

`FastMCP`, one `@mcp.tool()` per tool, build `TenableClient` from
`TenableConfig.from_env()`, **redact at the boundary**: every returned finding via
`redact_obj(f.model_dump())`. Tool docstrings written for a model (one sentence:
when to use + what it returns), platform-anchored to avoid cross-server collisions
(the #2.5 disambiguation pattern — e.g. "Tenable vulnerability…").

## Skills (recipe step 10)

Three portable `SKILL.md` under `skills/tenable/`, following the established
posture / investigation / platform-native trio. Tools referred to by base name.

1. **`exposure-posture-review`** ⭐ **default focus** —
   `get_vulnerability_summary` → `list_top_vulnerabilities` → `list_scans` (scan
   freshness caveat on the posture claim). CISO / security-engineer lens.
2. **`host-vulnerability-triage`** — resolve host via `list_assets` →
   `get_asset_vulnerabilities` → `get_vulnerability_info` on the worst findings.
   SOC-analyst / security-engineer lens. (Covers the per-host enumeration ask.)
3. **`scan-coverage-review`** — `list_scans` → `list_assets` to surface stale /
   unscanned coverage gaps. Security-engineer operational lens.

Each `SKILL.md`: valid frontmatter (`name`, `description` ≤60 chars, `version`),
`## When to Use / Procedure / Pitfalls / Verification`. Enforced by
`skills/test_skills_valid.py`.

**Persona wiring (Hermes):** `exposure-posture-review` favored by the
security-engineer and CISO personalities.

## Testing & Evaluation

### Layer A — Contract tests (mandatory, written first)

`servers/tenable-mcp/tests/test_tools.py`, fake client:

- Each tool returns correctly-shaped findings (schema validation).
- **Redaction** strips secrets/PII on output **and** error paths.
- `limit` bounds and pagination behave on large mocked result sets.
- 401 / 403 / 429 / 5xx each yield a graceful finding, never an exception.
- Asset resolution: UUID path, hostname path, and no-match path.

### Layer B — Evals

- `evals/tenable/tasks.yaml` — ≥1 task per tool (natural-language → expected tool).
- Register `tenable` in `evals/test_eval_coverage.py` `SERVERS` and
  `evals/run.py` `SERVER_MODULES`. Combined registry grows **28 → 34 tools**;
  re-run the scorecard afterward and watch for description collisions (the
  composition-cost pattern from Intune).

### Smoke + live validation

- `scripts/live_smoke_tenable.py` (+ `--persona` flag, matching the other servers).
- **Live validation is user-gated:** the user creates `.env.tenable` at repo root
  (gitignored), Claude runs the smoke script with network on, and we fix-forward
  the field-name/endpoint mismatches live data reveals. Mark live-validated once
  clean.

## Docs (recipe step 11)

Update: `CLAUDE.md` Platform Integrations table + Architecture tree + skills list;
`README.md` status; user-guide support matrix + a Tenable workflow.

## Build Order (recipe)

1. `TenableConfig` + test → 2. scaffold server → 3. `client.py` → 4. `errors.py`
→ 5. `tools.py` (contract tests first) → 6. `server.py` (redact at boundary)
→ 7. evals → 8. smoke script → 9. **live validation (user-gated)** → 10. skills
→ 11. docs → 12. verify (`pytest`, `ruff`, `mypy`) + commit.

## Risks / Open Questions (resolved at live validation)

- Exact `/workbenches/*` response field names (`plugin_id` vs `plugin`, severity
  count key names, `last_seen` vs `last_observed`).
- Whether a native vulnerability-summary endpoint exists or we aggregate
  `/workbenches/vulnerabilities` client-side.
- Scan freshness field (`last_modification_date` vs `last_run`).
