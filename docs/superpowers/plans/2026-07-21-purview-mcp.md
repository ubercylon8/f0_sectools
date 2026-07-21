# purview-mcp Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build server #8 per `docs/superpowers/specs/2026-07-21-purview-mcp-design.md` — read-only Purview data-risk tools over Microsoft Graph.

**Architecture:** Identical to the 7 existing servers (tenable-mcp/intune-mcp are the closest templates: async httpx Graph/REST client from `core/`). TDD each step.

## Global Constraints

- 6 tools exactly as specified (flat scalars, bounded output, findings schema).
- Every failure → finding, never an exception; redact at the boundary.
- `serviceSource` enum values and the beta labels path are ASSUMPTIONS until the live smoke confirms them — mark with comments and validate in step 9.
- New env prefix `PURVIEW`; `.env.purview.example` documents `AuditLogsQuery.Read.All` + the labels permission.

### Task 1: Config
- [ ] `PurviewConfig` alias in `core/auth/config.py` (`from_env(prefix="PURVIEW")`) + test in `core/tests/test_config.py`. Commit.

### Task 2: Scaffold
- [ ] `servers/purview-mcp/` (pyproject `f0-purview-mcp` script, README, `.env.purview.example`, package, tests dir); `uv sync --all-packages`. Commit.

### Task 3: Client + errors (TDD)
- [ ] `client.py`: GraphClient-based; methods `list_alerts(service_source, start_iso, top)`, `create_audit_query(...)`, `get_audit_query(id)`, `list_audit_records(id, top)`, `list_sensitivity_labels()` (beta path). `errors.py`: `map_purview_error` (401/403 → permission_missing, 429 → rate_limited, 5xx → unavailable). Contract tests w/ fake transport. Commit.

### Task 4: Tools (TDD, contract tests first)
- [ ] `get_dlp_summary`, `list_dlp_alerts` (severity_min Literal), `list_insider_risk_alerts`, `list_sensitivity_labels`, `search_audit_log` (submit+poll ≤50s → records or query-id finding), `get_audit_results`. Empty-string args = unset; charset guards on `activity`/`user`/`audit_query_id`; bounded lists + "more available". Commit.

### Task 5: Server
- [ ] `server.py` FastMCP `f0-purview`, one wrapper per tool, redact at boundary; schema test (Literal enums advertised). Commit.

### Task 6: Evals + combined counts
- [ ] `evals/purview/tasks.yaml` (≥1/tool, ~8 tasks); add to `SERVERS` in `evals/test_eval_coverage.py` + `SERVER_MODULES` in `evals/run.py`; bump `test_combined` tool-union (45→51) and task counts (83→91) and server list. Commit.

### Task 7: Smoke + runtime wiring + docs
- [ ] `scripts/live_smoke_purview.py`; wire into `integrations/pi/mcp.json`, both Hermes configs, `opencode.json` (drift guards enforce); CLAUDE.md table+tree, user-guide matrix, CHANGELOG. Full `pytest`+ruff+mypy. Commit.

### Task 8: Live validation (needs operator: `AuditLogsQuery.Read.All` granted + `.env.purview`)
- [ ] Run smoke with network; fix-forward field/shape mismatches (serviceSource enums, beta labels path/permission, audit latency). Mark live-validated. Commit fixes.

### Task 9 (post-validation): Skills
- [ ] `skills/purview/{data-risk-review,dlp-alert-triage,audit-investigation}` + skills test; opencode symlinks (+drift guard); persona wiring; user-guide workflows. Commit.
