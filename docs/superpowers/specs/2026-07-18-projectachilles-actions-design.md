# ProjectAchilles Actions Server (Gated Writes) — Design

**Date:** 2026-07-18
**Status:** Approved (brainstormed with James; sub-project B of the ProjectAchilles integration)

## Overview

A second thin MCP server, `servers/projectachilles-actions-mcp/` (FastMCP name
`f0-pa-actions`), exposing **gated write actions** against ProjectAchilles:
run a validation test now, schedule one, pause/resume a schedule, cancel a
pending task — plus the two reads needed to drive those safely. The existing
read server (`projectachilles-mcp`) is at the 8-tool small-model ceiling and
is **not modified**.

This is the second consumer of `core/gating` (after Defender
`isolate_host`/`release_host`) and requires **no `core/` changes**.

## Goals

- Let an operator-supervised agent close the validation loop: find a weak
  technique (read server) → run/schedule the covering test (this server) →
  verify the result landed (read server `list_test_executions`).
- Prove the flag + single-use-token + audit gate pattern generalizes beyond
  Defender.
- Stay small-model-safe: flat scalar args, closed enums, guided server-side
  resolution of everything the backend payload needs.

## Non-Goals (explicitly out of scope)

- Schedule **delete**, task delete, raw **command** tasks, agent uninstall —
  these require admin-only permissions that `pa_` API keys can never
  synthesize (operator role ceiling).
- Fleet-wide targeting (multi-agent runs/schedules). v1 targets exactly one
  agent per call.
- Multi-day weekly schedules (single `day` enum only).
- LimaCharlie isolate-sensor or any other platform's writes.

## Auth Facts (verified in PA backend source)

- `acceptApiKey` middleware (global) validates `Authorization: Bearer pa_…`
  and synthesizes a Clerk-shaped identity. **read-write scope → `operator`
  role**; read-only scope → `READ_ONLY_PERMISSIONS`.
- Operator includes: `endpoints:tasks:read/create/cancel/notes`,
  `endpoints:schedules:read/create/write`, `tests:builds:read`,
  `tests:library:read`, `endpoints:agents:read`.
- Operator does NOT include: `endpoints:schedules:delete`,
  `endpoints:tasks:delete`, `endpoints:tasks:command`,
  `endpoints:agents:delete`.
- `org_id` is required in create bodies; `validateRequestOrgId` (tasks)
  rejects a mismatch with the key's org. The server resolves `org_id` from
  the target agent's record (agents carry `org_id`).
- **Live-validation prerequisite:** the `.env.projectachilles` key must be
  **read-write scope**; a read-only key 403s on every write (mapped to a
  `permission_missing` finding with a "issue a read-write pa_ key" hint).

## Architecture

```
servers/projectachilles-actions-mcp/
  pyproject.toml                      # deps: f0-sectools-core, mcp, httpx
  README.md
  f0_pa_actions_mcp/
    __init__.py
    client.py      # PA REST client: get + NEW post/patch (same Bearer/httpx pattern)
    resolve.py     # guided resolution: test_id -> (test_name, binary_name); hostname -> (agent_id, org_id)
    tools.py       # 6 tools returning list[Finding]; gate consulted AFTER resolution
    server.py      # FastMCP registration, redact_obj at the boundary, GatedAction wiring
  tests/
    test_tools.py, test_resolve.py, test_gating.py, test_client_errors.py
```

Shares `.env.projectachilles` (same platform → same credential file;
per-platform isolation intact). `ProjectAchillesConfig.allow_write`
(`PROJECTACHILLES_ALLOW_WRITE`, already implemented, currently unused)
becomes the gate flag.

Client extension: `post(path, json)` and `patch(path, json)` alongside the
existing `get` — same `httpx.AsyncClient`, same `/api` prefixing, same error
surface. The read server's client is not touched; the actions server gets its
own copy of the thin client (≈40 lines) rather than a cross-server import,
matching the thin-server pattern (servers import `core/`, never each other).

## Tool Surface (6 tools)

| Tool | Type | Backend call |
|---|---|---|
| `run_test(test_id, hostname, confirmation_token="")` | GATED | `POST /agent/admin/tasks` |
| `schedule_test(test_id, hostname, schedule, run_time, run_date="", day="", day_of_month=0, confirmation_token="")` | GATED | `POST /agent/admin/schedules` |
| `set_schedule_status(schedule_id, status, confirmation_token="")` | GATED | `PATCH /agent/admin/schedules/:id` |
| `cancel_task(task_id, confirmation_token="")` | GATED | `POST /agent/admin/tasks/:id/cancel` |
| `list_schedules(status="")` | read | `GET /agent/admin/schedules` |
| `get_task_status(task_id)` | read | `GET /agent/admin/tasks/:id` |

Enum params are `Literal[...]` from day one (roadmap item 2 applied here, not
retrofitted):

- `schedule: Literal["once", "daily", "weekly", "monthly"]`
- `status` (set_schedule_status): `Literal["active", "paused"]`
  (pause = the "unschedule" verb; resume = back to active)
- `day: Literal["", "monday", "tuesday", "wednesday", "thursday", "friday",
  "saturday", "sunday"]` (weekly only; `""` = unset)
- `list_schedules status`: `Literal["", "active", "paused", "completed"]`
  (`""` = all; small models emit `""` for optional args — treat as unset)

`run_time` is `"HH:MM"` 24h (validated by regex `^([01]\d|2[0-3]):[0-5]\d$`);
`run_date` is `"YYYY-MM-DD"` (once only); `day_of_month` is `int` 1–31
(monthly only; `0` = unset). Timezone is always `UTC` in v1 (stated in the
tool description).

### schedule_config mapping (flat args → backend union)

The backend's `schedule_config` is a Zod union of four strict shapes. The
server builds the right member from the flat args:

| `schedule` | required extra | payload |
|---|---|---|
| `once` | `run_date` | `{"date": run_date, "time": run_time}` |
| `daily` | — | `{"time": run_time}` |
| `weekly` | `day` | `{"days": [dow], "time": run_time}` (dow: monday=1 … saturday=6, sunday=0) |
| `monthly` | `day_of_month` | `{"dayOfMonth": day_of_month, "time": run_time}` |

A missing/extra type-specific arg (e.g. `schedule="weekly"` with no `day`,
or `run_date` set with `schedule="daily"`) → graceful guidance finding,
**before** the gate is consulted (no token burned).

## Guided Resolution (resolve.py)

The model supplies only `test_id` + `hostname`. Before the gate:

1. **Test:** `GET /browser/tests/{test_id}` (fallback: `GET /browser/tests?search=`,
   same as read server `get_test`) → `test_name`, metadata block
   (category/severity/techniques/... passed through as the task `metadata`).
   Unknown id → "test not found" finding.
2. **Build:** `GET /tests/builds/{test_uuid}` → `data.exists` +
   `data.filename`. `exists: false` (NOTE: 200 with exists:false, not a 404)
   → "test not built — build it in the PA console first" finding.
   `binary_name` = `data.filename`.
3. **Agent:** `GET /agent/admin/agents` → exact (case-insensitive) hostname
   match. 0 matches → "no agent with hostname X" finding; >1 → finding
   listing the candidates. Exactly 1 → `agent_id`, `org_id`.

Resolution failures return findings without consulting the gate, so the
model gets actionable feedback without burning an operator token.

## Gating Flow

Identical three-step pattern to Defender:

1. **Flag off** → GateDenied → finding: "action disabled; set
   PROJECTACHILLES_ALLOW_WRITE=true".
2. **Flag on, no token** → **intent finding** (`finding_type: action_result`,
   severity `info`): fully-resolved description (test name, hostname,
   agent id, schedule text) + the exact operator command:
   `python scripts/confirm_action.py <action> "<target>" --platform projectachilles`.
   No API call.
3. **Flag on + valid token** → execute via
   `GatedAction.execute_async`, audit-record (action, target, actor,
   token hash prefix) to the local audit log.

**Token target strings** (token bound to `(action, target)`; printed
verbatim in the intent finding):

| Action | Target string |
|---|---|
| `projectachilles.run_test` | `<test_uuid>@<hostname>` |
| `projectachilles.schedule_test` | `<test_uuid>@<hostname>` |
| `projectachilles.set_schedule_status` | `<schedule_id>:<status>` |
| `projectachilles.cancel_task` | `<task_id>` |

A token issued for one host/test/status cannot authorize another.
`scripts/confirm_action.py` already supports `--platform projectachilles`;
no changes needed.

## Findings

All tools return `list[Finding]`, redacted at the server boundary
(`redact_obj(f.model_dump())`), exactly like every other server.

- Intent findings: `finding_type=action_result`, `recommended_action.gated_action`
  set to the action name, evidence = resolved facts + operator command.
- Execution results: task/schedule id, status, next_run_at (schedules) as
  evidence; `recommended_action.summary` points at the follow-up read
  (`get_task_status` after run_test; `list_test_executions` on the read
  server once completed).
- `get_task_status` severity: `info` for pending/assigned/downloading/
  executing/completed, `medium` for failed/expired.
- `list_schedules`: one finding per schedule (id, name, test_name, type,
  status, next_run_at), bounded to 50.

## Error Handling

The actions server carries its own thin `errors.py` following the same
recipe as the read server's `map_pa_error` (servers never import each other;
error mapping is per-server adapter code), extended for writes — every
failure becomes a finding, never an exception:

- `401` → auth posture finding (existing behavior).
- `403` → `Finding.permission_missing` + hint: "pa_ key lacks write scope —
  issue a read-write key".
- `404` (task/schedule id) → not-found finding.
- `400` (validation, terminal-task cancel) → backend message wrapped as a
  finding.
- `429` → rate-limited finding; `502/503/504` → API-unavailable posture
  finding.

## Testing

### Layer A — contract tests (fake client, tmp-path token store + audit log)

- Findings shape + schema validation + redaction for all 6 tools.
- **Gate negative-space tests** (the core of the suite): flag off → denied
  finding AND zero calls recorded on the fake client; no token → intent
  finding AND zero calls; wrong-target/expired/reused token → denied;
  valid token → exactly one `post`/`patch` recorded AND one audit line.
- Resolution edges: unknown test, unbuilt test (`exists:false`), hostname
  0/2 matches, schedule-arg mismatches — each graceful, gate never
  consulted.
- Error mapping per status code.

### Layer B — evals

`evals/projectachilles-actions/tasks.yaml`, ≥1 task per tool, analyst
phrasing ("run the T1110 brute-force test on host sbl7203", "pause the
nightly schedule"). Register in `evals/test_eval_coverage.py` `SERVERS` and
`evals/run.py` `SERVER_MODULES`. Bump `evals/test_combined.py`: union tool
count 38 → 44; per-server task-count assertion + comment. This server is the
measurement vehicle for the open Gemma-12B gated-write callability question.

### Smoke script

`scripts/live_smoke_projectachilles_actions.py`: reads run normally; gated
tools exercised through the **intent stage only** by default; `--execute`
flag for a full token-in-hand pass. Live validation is user-gated and needs
a read-write key.

## Skill

One new `skills/projectachilles/run-validation-test/SKILL.md`: when to run
vs schedule, the two-step token flow, pitfalls (test must be built; one host
per call; UTC times; pause not delete). `cross-platform/validation-coverage-loop`
gets a cross-reference, not a copy (Rule 9).

## Docs

- CLAUDE.md: architecture tree + Platform Integrations row (PA gated-write
  column: "run test, schedule test, pause/resume schedule, cancel task").
- README status; user-guide support matrix + a short workflow.
- `.env.projectachilles.example`: `PROJECTACHILLES_ALLOW_WRITE` + read-write
  scope note.

## Milestones

1. Scaffold + client (get/post/patch) + config wiring.
2. resolve.py + contract tests.
3. Gated tools + gate tests.
4. Read tools (list_schedules, get_task_status).
5. Server registration + redaction boundary.
6. Evals + combined-count bumps.
7. Smoke script + skill + docs.
8. Live validation (user-gated; needs read-write key).
