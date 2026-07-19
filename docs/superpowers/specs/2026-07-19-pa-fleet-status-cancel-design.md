# PA fleet status & cancel — design

**Date:** 2026-07-19
**Servers:** `projectachilles-mcp` (read) + `projectachilles-actions-mcp` (actions)
**Depends on:** fleet-by-tag runs (PR #41), bundle-results rollup (PR #38), gating approvals + chat-confirm (#33/#35/#37)

## Problem

Two symptoms observed in live testing of fleet (tagged) test runs:

1. **Phantom host in results.** Asking for a run's results sometimes surfaces a
   host that was never part of that execution/schedule.
2. **N tool calls for N hosts.** Asking for task status, results, or cancel on a
   multi-host run makes one tool call *per host/task* (e.g. "cancel all 5 pending"
   → 5 `cancel_task` calls) instead of one parameterized call.

### Root cause

Both are one architectural gap: **a fleet run has no first-class identity after
launch, and the follow-up tools cannot scope to a run.**

- `run_test`'s fan-out (`POST /agent/admin/tasks` with `agent_ids[]`) returns a
  flat `data.task_ids` array — **no parent/batch id in the response.**
- `list_test_executions` (read server) queries `/analytics/executions/paginated`
  with only `from/to/pageSize` — a **tenant-wide time window**, unscoped to any
  run, so unrelated recent hosts leak in. That *is* the phantom host.
- `get_task_status` and `cancel_task` operate on a **single `task_id`**, so the
  model holds the N task_ids in context and iterates — exactly the multi-step
  state juggling CLAUDE.md warns against.

## Backend contract (verified against PA source, not assumed)

Read from `~/F0RT1KA/ProjectAchilles/backend/src`:

**Tasks** (`api/agent/tasks.routes.ts`, `services/agent/tasks.service.ts`) —
admin router, `endpoints:tasks:read` / `:cancel`:

- `GET /admin/tasks` — filters `agent_id`, `org_id`, `status`, `type`,
  `search` (SQL `LIKE` over `payload.test_name` **and** `agents.hostname`),
  `limit` (default 50), `offset`. Returns `{success, data:{tasks:[…], total}}`.
- `GET /admin/tasks/grouped` — same filters, grouped by `batch_id`.
- `GET /admin/tasks/:id` — single task; row carries `batch_id`, `agent_hostname`,
  `status`, `result`, `payload`.
- `POST /admin/tasks/:id/cancel` — cancels **one** task (status → `expired`).
  **There is no batch-cancel endpoint.**
- `createTasks` mints one `batch_id = crypto.randomUUID()` per fan-out and stamps
  every task with it — but `batch_id` is **not a filter param** on either list
  endpoint, and is **not returned by the create response**.

**Executions** (`api/analytics.routes.ts`) —
`GET /analytics/executions/paginated` filters include **`tests`**, **`tags`**,
**`hostnames`**, `bundleNames`, `result`, `page`, `pageSize`, `sortField`,
`sortOrder`, `grouped`.

### Consequences for the design

- **Scope a run by `test` + `tag` + `status`** (all filterable) — *not* by
  `batch_id` (not filterable). This is better anyway: it matches the fleet-by-tag
  mental model, and it catches **schedule-fired** tasks (each schedule fire gets
  its own `batch_id`, so a batch handle would miss them).
- **Bulk cancel loops inside our tool.** No batch-cancel endpoint exists, so one
  MCP call → one confirmation → N per-task `POST /:id/cancel`. This is the same
  fan-out-inside-the-tool inversion `run_test` already uses.

## Scope

Fix both symptoms (read + cancel). Three changes across the two servers:

| Server | Change | Fixes |
|---|---|---|
| read `projectachilles-mcp` | `list_test_executions` gains `test`/`tag`/`hostname` scoping | phantom host + results-spam |
| actions `pa-actions` | new **read** `list_tasks(status, search, limit)` | task-status spam |
| actions `pa-actions` | `cancel_task` → **gated** `cancel_tasks` (single XOR filter, bulk) | cancel spam |

Net actions tool count: **6 → 7** (add `list_tasks`, rename+widen `cancel_task`
to `cancel_tasks`; `get_task_status` stays as the deep single-result view). Under
the ≤~8 ceiling.

### Rejected alternatives

- **Batch-handle (Approach B):** `run_test` recovers `batch_id`, follow-ups take
  it. Rejected — `batch_id` is not a filter param (would page `/grouped` to find
  ours), and it *misses schedule-fired tasks*, the opposite of the goal.
- **Status-only minimal (Approach C):** just `cancel_pending()` + bare
  `list_tasks`, no `test`/`tag` scoping, no executions fix. Rejected — leaves the
  phantom host unfixed.

## Out of scope (YAGNI)

- No batch-cancel *endpoint* work on the PA backend (not ours).
- No `batch_id` handle / run-id persistence (Approach B, rejected).
- No schedule-level cancel (`set_schedule_status` already covers schedules).
- No cross-server "fleet rollup" mega-tool.

---

## Component 1 — read: scope `list_test_executions`

**Files:** `servers/projectachilles-mcp/f0_projectachilles_mcp/{tools.py, server.py}`

Add three flat scalar scoping params; each non-empty one adds the matching filter
to the existing `params` dict, empty ones are omitted:

```python
async def list_test_executions(
    pa, days: int = 7, limit: int = 25,
    test: str = "",       # -> ?tests=     scope to one test (name/uuid)
    tag: str = "",        # -> ?tags=      scope to a fleet's tag
    hostname: str = "",   # -> ?hostnames= scope to one host
) -> list[Finding]:
```

Everything downstream is unchanged: the per-`(bundle, host)` rollup, the
`window_truncated` softening, the `more_not_shown` overflow, and the
security/hygiene vocabulary. Scoping only shrinks the input set.

**Server tool description** gains: *"Pass `test` (and/or `tag`/`hostname`) to
scope results to one run instead of a raw time window."*

**Charset guard:** `test`/`tag`/`hostname` validated against the existing bounded
charset (same `_TAG_RE`-style guard the tag path uses); a malformed value → a
pre-return guidance finding, never injected into the query string.

**Caveats (carried into the plan, not assumed away):**

- **`tests` = name or UUID?** Not assumed — live-validation checkpoint (step 9).
  Pass the caller's identifier through; pin the semantics live and document it.
- Scoping shrinks but does not abolish truncation — the existing
  `window_truncated` evidence remains the guard.

**No regression:** empty scoping params ⇒ payload byte-identical to today, so
current callers and tests are unaffected.

---

## Component 2 — actions read: `list_tasks`

**Files:** `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/{tools.py, server.py}`

Belongs on the actions server: `GET /admin/tasks` is on the same admin API and
key as the writes, alongside the existing admin reads (`get_task_status`,
`list_schedules`). Executions (analytics API) stay on the read server.

```python
async def list_tasks(pa, status: str = "", search: str = "", limit: int = 25) -> list[Finding]:
    # GET /admin/tasks?status=&search=&limit=  ->  {data:{tasks:[...], total}}
```

- `status` — short closed enum: `pending | assigned | running | completed |
  failed | expired` (empty = all). Task **lifecycle** state — distinct from
  execution *results*.
- `search` — LIKE over `test_name` + `hostname` (the backend's real search
  columns).
- Returns **one `info` posture finding per task**: title
  `"<test_name> on <host>: <status>"`, evidence `task_id`, `agent_hostname`,
  `created_at`. **Plus a summary count line** (e.g. `3 pending, 1 running`).
- Bounded at `limit` (default 25); `total` surfaced; empty result → clean empty
  list, not an error.

This is the "is the run still going / what's still pending" sweep — one call, N
per-host rows instead of N `get_task_status` calls.

---

## Component 3 — actions gated: `cancel_tasks`

**Files:** `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/{tools.py, server.py}`

Renames and widens `cancel_task`. Gated action name: `projectachilles.cancel_tasks`.

```python
async def cancel_tasks(
    pa, gate: GatedAction,
    task_id: str = "",         # single precise cancel  (XOR the filter)
    status: str = "pending",   # filter: which lifecycle state to cancel
    search: str = "",          # filter: narrow by test_name / hostname
    confirmation_token: str = "",
    actor: str = "mcp-operator",
) -> list[Finding]:
```

**Exactly one** of `task_id` **or** `(status/search)` — both/neither → a pre-gate
guidance finding, no token burned (same XOR pattern as `run_test`'s
`hostname`/`tag`).

**Flow (mirrors the fleet pattern):**

1. **Resolve the set first** (before the target):
   - `task_id` → set `= [task_id]`, `N = 1`.
   - filter → `GET /admin/tasks?status=&search=&limit=201` → the cap decision
     uses the response's `total` (full COUNT matching the filter, independent of
     `limit`); the cancel set is the returned `tasks` array. **`limit=201`
     (cap + 1) is deliberate:** it lets us both detect `total > 200` (refuse) and
     fetch the *entire* set up to the cap in one page — a default `limit=50` would
     silently undercount `N` and cancel only 50 of a larger pending set. `N = total`.
2. **Build the count-bound target:**
   - single: `target = task_id`
   - bulk: `target = f"cancel:{status}:{search or '*'}:{N}"` — **N baked in**,
     whole-string compared (never split on `:`).
3. **No token / no approval →** `gate.record_request(target)` + intent finding
   listing matched tasks (≤15 + "K more") and the total count.
4. **Execute →** `gate.execute_async(target=, actor=, token=, run=…)` where `run`
   **loops** `POST /admin/tasks/:id/cancel` over the set and aggregates.

**Drift-catch (free, no `core/gating` change):** every MCP call re-runs the
function top-to-bottom, so the execute call re-enumerates. A pending task
finishing between preview (N=5) and approval yields execute-time target
`cancel:pending:*:4`, which no longer matches the `…:5` token/approval → the gate
refuses the stale token and asks to re-preview. Same-size swap (5→5, one task
swapped) is **not** caught — deliberate, for lower friction; documented.

**Aggregate `run` — cancel is racy:** each per-task cancel is wrapped; tally
`cancelled` / `already_terminal` / `failed`; never throw the whole batch on one
bad task. An **auth/permission error on the first call** short-circuits to a clean
permission finding (no partial loop). Returns **one** summary `action` finding:
`"Cancelled X of N tasks (Y already finished, Z failed)"`, evidence ≤15 rows +
"K more".

**Blast-radius cap:** bulk cancel refuses when the matched set **> 200** ("narrow
with `search`"). The decision uses the response `total`; reuse the fleet-launch
coercion guard so a non-int `total` can't bypass the cap (coerce to usable int
else fall back to `len(tasks) >= 200`). The cap check runs **before** any cancel
is issued, and — because the enumeration pages at `limit=201` — `N` reflects the
full matched set, not a truncated page.

**Chat-confirm:** allowed for `cancel_tasks`, count-bound. `confirm_mode` is
server-wide; cancelling a *pending* validation task is low-harm and reversible
(re-run), **not** in CLAUDE.md's never-chat-confirm list (isolate/disable/
quarantine/close/delete), and strictly less dangerous than the fleet-*launch*
already kept on chat-confirm. The not-single-use / no-TTL chat caveat carries over
verbatim.

---

## Safety (cross-cutting — routed through existing `core/` machinery, Rule 6)

- **Errors → findings, never exceptions.** Both new tools use `map_pa_error(e,
  capability)` (auth → posture, `403` → `permission_missing`, `429` →
  `rate_limited`, gateway → "API unavailable"). Post-gate failures use the
  existing `_after_gate_error(...)` path. The `cancel_tasks` per-task loop catches
  locally (see Component 3).
- **Redaction (Rule 3).** Nothing new: output returns through the server's
  `_render` → `redact_obj(f.model_dump())` boundary, including every error path.
  Backend already strips `env_vars` via `sanitizeTaskForAdmin`; redaction is the
  second pass.
- **Output bounding (Rule 5).** `list_test_executions`: unchanged
  (`limit` 25, `window_truncated`, `more_not_shown`). `list_tasks`: `limit` 25,
  `total` surfaced, summary count line. `cancel_tasks`: 200 hard cap, ≤15-row
  intent/result, one summary finding.
- **Small-model surface (Rule 5).** All new args flat scalars; `status` a 6-value
  closed enum; `cancel_tasks` `task_id` XOR filter reuses the validated
  `run_test` host/tag pattern (both/neither → guidance). Descriptions written for
  the model (when-to-use + returns + the "exactly one of" rule). `search`/`test`/
  `tag`/`hostname` charset-guarded pre-gate.

---

## Testing

### Layer A — contract tests (mandatory, mocked, deterministic)

| Area | Cases |
|---|---|
| `list_test_executions` scoping | empty params → payload byte-identical to today; `test`/`tag`/`hostname` each add the right query param; phantom-host repro: two tests in the mock, `test=X` returns only X's hosts |
| `list_tasks` | shape + status enum; `search` passthrough; per-task findings + summary count; `limit` bounding + `total` surfaced; empty result → clean empty |
| `cancel_tasks` single | `task_id` → target == `task_id`, N=1; refuses without flag; refuses without valid token |
| `cancel_tasks` bulk | filter → target `cancel:pending:*:N`; **drift**: intent N=5, task completes, execute re-enumerates N=4 → target mismatch → refused, token spent; **200 cap** incl. non-int `total`; **no undercount**: filter matching 60 tasks → all 60 cancelled (not truncated to a 50-page); both/neither of `task_id`/filter → pre-gate guidance, no token burned |
| `cancel_tasks` loop | one per-task cancel 5xx → batch continues, tallied `failed`; first-call `403` → clean permission finding, no partial loop |
| redaction | secret/`env_vars` stripped from `list_tasks` output and cancel error paths |

### Layer B — eval tasks

Add ≥1 task per new tool to `evals/projectachilles/tasks.yaml`:
- "show me what's still pending for the acme run" → `list_tasks`
- "cancel all pending tests" → `cancel_tasks`
- "results for test X on the windows fleet" → scoped `list_test_executions`

Watch the combined-registry scorecard for description collisions (#2.5 pattern);
likely confusion pairs `list_tasks`↔`list_schedules`, `cancel_tasks`↔`run_test` —
anchor descriptions if they mis-route.

### Live-validation checklist (user-gated, on pi — step 9, "live API is truth")

1. `?tests=` — matches `test_name` or `test_uuid`? Pin + document.
2. `list_tasks` per-host rows for a real fleet run — hostnames all populated?
3. Bulk `cancel_tasks(status=pending)` on a real fleet → count-bound preview, N
   cancels, drift re-approval when a task finishes mid-flight.
4. Scoped `list_test_executions(test=…, tag=…)` → phantom host gone.

---

## Skills & docs (Rule 9 — authored once)

- `skills/projectachilles/run-validation-test/SKILL.md` — add a "checking &
  cancelling a run" step: scope results with `test`/`tag`, sweep lifecycle with
  `list_tasks`, bulk-cancel with `cancel_tasks` (count-bound, same confirm flow).
- `servers/projectachilles-actions-mcp/README.md` — tool table
  (`cancel_task`→`cancel_tasks`, +`list_tasks`), 200 cap, count-bound +
  same-size-swap caveat, chat-confirm note.
- `servers/projectachilles-mcp/README.md` + `list_test_executions` description —
  the new scoping params.
- **CLAUDE.md** — actions-server line: "6 tools" → "7 tools"
  (`cancel_task`→`cancel_tasks`, +`list_tasks`).
- **Runtime templates** — no server added/removed, so `integrations/pi/mcp.json`
  and `integrations/hermes/config.example.yaml` need no change; run
  `integrations/test_integrations_valid.py` to confirm.
