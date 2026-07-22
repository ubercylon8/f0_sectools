# f0-pa-actions — ProjectAchilles gated write actions (MCP server)

Companion to `servers/projectachilles-mcp/` (read-only). This server exposes
the **write** side of the validation loop, every write gated by
`core/gating` (operator flag + per-action human confirmation
(forge-resistant token/watcher, or opt-in chat-confirm) + local audit):

| Tool | Type |
|---|---|
| `run_test(test_id, hostname, tag)` | GATED — execute a validation test now, on ONE host (`hostname`) or a FLEET (`tag` — every agent carrying it) |
| `schedule_test(test_id, hostname, schedule, run_time, …, tag)` | GATED — recurring/once schedule (UTC), on ONE host or a FLEET (`tag`) |
| `set_schedule_status(schedule_id, status)` | GATED — pause/resume |
| `cancel_tasks(task_id \| status, search)` | GATED — cancel ONE task (`task_id`) or a BULK sweep of matching tasks (`status`/`search` filter, count-bound confirmation) |
| `list_schedules(status)` | read |
| `get_task_status(task_id)` | read — one-shot; returns the run outcome (bundle rollup or single-test pass/not-passed) on completion |
| `list_tasks(status, search)` | read — admin task list with lifecycle status; one call, N per-host rows — the fleet-aware alternative to N `get_task_status` calls |

`run_test`/`schedule_test` take **exactly one** of `hostname` (single exact
agent) or `tag` (fleet — every agent currently carrying that tag, fanned out
in one gated action). The no-token intent preview lists matched hosts (up to 15, with an "N more"
marker) and the total count; the confirmation is **bound to that host count**,
so if the count changes before approval you must re-preview and re-confirm.
A same-size membership swap (one host gains the tag, another loses it) is not
caught—deliberate, for lower friction. A tag matching more than 200 hosts is
refused — narrow it.
Per-host results after a fleet run: `list_test_executions` on the read
server, which groups a bundle run into one COMPLIANT/NON-COMPLIANT finding
per host (`get_task_status` here is one task id at a time).

`cancel_tasks` takes **either** `task_id` (cancel one task) **or** a bulk
`status`/`search` filter — never both. Bulk mode resolves the filter against
`GET /agent/admin/tasks` first (PA has no batch-cancel endpoint, so the tool
loops per-task under one gated action) and binds confirmation to the match
**count**, encoded in the confirmation target as `cancel:<status>:<search>:<N>`
(e.g. `cancel:pending:*:42`). A filter matching more than 200 tasks is refused
outright — narrow it with `search`. As with fleet `run_test`/`schedule_test`,
a same-size membership swap between preview and approval (one task finishes,
another becomes pending) is not caught — deliberate, for lower friction; if
you suspect drift, re-preview. `list_tasks` is the read-only way to check
what a filter would match before cancelling. `cancel_tasks` allows
chat-confirm like the other gated actions here — the same not-single-use /
no-TTL caveat in the Confirmation modes section below applies.

## Setup

Shares `.env.projectachilles` with the read server (same platform, same
credential file). Two extra requirements for writes:

1. The `pa_` API key must be **read-write scope** (a read-only key 403s on
   every write — you get a permission finding telling you so).
2. `PROJECTACHILLES_ALLOW_WRITE=true` must be set.

Executing a gated action is two-step: call the tool without
`confirmation_token` to get the fully-resolved intent (and the exact target
string), then get human confirmation. Two equivalent ways:

- **Watcher (default):** the operator runs `python scripts/confirm_action.py
  --watch`, approves the pending request with one keypress, and the agent
  calls the same tool again with the same arguments — no token needed.
- **Token (fallback, headless/scripted):** run `python scripts/confirm_action.py
  <action> "<target>" --platform projectachilles` and call again with the
  printed token.

Both are single-use, expire in 15 minutes, and are bound to (action, target).
Gating state lives under `$F0_GATING_DIR` (default `~/.f0sectools/gating/`).

**Confirmation modes.** By default (`PROJECTACHILLES_CONFIRM_MODE=token`,
also the value when unset) this server only accepts the watcher/token
confirmations above — both **forge-resistant**, since the approval never
enters model context. Set `PROJECTACHILLES_CONFIRM_MODE=chat` to opt into
**chat-confirm**: the operator just replies "approved" in the chat, and the
agent re-calls the same tool with `confirmation_token` set to the
`confirmation_target` shown in the intent finding; execution is audited with
`method=chat-confirm`. This is low-friction and convenient for supervised,
reversible runs (e.g. `run_test`), but it is **not forge-resistant** — the
model can see and echo the target itself, so a misaligned model could in
principle fabricate the confirmation. It is opt-in, off by default, and
**must never be enabled for a destructive or irreversible action**; use the
watcher or token surface for those. Unlike a token or watcher approval, the
chat echo is **not single-use and has no TTL** — `confirmation_token ==
target` authorizes every call while `allow_write` is on, including a silent
re-execute if the model retries a failed run with the same arguments. Get a
fresh operator "approved" before each re-call, and never reuse the echo to
retry a failed execution.

## Run

    uv run f0-projectachilles-actions-mcp

## Reference & validation

Full parameter details:
[generated tool reference](../../docs/reference/tools/projectachilles-actions.md).
Operator walkthrough of the gate:
[gated actions guide](../../docs/user-guide/gated-actions.md); a full annotated
session: [gated-run-test transcript](../../examples/transcripts/gated-run-test.md).

✅ Live-validated on a real tenant with a read-write-scope `pa_` key
(single-host and tag/fleet runs, count-bound bulk cancel):

```bash
uv run python scripts/live_smoke_projectachilles_actions.py            # intents only
uv run python scripts/live_smoke_projectachilles_actions.py --execute  # with tokens
```

Driven by the `run-validation-test` skill — see the
[skills catalog](../../docs/reference/skills.md#projectachilles).
