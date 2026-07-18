# f0-pa-actions — ProjectAchilles gated write actions (MCP server)

Companion to `servers/projectachilles-mcp/` (read-only). This server exposes
the **write** side of the validation loop, every write gated by
`core/gating` (operator flag + single-use confirmation token + local audit):

| Tool | Type |
|---|---|
| `run_test(test_id, hostname)` | GATED — execute a validation test now |
| `schedule_test(test_id, hostname, schedule, run_time, …)` | GATED — recurring/once schedule (UTC) |
| `set_schedule_status(schedule_id, status)` | GATED — pause/resume |
| `cancel_task(task_id)` | GATED — cancel a pending run |
| `list_schedules(status)` | read |
| `get_task_status(task_id)` | read |

## Setup

Shares `.env.projectachilles` with the read server (same platform, same
credential file). Two extra requirements for writes:

1. The `pa_` API key must be **read-write scope** (a read-only key 403s on
   every write — you get a permission finding telling you so).
2. `PROJECTACHILLES_ALLOW_WRITE=true` must be set.

Executing a gated action is two-step: call the tool without
`confirmation_token` to get the fully-resolved intent (and the exact target
string), then run `python scripts/confirm_action.py <action> "<target>"
--platform projectachilles` and call again with the printed token. Tokens
are single-use, expire in 15 minutes, and are bound to (action, target).

## Run

    uv run f0-projectachilles-actions-mcp
