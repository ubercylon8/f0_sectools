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
watcher or token surface for those.

## Run

    uv run f0-projectachilles-actions-mcp
