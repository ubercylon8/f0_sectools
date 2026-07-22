<!-- GENERATED FILE - do not edit. Regenerate with: uv run python scripts/gen_docs.py -->

# `f0-pa-actions` tool reference

Module `f0_pa_actions_mcp.server` · **7 tools** (3 read + 4 gated write) · [server README](../../../servers/projectachilles-actions-mcp/README.md)

> 🔒 Gated write tools require the platform write flag **and** a per-action human confirmation — see the [security model](../../explanation/security-model.md#gated-write-actions).

## `run_test` 🔒 *(gated write)*

Run a ProjectAchilles validation test now on ONE host OR a whole TAG/GROUP (GATED WRITE).

Target exactly one of `hostname` (one exact agent) OR `tag`. Any request to
run on a GROUP of hosts — "the hosts tagged X", "hosts with tag X", "the X
group", "the same test on tag X" — is a `tag` run: pass that tag string
straight to `tag` and the server expands it to every matching agent. Do NOT
look up or enumerate the hosts yourself first. test_id is the test's UUID.
Call WITHOUT confirmation_token first to preview: the intent lists the
matched hosts and count. For a fleet the confirmation is bound to the host
COUNT, so if the tag's membership changes before you confirm you must
re-preview and re-approve. Requires PROJECTACHILLES_ALLOW_WRITE=true.

| Parameter | Type | Default |
|---|---|---|
| `test_id` | `string` | *(required)* |
| `hostname` | `string` | `""` |
| `tag` | `string` | `""` |
| `confirmation_token` | `string` | `""` |

Used by skills: [`run-validation-test`](../../../skills/projectachilles/run-validation-test/SKILL.md)

## `schedule_test` 🔒 *(gated write)*

Schedule a ProjectAchilles validation test on ONE host OR a whole TAG/GROUP (GATED WRITE).

Target exactly one of `hostname` or `tag`. Any "hosts tagged X / hosts with
tag X / the X group" request is a `tag` run: pass the tag string straight to
`tag` and the server expands it — do NOT look up or enumerate the hosts
yourself. run_time is 24h HH:MM UTC. schedule=once also needs run_date
(YYYY-MM-DD); weekly also needs day; monthly also needs day_of_month (1-31).
Same count-bound confirmation as run_test for fleets.

| Parameter | Type | Default |
|---|---|---|
| `test_id` | `string` | *(required)* |
| `hostname` | `string` | `""` |
| `schedule` | `"once"` \| `"daily"` \| `"weekly"` \| `"monthly"` | `"daily"` |
| `run_time` | `string` | `""` |
| `run_date` | `string` | `""` |
| `day` | `""` \| `"monday"` \| `"tuesday"` \| `"wednesday"` \| `"thursday"` \| `"friday"` \| `"saturday"` \| `"sunday"` | `""` |
| `day_of_month` | `integer` | `0` |
| `tag` | `string` | `""` |
| `confirmation_token` | `string` | `""` |

Used by skills: [`run-validation-test`](../../../skills/projectachilles/run-validation-test/SKILL.md)

## `set_schedule_status` 🔒 *(gated write)*

Pause (status=paused) or resume (status=active) a ProjectAchilles test
schedule (GATED WRITE).

Get schedule_id from list_schedules. Same two-step confirmation flow as
run_test. Pausing is the supported way to stop a schedule (no delete).

| Parameter | Type | Default |
|---|---|---|
| `schedule_id` | `string` | *(required)* |
| `status` | `"active"` \| `"paused"` | *(required)* |
| `confirmation_token` | `string` | `""` |

Used by skills: [`run-validation-test`](../../../skills/projectachilles/run-validation-test/SKILL.md)

## `cancel_tasks` 🔒 *(gated write)*

Cancel ProjectAchilles test tasks (GATED WRITE). Pass EITHER task_id (one
task) OR a status/search filter to bulk-cancel a run's tasks in one action
(e.g. status=pending cancels all pending). Bulk confirmation is bound to the
matched task COUNT; >200 matches is refused. Same two-step confirmation as
run_test.

| Parameter | Type | Default |
|---|---|---|
| `task_id` | `string` | `""` |
| `status` | `"pending"` \| `"assigned"` \| `"running"` \| `"completed"` \| `"failed"` \| `"expired"` | `"pending"` |
| `search` | `string` | `""` |
| `confirmation_token` | `string` | `""` |

Used by skills: [`run-validation-test`](../../../skills/projectachilles/run-validation-test/SKILL.md)

## `list_schedules`

List ProjectAchilles recurring test schedules (read-only).

Scheduled future runs — not past results (use list_test_executions on the
read server for those). status '' = all.

| Parameter | Type | Default |
|---|---|---|
| `status` | `""` \| `"active"` \| `"paused"` \| `"completed"` | `""` |

Used by skills: [`run-validation-test`](../../../skills/projectachilles/run-validation-test/SKILL.md)

## `get_task_status`

One-shot status check for a ProjectAchilles test-run task (read-only).

One task by task_id (from run_test). If still running, report that status
and do not call again until the user asks. On completion, returns the run's
OUTCOME (bundle verdict or pass/not-passed) — no need to check again or call
list_test_executions.

| Parameter | Type | Default |
|---|---|---|
| `task_id` | `string` | *(required)* |

Used by skills: [`run-validation-test`](../../../skills/projectachilles/run-validation-test/SKILL.md)

## `list_tasks`

List ProjectAchilles test tasks and their lifecycle status (read).

status filters by task state; search matches test name or hostname. One call
returns all matching tasks (N per-host rows) — use instead of calling
get_task_status once per task.

| Parameter | Type | Default |
|---|---|---|
| `status` | `""` \| `"pending"` \| `"assigned"` \| `"running"` \| `"completed"` \| `"failed"` \| `"expired"` | `""` |
| `search` | `string` | `""` |
| `limit` | `integer` | `25` |

Used by skills: [`run-validation-test`](../../../skills/projectachilles/run-validation-test/SKILL.md)
