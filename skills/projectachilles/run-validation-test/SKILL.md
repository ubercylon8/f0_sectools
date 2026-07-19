---
name: run-validation-test
description: Run or schedule a ProjectAchilles validation test (gated)
version: 1.0.0
metadata:
  hermes:
    tags: [security, projectachilles, validation, gated-write, detection-engineer]
    category: security
---

# Run or Schedule a ProjectAchilles Validation Test

## When to Use

The user wants to actually EXECUTE a validation test — "run the brute-force
test on web-01", "schedule the ransomware sim nightly", "pause that
schedule", "cancel that run". Uses the **f0_sectools ProjectAchilles
ACTIONS** MCP server (gated writes). For finding tests, scores, or past
results, use the read server instead (find_tests, get_defense_score,
list_test_executions).

## Tools

Base tool names (runtime may prefix): `run_test`, `schedule_test`,
`set_schedule_status`, `cancel_task` (all GATED), `list_schedules`,
`get_task_status` (reads).

## Procedure

1. Resolve the test first: use `find_tests`/`get_test` (read server) to get
   the test's **uuid** — the actions server takes a uuid, not a name.
2. Call the gated tool WITHOUT `confirmation_token`. You get back the
   fully-resolved intent (test, host, agent id) and a `confirmation_target`
   evidence value.
3. STOP and ask the operator to approve the action in their
   `confirm_action.py --watch` terminal (the pending request appears there
   automatically; the intent finding shows the exact target). If they prefer
   tokens, the finding also carries the one-shot command. **If
   `PROJECTACHILLES_CONFIRM_MODE=chat`** (opt-in, off by default — see the
   operator's `.env.projectachilles`), skip the watcher/token step: just ask
   the operator to reply "approved" in the chat.
4. Once the operator says approved, call the SAME tool again with the SAME
   arguments (no token needed — the gate consumes the stored approval).
   Approvals are single-use, expire in 15 minutes, and are bound to the
   exact action + target shown in the intent. Schedule timing arguments
   (time/day/date) are NOT part of the binding — re-read the intent finding
   before confirming so you approve the exact schedule shown.
   **In chat-confirm mode**, instead pass `confirmation_token` set to the
   exact `confirmation_target` evidence value shown in the intent finding —
   that echo, plus the operator's chat "approved", is the confirmation.
   Chat-confirm is convenient for supervised, reversible runs like this one
   but is not forge-resistant (the model itself can see and echo the
   target), so it is never used for destructive actions.
5. Verify: launching a test is **fire-and-report** — the run is async and
   takes minutes to finish. Do NOT poll: make at most one `get_task_status`
   call per user request. `get_task_status` returns the run's **outcome on
   completion** (bundle verdict COMPLIANT/NON-COMPLIANT with X/Y controls, or
   single-test pass/not-passed) directly — there's no need to also call the
   read server for the result. Use `list_schedules` to verify schedules.

### Fleet-by-tag targeting

`run_test`/`schedule_test` take exactly one of `hostname` (one exact agent)
or `tag`. A `tag` fans the same test out to every agent carrying it — a
fleet — in one gated action. The step-2 intent preview lists the matched
hosts plus the total count as evidence; the step-4 confirmation is **bound
to that count**, so if the fleet's membership changes between preview and
approval (an agent gains/loses the tag), confirmation fails and you must
re-preview and re-approve against the new count. A tag matching more than
200 hosts is refused outright — narrow the tag and retry. After a fleet run,
get per-host results from `list_test_executions` on the read server
(`get_task_status` only covers one task id at a time, not the whole fleet).

## Pitfalls

- The test must be BUILT in the ProjectAchilles console first; an unbuilt
  test returns a "not built" finding, not an error.
- `hostname` is an exact, single-agent match. To target several hosts at
  once, use `tag` instead (see Fleet-by-tag targeting above) — there is no
  hostname list/glob.
- Fleet confirmations are bound to host COUNT, not the specific host list —
  a same-size membership swap between preview and approval will NOT be
  caught. Re-preview if you have reason to think membership changed even
  when the count looks the same.
- All schedule times are UTC, 24h HH:MM.
- "Unschedule" = pause (`set_schedule_status` status=paused). There is no
  delete — that is admin-only in the platform.
- If every write returns a permission finding, the pa_ key is read-only —
  the operator must issue a read-write-scope key.
- In chat-confirm mode, the echoed target is NOT single-use or time-limited —
  it authorizes every call while the write flag is on. Get a fresh operator
  "approved" before each re-call, and never reuse the echo to retry a failed
  execution.
- Never loop `get_task_status` waiting for completion — tell the user you'll
  check when they ask.

## Verification

The action finding says "Action completed"; follow its recommended action.
A "Pending action" finding means step 3 has not happened yet — that is the
expected first response, not a failure.
