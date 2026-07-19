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
   tokens, the finding also carries the one-shot command.
4. Once the operator says approved, call the SAME tool again with the SAME
   arguments (no token needed — the gate consumes the stored approval).
   Approvals are single-use, expire in 15 minutes, and are bound to the
   exact action + target shown in the intent. Schedule timing arguments
   (time/day/date) are NOT part of the binding — re-read the intent finding
   before confirming so you approve the exact schedule shown.
5. Verify: `get_task_status` for runs (then `list_test_executions` on the
   read server for the blocked/not-blocked outcome); `list_schedules` for
   schedules.

## Pitfalls

- The test must be BUILT in the ProjectAchilles console first; an unbuilt
  test returns a "not built" finding, not an error.
- One host per call (exact hostname match). Fleet-wide runs are not
  supported here — use the PA console.
- All schedule times are UTC, 24h HH:MM.
- "Unschedule" = pause (`set_schedule_status` status=paused). There is no
  delete — that is admin-only in the platform.
- If every write returns a permission finding, the pa_ key is read-only —
  the operator must issue a read-write-scope key.

## Verification

The action finding says "Action completed"; follow its recommended action.
A "Pending action" finding means step 3 has not happened yet — that is the
expected first response, not a failure.
