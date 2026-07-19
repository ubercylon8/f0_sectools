# ProjectAchilles Bundle Results + No-Poll Status — Design

**Date:** 2026-07-19
**Status:** Approved (brainstormed with James)

## Problem

Two read/UX defects surfaced during live pi testing of the pa-actions server
(neither touches the gate):

1. **Async-status polling holds the chat hostage.** `run_test` launches a task
   that runs asynchronously on the agent (minutes). The model treats "check
   status" as *loop `get_task_status` until completed*, so it burns turns
   polling and the operator can't use the chat until the run finishes.
   `get_task_status`'s current running-branch summary literally says "Poll
   again later," actively inviting the loop.

2. **Bundle results are under-reported — dangerously.** `list_test_executions`
   (read server) is bundle-blind. VERIFIED live: a bundle run stores every
   control correctly in ES as an individual row, but the tool emits one flat
   finding per row with no rollup, over an unbounded 7-day window (default
   limit 25; the live window held 118 items). Handed 22 flat control rows, the
   small model summarized the first 5 (validator 1: 4/5 pass) and reported the
   host as basically-passing — when it is **NON-COMPLIANT** (Identity Endpoint
   Posture Bundle: 22 controls, 15 passed / 7 failed, a fully-failing Cloud
   Credential Protection validator). This is CLAUDE.md's own rule ("bound and
   paginate… summarize counts") not being met for bundles.

## Key live finding (drives the whole design)

The completed **task record already carries the pre-aggregated verdict.**
`GET /agent/admin/tasks/{id}` → `result.bundle_results` contains:
`bundle_name`, `bundle_category`, `total_controls` (22), `passed_controls`
(15), `failed_controls` (7), `overall_exit_code` (101), and `controls[]` —
each `{control_id, control_name, validator, compliant, severity, techniques,
tactics, ...}`. The agent did the rollup. So the loop-closer needs **no
analytics query and no new grouping logic** — it presents an
already-summarized structure. Non-bundle single tests have `exit_code` and no
`bundle_results`.

## Decision

Fold both fixes into existing tools — **no new tools, no tool-budget impact**
(read server stays at 8, actions server at 6). The two changes touch different
servers and different data sources (task `bundle_results` vs analytics rows),
so no shared helper is needed and the thin-server rule is respected.

## Change A — `get_task_status` becomes status + outcome (actions server)

`servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py::get_task_status`.

- The tool already fetches `GET /agent/admin/tasks/{tid}`. On `status ==
  "completed"`, read `result` (JSON string or dict), then `bundle_results`
  (JSON string or dict):
  - **Bundle:** emit one rollup finding — title `"<bundle_name> on <host>:
    COMPLIANT|NON-COMPLIANT (<passed>/<total> controls passed)"`; verdict is
    NON-COMPLIANT when `overall_exit_code != 0` or `failed_controls > 0`;
    severity `medium` (or `high` if any failing control is critical/high) when
    NON-COMPLIANT, else `info`; `finding_type` `misconfig` when NON-COMPLIANT
    else `posture`. Evidence: `passed`/`failed`/`total` counts, plus each
    **failing** control (`compliant == false`) as `control_name (validator) —
    severity`, **bounded** to the first 15 with an "N more" note. `references`
    = MITRE techniques unioned from the failing controls.
  - **Non-bundle:** `exit_code == 0` → "passed"/blocked outcome (info/posture);
    non-zero → "not passed"/NOT blocked (severity from the task, misconfig).
  - **Malformed/missing `result`:** graceful "completed; outcome unavailable"
    finding — never a crash (defensive dict/JSON access).
- Non-completed statuses unchanged EXCEPT wording (Change B).

## Change B — no-poll guidance (#1)

A tool cannot stop a determined loop; strong, consistent cues across three
surfaces are the lever:

- `get_task_status` **docstring/description:** "One-shot status-and-result
  check. If the task is still running, report that and STOP — do not call
  again until the user asks."
- `get_task_status` **running-branch summary:** replace "Poll again later…"
  with "Still running (async, often minutes). I will not check again until you
  ask — say 'check the test' later."
- `run_test` and `schedule_test` **success-finding summary:** fire-and-report —
  "Submitted as task `<id>`; it runs asynchronously. Ask me later and I'll
  check once with get_task_status." Remove any "track it"/"poll" phrasing.

## Change C — `list_test_executions` bundle rollup (read server)

`servers/projectachilles-mcp/f0_projectachilles_mcp/tools.py::list_test_executions`.

- After fetching the paginated analytics rows, **group** rows where
  `is_bundle_control` is truthy by `(bundle_name or test_name, hostname)`:
  one finding per bundle-run — title `"<bundle> on <host>: <passed>/<total>
  controls passed"`, verdict severity (NON-COMPLIANT when any control has
  `is_protected` false), failing controls as **bounded** evidence, `references`
  unioned from failing controls' `techniques`.
- Rows that are not bundle controls keep the existing per-row behavior and the
  existing security-vs-cyber-hygiene vocabulary (blocked/NOT blocked vs
  passed/not passed) unchanged.
- Keep the existing `days` and `limit` args and the paginated endpoint call.

## Testing

- **Actions (`tests/test_read_tools.py` / a new test module):**
  `get_task_status` completed-with-`bundle_results` (both a JSON-string and a
  dict `result`) → one rollup finding, correct counts, failing controls in
  evidence, NON-COMPLIANT severity, MITRE refs; completed non-bundle → single
  outcome (both exit codes); malformed `result` → graceful; running-branch
  summary contains no "poll" wording. `run_test`/`schedule_test` success
  summary asserts fire-and-report text and no "track"/"poll" wording (existing
  intent-text and gate tests stay green).
- **Read (`tests/test_tools.py`):** `list_test_executions` with a mocked
  22-row bundle (7 failing) → exactly **one** rollup finding with correct
  counts and bounded evidence; mixed bundle + single rows → rollup + per-row
  findings; single-only rows → unchanged (existing tests green).
- All hermetic/mocked; live re-check on pi is user-gated.

## Docs

- `skills/projectachilles/run-validation-test/SKILL.md`: no-poll procedure
  (launch = fire-and-report; at most one status check per user request;
  `get_task_status` now shows the outcome).
- `servers/projectachilles-actions-mcp/README.md`: `get_task_status` returns
  the result on completion.
- Read-server skills that use `list_test_executions`
  (`defense-posture-review`, `coverage-gap-analysis`): one-line note that
  bundle runs roll up.
- No CLAUDE.md rule change (read/UX only).

## Out of scope (YAGNI)

No new tools; no analytics rollup in the actions server (the task record
already aggregates); no gate/schema change; no change to `list_schedules` or
the confirmation flow.

## Milestones

1. `get_task_status` bundle/non-bundle rollup + graceful fallback + tests
   (actions).
2. No-poll wording: `get_task_status` running branch/description +
   `run_test`/`schedule_test` success summaries + tests (actions).
3. `list_test_executions` bundle grouping + tests (read server).
4. Docs (skill, READMEs, read-server skill notes).
5. Live check on pi (user-gated): run a bundle, `get_task_status` returns the
   NON-COMPLIANT rollup in one call; confirm the model does not poll.
