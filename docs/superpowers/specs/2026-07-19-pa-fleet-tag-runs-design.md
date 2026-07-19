# Fleet-Wide ProjectAchilles Test Runs by Tag — Design

**Date:** 2026-07-19
**Status:** Approved (brainstormed with James)

## Problem

`run_test` / `schedule_test` target exactly one `hostname` today (fleet-wide
was a v1 non-goal). Running a test across many hosts means N separate gated
calls with N confirmations. The operator wants to target **a fleet by tag**
(e.g. `windows-endpoints`) in one gated action.

## Backend facts (verified)

- Agent records carry `tags: string[]`.
- `GET /agent/admin/agents?tag=<tag>` filters agents by tag **server-side**.
- `CreateTaskSchema` / `CreateScheduleSchema` accept `agent_ids` as an **array**;
  `createTasks` / `createSchedule` loop over it — one call fans out to N agents.
- The admin agents **list strips `org_id`** (the known bug); the single-agent
  detail endpoint keeps it. All agents on a single-org `pa_` key share one org.

## Decisions (from brainstorming)

1. **Tag is a parameter, not a new tool.** `run_test` / `schedule_test` gain
   `tag: str = ""` beside `hostname: str = ""`; exactly one must be set.
   Single-host stays byte-unchanged and backward compatible. Tool count stays
   at 6.
2. **Confirmation binds to tag + host count:** fleet target =
   `test_uuid@tag:<tag>:<N>`. The drift-catch (blast radius changed between
   preview and execute) needs **zero `core/gating` changes** — see below.

## Tool surface

`run_test(test_id, hostname="", tag="", confirmation_token="")` and
`schedule_test(test_id, hostname="", tag="", schedule, run_time, …,
confirmation_token="")`:

- exactly one of `{hostname, tag}` non-empty → proceed;
- both set, or neither → pre-gate guidance finding (*"set exactly one of
  hostname or tag"*), gate never consulted, no token burned.

`set_schedule_status` / `cancel_task` unchanged (they act on IDs, not hosts).

Tool descriptions state the choice plainly: *target ONE host by `hostname`,
OR a fleet by `tag` — set exactly one.*

## Resolution — new `resolve_agents_by_tag(pa, tag)`

Parallels `resolve_agent`:

1. Guard the tag (charset `^[A-Za-z0-9._:@-]{1,64}$`, non-empty) → `ResolveFailed`
   guidance otherwise.
2. `GET /agent/admin/agents?tag=<tag>&limit=200`.
3. 0 matches → graceful *"no agents carry tag 'X'"* finding.
4. **>200 matches → HARD REFUSAL** (*"tag matches >200 agents; narrow it"*).
   For a tool that launches attack simulations a silently-capped blast radius
   is unacceptable; the admin agents envelope reports its count as `data.total`
   (verified — `{"data": {"agents": [...], "total": N}}`), so refuse when
   `data.total > 200` (or, defensively, when the returned list already hits the
   limit) rather than run on a subset.
5. Returns `{"agent_ids": [...], "hostnames": [...], "org_id": str}` — `org_id`
   fetched **once** from the first agent's detail endpoint (the list strips it).

Single-host path keeps `resolve_agent` unchanged.

## Body construction

`agent_ids` becomes the resolved list: `[one]` (host, as today) or `[…N]`
(tag). `org_id` and every other field identical. The backend fans out.

## Confirmation binding + drift-catch (no core change)

Target string:
- single host: `test_uuid@hostname` (unchanged).
- fleet: `test_uuid@tag:<tag>:<N>`, N = resolved agent count.

The tool resolves the selection **before the gate on BOTH the intent and the
execute call**:

- **Intent** (no token): resolve → N → target `…@tag:webs:12` → ONE intent
  finding listing the test, tag, N, the hostnames (bounded 15 + "…K more"),
  and the exact `confirmation_target`. Operator approves 12 hosts.
- **Execute** (token/approval/chat-echo): the tool **re-resolves the tag**,
  recomputes N, builds the target from the *current* count, and passes it to
  `gate.execute_async(target=…)`. If membership changed to 15, the current
  target `…@tag:webs:15` does not match the token issued for `…@tag:webs:12`,
  so `consume(action, target)` finds nothing → `GateDenied` → refusal:
  *"the fleet size changed (was 12, now 15) — re-preview and re-approve."*

Because N is baked into the target string, a changed count is a changed
target — the existing `(action, target)` binding catches drift for the token,
watcher-approval, and chat-confirm paths alike. **No `core/gating` change.**

## Bounded, summarized output

- **Intent finding:** ONE finding — test, tag, N, hostnames bounded to 15 +
  "…K more", `confirmation_target`.
- **Execution result:** ONE summary finding — *"Submitted N tasks: run
  '<test>' on tag '<tag>' (N hosts)"*, first ~10 `task_id`s + the count as
  evidence. Never N flat findings.

## Fleet results (reuse, no new tool)

A fleet run yields N task IDs. Existing surfaces cover it:
- **`list_test_executions` (read server) is bundle-aware and groups by
  `(bundle, host)`** → a fleet bundle run shows as one rollup finding **per
  host** (COMPLIANT/NON-COMPLIANT, X/Y) — a usable fleet results view.
- `get_task_status` drills into a single host's task.

The execution summary finding points the operator there.

## Testing (mocked/hermetic)

- `resolve_agents_by_tag`: tag→N (org fetched once from detail); 0 → guidance;
  >200 → hard refusal; charset guard.
- `run_test` / `schedule_test`: exactly-one-of host/tag (both/neither →
  guidance, gate never consulted); tag path builds `agent_ids:[…N]` and target
  `test@tag:<tag>:<N>`; intent lists bounded hostnames + count; **drift test**
  — token at N=12, tag re-resolves to N=15 → refusal, no write, token not
  burned; valid token at unchanged N → one POST with the full `agent_ids` list
  + summary result finding; single-host path byte-unchanged (existing tests
  stay green); 40-host tag → host evidence bounded to 15 + "more".

## Docs

- `skills/projectachilles/run-validation-test/SKILL.md`: fleet section (target
  a tag; approve the count; re-approve on drift).
- pa-actions README + `.env` note; tool descriptions updated for host-or-tag.
- No CLAUDE.md rule change (still gated, still small-model-safe).

## Out of scope (YAGNI)

- A single **fleet rollup** result ("18/20 hosts COMPLIANT") — its own
  brainstorm; per-host `list_test_executions` view suffices for v1.
- Per-host partial approval (approve 10 of 12).
- Tag boolean logic (`tagA AND NOT tagB`) — one tag per call.
- Any `core/gating` change (the drift-catch reuses the existing target binding).

## Milestones

1. `resolve_agents_by_tag` (+ org-once, >200 refusal, 0/charset) + tests.
2. `run_test` host-or-tag (exactly-one validation, tag body, target
   `test@tag:<tag>:<N>`, bounded intent + summary result) + tests.
3. `schedule_test` host-or-tag (same pattern) + tests.
4. Server tool wiring (add `tag` param + descriptions) + registration/eval
   task updates.
5. Docs (skill fleet section, README, tool descriptions).
6. Live check on pi (user-gated): tag a couple of hosts, run a test on the
   tag, confirm the count-bound approval and the fanned-out tasks; verify a
   size change forces re-approval.
