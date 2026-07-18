# Low-Friction Gated-Write Confirmation (Approval Watcher) — Design

**Date:** 2026-07-18
**Status:** Approved (brainstormed with James)

## Problem

The current confirmation flow works but is high-friction: the operator must
open a terminal **at the repo root** (the token store is CWD-relative), run
`scripts/confirm_action.py <action> "<target>"`, copy the printed token, and
paste it into the chat so the model retries the tool with
`confirmation_token`. The paste also means the plaintext token transits model
context (harmless — single-use, target-bound — but against the spirit of
"the model never sees it").

## Decision

**Approach A now, B later** (explored during brainstorming):

- **A (this spec): server-side pre-approval ("approval watcher").** The
  human approves the *identity of the action* on the host; the model simply
  repeats the identical tool call. No token is carried by anyone.
- **B (future, separate spec): MCP elicitation** as a progressive
  enhancement. Verified: our MCP Python SDK exposes `Context.elicit`, but
  `pi-mcp-extension` 1.5.0 (the primary runtime's bridge) implements no
  elicitation, so B is deferred until clients support it. B will fall back
  to A.
- Rejected: desktop-dialog-as-mechanism (GUI-session-fragile; demoted to an
  optional `--notify` ping), session arming (`--arm 10m` — erodes
  per-action consent).

## Invariants (unchanged, non-negotiable)

Flag required; human-in-the-loop **per action**; single-use; target-bound;
TTL'd (15 min default); locally audited; all gating logic in `core/gating`;
a model alone can never write — approvals are host filesystem records that
only the human-side CLI creates, and no MCP tool writes to the approvals
directory. The legacy token flow keeps working unchanged (backward compat +
headless/scripted use, e.g. the smoke script's `--execute`).

## New operator flow

1. Model calls a gated tool with no token. The server resolves everything,
   **records a pending request**, and returns the intent finding (as today).
2. The operator's long-lived watcher (`confirm_action.py --watch`, e.g. a
   tmux pane; optional `--notify` fires `notify-send`) shows
   `<action> → <target> — approve? [y/N]`. `y` approves (15 min TTL);
   `n` deletes the request and audits a denial.
3. The operator tells the model "approved, go"; the model repeats the
   **identical** call. The gate consumes the matching approval, executes,
   audits. Friction: one keypress + one chat word.

## Gating directory (fixes CWD sensitivity)

A single fixed location shared by servers and the CLI:

- `$F0_GATING_DIR` if set, else `~/.f0sectools/gating/`
- Layout: `requests/` (pending, display-only), `approvals/`
  (human-granted), `tokens/` (legacy pending tokens), `audit.log`.
- Records keyed by `sha256(action|target)` → idempotent re-requests.
- `TokenStore`'s default dir moves here too (tokens are 15-minute ephemera;
  no migration). The audit-log default moves here as well; existing
  `*_AUDIT_LOG_PATH` env overrides keep working. A resolver helper
  `gating_dir()` in `core/gating` is the one place that computes this.

## core/gating changes

### ApprovalStore (new; sibling of TokenStore, same file-per-record pattern)

- `record_request(action, target, ttl_s=900)` — server-side when returning
  an intent; writes `requests/<key>.json` `{action, target, requested_at,
  expires_at}`. Requests are display data, **never** authorization.
- `list_pending() -> list[dict]` — for the watcher.
- `approve(action, target, ttl_s=900)` — human-CLI-side; writes
  `approvals/<key>.json`, deletes the request record.
- `deny(action, target)` — deletes the request (watcher `n`).
- `consume(action, target) -> bool` — single-use with the same
  unlink-before-validate discipline as `TokenStore.consume` (concurrent
  callers cannot both win); expiry-checked; expired records swept on access.
- `has_approval(action, target) -> bool` — non-consuming, expiry-checked
  peek.

### GatedAction

- Constructor gains `approvals: ApprovalStore | None = None` (defaults to a
  store on `gating_dir()`; tests pass explicit tmp dirs, existing pattern).
- `_authorize(target, token)`: **flag check first (outermost, as today)** →
  token supplied? validate exactly as now → else
  `approvals.consume(name, target)` → else `GateDenied`. Approvals cannot
  bypass a disabled platform.
- Helpers for tools: `has_approval(target)` and `record_request(target)`.
- Audit record gains `method: "token" | "approval"` plus the record-hash
  prefix as the reference (no secrets in the log, as today). Watcher
  denials are audited as `method: "denied"`.

## Server-side change (thin, no schema change)

Each gated tool's short-circuit changes from
`if not confirmation_token: return intent` to:

```python
if not confirmation_token and not gate.has_approval(target):
    gate.record_request(target)
    return [intent...]
```

Sites: Defender `_run_machine_action` (1) and pa-actions `run_test`,
`schedule_test`, `set_schedule_status`, `cancel_task` (4). Intent-finding
text changes from "run confirm_action.py and paste the token" to "approve
this in your confirm_action.py watcher (target shown below); the token
flow still works" — still printing the exact target string. Tool
signatures and MCP schemas are untouched → zero eval/callability impact;
the small model's only new behavior is "call it again".

## CLI (`scripts/confirm_action.py`)

- Legacy one-shot `confirm_action.py <action> <target> [--platform …]`
  (prints a token) — kept verbatim.
- `--watch [--notify] [--interval N]` — poll `requests/`, prompt per
  pending item, `y` → approve, `n` → deny; `--notify` fires `notify-send`
  on new arrivals (best-effort, absence tolerated).
- `--approve <action> "<target>"` and `--list` — one-shot forms for
  SSH/scripted use.

## Testing

- **Core:** approve→consume happy path; expiry; double-consume race
  (unlink-first); wrong target; flag-off still denied even with approval;
  `has_approval` does not consume; `record_request` idempotent; `deny`
  removes; audit `method` values. Explicit tmp dirs throughout.
- **Servers:** existing negative-space suites stay green unchanged
  (backward-compat proof). New per-server tests: same call twice with an
  approval granted in between → exactly one POST/PATCH + audit
  `method=approval`; approval bound to a different target → still intent;
  request record written on intent.
- **CLI:** watcher logic factored into testable functions (list/approve/
  deny paths); no interactive test theater.

## Docs

- CLAUDE.md "Gated Write Actions": the two confirmation modes (watcher =
  interactive default; token = headless/scripted) + `F0_GATING_DIR`.
- `skills/projectachilles/run-validation-test/SKILL.md` step 3: "ask the
  operator to approve in their watcher" (token flow as fallback).
- Defender + pa-actions READMEs, user-guide gated-writes passages,
  `.env.*.example` comments (`F0_GATING_DIR`, watcher usage).

## Out of scope

MCP elicitation (B — separate spec once a target client supports it),
desktop dialogs beyond `--notify`, session arming, any change to eval
task sets (schemas unchanged).

## Milestones

1. `gating_dir()` + `ApprovalStore` + `GatedAction` approval path (core,
   TDD).
2. Server-side short-circuit updates + intent-text updates + tests
   (defender, pa-actions).
3. CLI watch/approve/list/deny + tests.
4. Docs + skill update.
5. Live check on pi (user-gated): full loop — intent → watcher approve →
   identical call executes.
