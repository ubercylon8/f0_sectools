# Chat-Confirm Gating Mode (Opt-In Low-Friction Confirmation) — Design

**Date:** 2026-07-19
**Status:** Approved (brainstormed with James)

## Problem

The gated-write confirmation flow — even after the approval watcher — still
needs a second surface (a terminal running `confirm_action.py --watch`, or a
pasted token). During live testing on pi the operator found that friction
unacceptable and asked for a purely in-conversation confirmation: preview the
action, type **"approved"** in the chat, done.

## The security reality (stated plainly, because this is a security repo)

Everything in the chat is visible to **and forgeable by** the model. The
token/watcher gate's one real property is that confirmation arrives through a
channel the model cannot see or write. A chat "approved" removes that channel
separation, so the gate can no longer *independently verify* a human approved
— it trusts that the model faithfully waited for the operator's word.

That is not a new hole so much as an explicit one: in pi / Claude Code the
model already has shell access and could write approval files or run
`confirm_action.py --approve` itself, so the strong guarantee already rested
on "a human is supervising." Chat-confirm makes that assumption load-bearing
and visible instead of ceremonial.

**Therefore chat-confirm is opt-in, off by default, and never the option for
destructive/irreversible actions.** The forge-resistant token/watcher path
stays the default and the only path for host isolation and its class.

## Decision

Add a per-gate **`confirm_mode`** (`"token"` default | `"chat"`), sourced from
per-platform config. Wire it for ProjectAchilles only now (`PROJECTACHILLES_
CONFIRM_MODE`); Defender and every other platform stay token-only, untouched.

Rejected alternatives (kept on the roadmap, both forge-resistant): the local
web approval console, and MCP elicitation (blocked today —
`pi-mcp-extension` 1.5.0 has no elicitation support, verified in source).

## Critical Rule 1 amendment (governance — must ship in the same change)

CLAUDE.md Critical Rule 1 currently says a gated action *"MUST require both an
explicit config flag AND a per-action human confirmation **token**."*
Chat-confirm keeps the flag and keeps per-action human confirmation but drops
the token. Rule 1 is amended to name **two confirmation modes**:

- **Forge-resistant (token / watcher)** — the default, and the **only**
  permitted mode for destructive or irreversible actions (host isolation,
  account disable, quarantine). Confirmation arrives out-of-band on a channel
  the model cannot read.
- **Chat-confirm** — opt-in per platform, for supervised and reversible
  actions (e.g. ProjectAchilles validation runs on your own fleet). The
  operator's chat "approved" is the per-action human confirmation; it is
  **not** forge-resistant and is disabled by default.

The rule keeps: explicit flag required, per-action human confirmation, and
audit — always.

## Mechanism (all in core/gating; additive)

`GatedAction.__init__` gains `confirm_mode: str = "token"`.

`_authorize(target, token)` — the flag check stays outermost; one new branch
is inserted, the existing token/approval branches are unchanged:

```
if not enabled:                              -> GateDenied            (unchanged, outermost)
if confirm_mode == "chat" and token == target:  return "chat-confirm" (NEW echo shortcut)
if token:  consume-or-deny (TokenStore)                               (unchanged)
if approvals.consume(...):  return "approval"                         (unchanged)
raise GateDenied                                                      (unchanged)
```

Consequences:
- In chat mode the token and watcher paths still work — chat-confirm is a
  strictly-additive third accepted route, never a replacement.
- The echo shortcut requires `token == target` exactly. The model has the
  target (it's the intent's `confirmation_target`), so this is not human
  verification — its value is **drift-prevention** (a changed host yields a
  different target that won't match) and a precise audit record.
- Cross-mode safety: a target-echo passed in `token` mode falls through to
  `TokenStore.consume`, fails, and denies — no leak.
- Audit records `method="chat-confirm"`.

No tool signature or MCP schema changes — the existing `confirmation_token`
argument carries the echoed target. Zero eval/callability impact.

## Config

`ProjectAchillesConfig` gains `confirm_mode: str = "token"` from
`PROJECTACHILLES_CONFIRM_MODE`, **validated** in `from_env` to `{"token",
"chat"}` (an unrecognized value raises `ValueError` — never silently weaken
the gate). `PlatformConfig` (Defender/Entra/Intune) is not modified.

## Server + tool wiring (thin)

- pa-actions `server.py` `_gate()` passes `confirm_mode=cfg.confirm_mode`.
- pa-actions `tools.py` `_intent()` reads `gate.confirm_mode` and branches the
  `recommended_action.summary`:
  - `token` mode: unchanged (watcher + token-fallback text).
  - `chat` mode: *"To execute, the operator replies 'approved'; then call this
    tool again with confirmation_token set to \"<target>\"."*
- Tool control flow is unchanged: the existing
  `if not confirmation_token and not gate.has_approval(target): ... return intent`
  short-circuit already returns intent on the first (no-token) call and
  authorizes on the confirmed call. (In chat mode `has_approval` is simply
  always false; the harmless request record it writes is TTL-swept.)

## Testing

- **Core (`core/tests/test_gating.py`):** chat-mode target-echo executes +
  audits `method=chat-confirm`; wrong echo denies; a valid token still works
  in chat mode (additive); a target-echo is rejected in `token` mode (no
  cross-mode leak); flag-off denies even with a correct echo (outermost
  invariant); `_gate` fixture carries `confirm_mode` explicitly (hermetic).
- **Config (`core/tests/test_config.py`):** `PROJECTACHILLES_CONFIRM_MODE`
  parsed; default `"token"`; invalid value raises.
- **pa-actions:** chat-mode intent finding carries the "reply approved" text;
  same call with `confirmation_token==target` under chat mode executes exactly
  once with one POST; wrong-target echo still returns intent/deny; all
  pre-existing token-mode tests stay green with unchanged assertions (fixtures
  pass `confirm_mode="token"`).

## Docs

- CLAUDE.md: amend Critical Rule 1 (two modes) + expand Gated Write Actions
  with the chat-confirm flow and the explicit trust caveat.
- `.env.projectachilles.example`: `PROJECTACHILLES_CONFIRM_MODE=token`
  documented default + the chat option and its caveat.
- `run-validation-test` skill: chat-confirm procedure variant beside the
  watcher one.
- pa-actions README.

## Out of scope (YAGNI)

Defender/other-platform chat wiring; the web approval console and MCP
elicitation (both remain roadmap items as the forge-resistant low-friction
options); any change to the token/watcher path or the findings schema.

## Milestones

1. `confirm_mode` on `GatedAction` + `_authorize` chat branch + core tests.
2. `ProjectAchillesConfig.confirm_mode` + validation + config tests.
3. pa-actions `_gate` wiring + `_intent` mode-aware text + tests.
4. Docs (Rule 1 amendment, gated section, .env, skill, README).
5. Live check on pi (user-gated): set `PROJECTACHILLES_CONFIRM_MODE=chat`,
   run a validation test, confirm "approved" alone executes it.
