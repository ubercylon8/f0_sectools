# Using gated write actions

How to enable, approve, and audit the tools that change platform state —
today: Defender `isolate_host`/`release_host` and the ProjectAchilles actions
server (`run_test`, `schedule_test`, `set_schedule_status`, `cancel_tasks`).

*This is the operator how-to. The design and guarantees are explained in the
[security model](../explanation/security-model.md#gated-write-actions); a full
annotated session is in
[examples/transcripts/gated-run-test.md](../../examples/transcripts/gated-run-test.md).*

Everything is off by default. If you never touch this page, every tool in
every server stays read-only.

## 1. Enable writes for one platform

Set the platform's write flag in its env file and restart the server:

```bash
# .env.projectachilles              # .env.defender
PROJECTACHILLES_ALLOW_WRITE=true    DEFENDER_ALLOW_WRITE=true
```

Enable only the platform you need. The flag makes the gate *reachable*; every
call still needs a per-action confirmation from you.

## 2. Run the watcher (recommended)

In your own terminal — one the agent runtime does not control:

```bash
uv run python scripts/confirm_action.py --watch
```

Now use the agent normally. When it invokes a write tool, the tool returns an
**intent** finding (what it will do, to which target — nothing executes) and a
request appears in your watcher:

```console
projectachilles.run_test -> 3f9d…|web-01 — approve? [y/N] y
APPROVED projectachilles.run_test -> 3f9d…|web-01 (15 min, single use)
```

Then tell the agent to proceed: it repeats the **identical** call and the gate
consumes your approval. Approvals are single-use, bound to that exact action +
target, and expire after 15 minutes. Fleet-wide runs (by tag) bind the
approval to the matched **host count** — if membership changes, the agent must
re-preview and you must re-approve.

Change nothing → nothing happens: an unapproved intent simply expires.

## 3. Alternative: one-shot tokens (headless / scripted)

Without a watcher session, mint a single-use token for one specific action:

```bash
uv run python scripts/confirm_action.py projectachilles.run_test "3f9d…|web-01"
# prints a token (valid 900s, single use)
```

Pass it to the agent to include as the tool's `confirmation_token`. Same
guarantees as the watcher; only the token's SHA-256 hash is ever stored.

## 4. Optional: chat-confirm (supervised, reversible actions only)

`PROJECTACHILLES_CONFIRM_MODE=chat` lets your in-chat "approved" serve as the
confirmation (the agent echoes the intent's `confirmation_target` back).
Convenient when you are watching every turn — but **not forge-resistant** and
not single-use, so: supervised sessions only, reversible actions only, give a
fresh "approved" before any re-call, and never expect it on destructive
actions (it is deliberately not wired to any). Details and the honest caveat:
[security model](../explanation/security-model.md#layer-2--human-confirmation-three-surfaces).

## 5. Read the audit trail

Every executed action appends a line to `~/.f0sectools/gating/audit.log`
(override the directory with `F0_GATING_DIR` — servers and the CLI must agree
on it):

```bash
tail -5 ~/.f0sectools/gating/audit.log | python -m json.tool --json-lines
```

Each entry: `action`, `target`, `actor`, `method`
(`approval`/`token`/`chat-confirm`), and `token_ref` — a hash reference tying
the execution to its confirmation.

## Safety notes

- **Keep the watcher out of the model's reach.** The guarantee holds only if
  `confirm_action.py` runs where the model cannot drive it. In runtimes with
  shell access (Claude Code, opencode), treat the CLI — especially
  `--approve` — as operator-only, and keep write flags off unless supervising.
- **Deny freely.** `N` (or ignoring the request) is always safe; the agent
  just reports the intent expired.
- **One platform at a time.** There is no global write switch, by design.

## Troubleshooting

- *"Action … is disabled"* — the write flag isn't set in that platform's
  `.env`, or the server wasn't restarted after setting it.
- *"requires a watcher approval … or a confirmation token"* — the approval
  expired (15 min), was already consumed, or the agent changed the target
  between preview and execute (any change requires a fresh approval).
- *Watcher sees no requests* — server and CLI disagree on `F0_GATING_DIR`;
  unset it in both or set it identically in both.
