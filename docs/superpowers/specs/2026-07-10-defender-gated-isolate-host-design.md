# Design: First gated write action — Defender `isolate_host` / `release_host`

**Date:** 2026-07-10
**Status:** Approved (design), pending spec review
**Scope:** One implementation plan.

## Problem

`core/gating/` is built and unit-tested, but **no server exposes a gated write**, so the
central safety claim of f0_sectools — *"a small local model must never be able to isolate a
host on its own"* — has never been exercised end to end. The findings schema's
`recommended_action.gated_action` field is always `null` in practice, so the
read → recommend → act loop dead-ends at "recommend."

This design adds the first two gated write actions — **`isolate_host`** and
**`release_host`** on the Defender server — proving the flag + confirmation-token + audit
pattern against a real platform API. It is pattern-proving, not a containment feature push:
no other actions ship here.

## Critical constraints (from CLAUDE.md)

- **Rule 1** — gated writes require BOTH an operator-set flag AND a per-action human
  confirmation token.
- **Rule 6** — all safety logic (redaction, schema, gating, auth) lives in `core/`; the
  server is thin wiring only.
- **Gated Write Actions spec** — four steps: disabled-unless-enabled → dry-run/intent first
  → fresh single-use token required → execute + audit.
- **Small-model-safe** — flat scalar args, ≤8 tools per server, bounded output.

## Key technical finding: isolation is NOT on Graph

Verified against Microsoft Learn (2026-07-10): machine isolation is the Defender for
Endpoint API, not Graph.

- `POST https://api.security.microsoft.com/api/machines/{id}/isolate`
  body `{"Comment": "...", "IsolationType": "Full"}` → `201` + a `machineAction`.
- `POST https://api.security.microsoft.com/api/machines/{id}/unisolate`
  body `{"Comment": "..."}` → `201` + a `machineAction`.
- Permission (application context): **`Machine.Isolate`** on the WindowsDefenderATP API.
- Token audience: **`https://api.security.microsoft.com/.default`** — different from the
  read tools' `https://graph.microsoft.com/.default`.

The read tools (incidents, alerts, hunting) stay on Graph. Only the write path uses the
security.microsoft.com host + audience.

## Architecture

### 1. `core/auth` — parameterize the token audience (minimal core change)

`GraphClient.__init__` already takes `base_url`; add a second optional param `scope`,
defaulting to today's value. `get_token()` uses `self._scope` instead of the hardcoded
string on line 54.

```python
def __init__(self, config, base_url="https://graph.microsoft.com/v1.0",
             scope="https://graph.microsoft.com/.default"):
    ...
    self._scope = scope
```

The Defender write path builds a second client instance:

```python
GraphClient(cfg, base_url="https://api.security.microsoft.com/api",
            scope="https://api.security.microsoft.com/.default")
```

No new client class — one more audience is not a new auth model (consistent with the
"auth models already handled" note in the recipe). `PlatformConfig.from_env` already reads `{PREFIX}_ALLOW_WRITE` into `allow_write`, so
**config needs no new fields** — `DEFENDER_ALLOW_WRITE=true` populates it for free. The
audit log path defaults to `audit-logs/actions.log` (already the `AuditLog` default), so no
new env var is required; an optional override can come later if needed.

The **actor** recorded in the audit trail is a fixed configured string (default
`"mcp-operator"`) — application-context auth has no signed-in user, so we record the operator
identity of the box, not an end user. This is honest about what we can attribute.

### 2. `core/gating` — add the confirmation-token store (real addition)

Today `GatedAction.execute()` accepts a token *string* but nothing generates, validates, or
expires tokens. Add a `TokenStore` alongside it:

- `TokenStore.issue(action, target, ttl_s=900) -> str` — generate a random token
  (`secrets.token_urlsafe`), persist **only its SHA-256 hash** bound to `(action, target,
  expires_at)` as a file under `audit-logs/pending/`, return the plaintext token.
- `TokenStore.consume(action, target, token) -> bool` — hash the presented token, match an
  unexpired record for that exact action+target, delete it (single-use), return success.
  Expired/mismatched/absent → `False`. Sweep expired records on access.

`GatedAction.execute()` gains a `token_store` and calls `consume(...)` in place of the bare
truthiness check. The plaintext token exists only in the operator's terminal and the
in-flight tool call — never persisted, never in model context.

### 3. `scripts/confirm_action.py` — the out-of-band generator

```
python scripts/confirm_action.py isolate_host <device_id> [--ttl 900]
```

Calls `TokenStore.issue("defender.isolate_host", device_id)` and prints the token to the
terminal with a one-line "paste this into the confirmation_token argument" instruction. The
model cannot invoke this to read its output — it runs in the operator's shell.

### 4. `servers/defender-mcp` — two new tools (4 → 6, under the ≤8 rule)

Both flat-arg, both the two-call intent/execute shape:

```python
@mcp.tool()
async def isolate_host(device_id: str, comment: str, confirmation_token: str = "") -> list[dict]:
    """Isolate a device from the network (gated write). Call WITHOUT a token first to see
    the intended action; execution requires an operator-supplied confirmation token."""
```

`release_host` is identical against `/unisolate` (no `IsolationType`).

Tool flow (in `tools.py`, one function per action, thin):

1. **No token → intent.** Return a `finding_type: "action"` Finding: title "WILL isolate
   <device_id>", `recommended_action.gated_action = "defender.isolate_host"`, evidence
   naming target + isolation type, and instructions to run `confirm_action.py`. **No API
   call.** Works even when the flag is off (it's just a description).
2. **Token present → execute** via `GatedAction.execute(target=device_id, actor=..., token=...,
   run=lambda: sec_client.post(...))`:
   - flag off → `GateDenied` → graceful `action` Finding "disabled; set DEFENDER_ALLOW_WRITE".
   - token invalid/expired → `GateDenied` → graceful Finding "invalid or expired token".
   - success → POST to MDE, audit record written, return `action_result` Finding with the
     `machineActionId`.

`server.py` redacts at the boundary (`redact_obj(f.model_dump())`) exactly like the read
tools. MDE errors map through the same `map_graph_error` family (403 → permission-missing
naming `Machine.Isolate`, 429 → rate-limited, 5xx → API-unavailable).

## Data flow

```
Analyst: "isolate DESKTOP-7"
  → model calls isolate_host(device_id, comment)            [no token]
  → intent Finding: "WILL isolate DESKTOP-7. Operator: run confirm_action.py"
Operator (terminal): python scripts/confirm_action.py isolate_host DESKTOP-7
  → prints token T (hash stored, 15-min TTL)
Operator pastes T into chat.
  → model calls isolate_host(device_id, comment, confirmation_token=T)
  → GatedAction: flag on? token valid+unexpired for (isolate_host, DESKTOP-7)?
     → POST api.security.microsoft.com/.../isolate
     → audit-logs/actions.log append {action,target,actor,token}
     → action_result Finding {machineActionId}
```

The model cannot shortcut: without a valid token, step-2 always returns a refusal Finding;
it cannot mint a token because it never sees `confirm_action.py`'s stdout.

## Error handling

Every failure is a Finding, never an exception (existing house rule):
`GateDenied` (flag off / bad token), MDE `403/429/5xx`, and unknown device id (MDE `404`)
all map to graceful `action` findings. Redaction runs on every path including errors.

## Testing

**Contract (mocked MDE client + temp TokenStore dir):**
- flag-off → execute attempt returns refusal Finding, no POST.
- no-token → intent Finding with `gated_action` set, no POST.
- valid token → POST fired once, `action_result` Finding, audit line written, redaction applied.
- bad token / expired token / wrong-target token → refusal Finding, no POST.
- `TokenStore` lifecycle: issue→consume succeeds once; second consume fails (single-use);
  expired record rejected; wrong action/target rejected; only the hash is on disk.
- `release_host` mirror: happy path + flag-off.

**Evals:** task that must produce the *intent* call correctly; a task confirming the model
does NOT fabricate a `confirmation_token`; a negative task confirming it can't jump straight
to execute.

**Live (dry-run + refusals only, sb.gob.do):** flag-off refusal, intent Finding shape,
bad-token rejection. **No device is isolated;** `Machine.Isolate` need not be granted for
this level. The execute POST is proven only against the mock.

## Out of scope (YAGNI)

- Any other action (disable-user, quarantine-file, close-incident).
- A token *server* or web UI — local CLI + file store only.
- Auto-release timer, isolation exclusions, `IsolationType=Selective` (ship `Full`; the arg
  is fixed, not model-chosen).
- Delegated-user auth — application context only, matching every existing server.

## Files touched

| File | Change |
|---|---|
| `core/f0_sectools_core/auth/graph.py` | add `scope` param to `GraphClient` |
| `core/f0_sectools_core/gating/actions.py` | add `TokenStore`; wire into `GatedAction.execute` |
| `core/tests/test_gating.py` | TokenStore lifecycle + gate tests |
| `servers/defender-mcp/f0_defender_mcp/tools.py` | `isolate_host`, `release_host` intent+execute |
| `servers/defender-mcp/f0_defender_mcp/server.py` | register 2 tools; build sec client; redact |
| `servers/defender-mcp/tests/test_tools.py` | contract tests (mock MDE) |
| `scripts/confirm_action.py` | out-of-band token generator |
| `scripts/live_smoke_defender.py` | add dry-run + refusal checks |
| `evals/defender/tasks.yaml` | intent + negative tasks |
| `.env.defender.example`, user-guide | `DEFENDER_ALLOW_WRITE` (+ optional `DEFENDER_AUDIT_ACTOR`), confirm-script workflow |
