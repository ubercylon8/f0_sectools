# Transcript: a gated write — refusal, intent, approval, execution

An annotated session showing the full lifecycle of a gated write action on the
`f0-pa-actions` server (`run_test` — running a ProjectAchilles validation test
on one host), including the two paths that **fail closed**. *Illustrative
recreation: values are fictional; the refusal messages, intent shape, watcher
flow, and audit line match the implementation in `core/gating/` exactly.*

The rule being demonstrated
([security model](../../docs/explanation/security-model.md#gated-write-actions)):
**execution requires BOTH the platform write flag AND a per-action human
confirmation delivered out-of-band — the model alone can never act.**

---

## Path 0 — flag off: the gate refuses (default state)

**Operator:** run the phishing-simulation test on web-01.

**Tool call:** `run_test(test_id="3f9d…", hostname="web-01")`

**Finding (posture):**

```
Action 'projectachilles.run_test' is disabled.
Set the platform write flag to enable it.
```

> With `PROJECTACHILLES_ALLOW_WRITE` unset, the write tools are inert. This is
> the state every server ships in. Enabling writes is a deliberate deployment
> decision, made in a file the model cannot edit.

## Path 1 — flag on: intent first, never execution

*The operator has set `PROJECTACHILLES_ALLOW_WRITE=true` in
`.env.projectachilles` and restarted the server.*

**Tool call:** `run_test(test_id="3f9d…", hostname="web-01")` — no
`confirmation_token`.

**Finding (intent, `finding_type: "action"`, abridged — full shape in
[`examples/findings/projectachilles-actions.json`](../findings/projectachilles-actions.json)):**

```json
{
  "finding_type": "action", "severity": "info",
  "title": "INTENT (not executed): run_test T1566-phish-sim on host web-01",
  "evidence": [
    { "key": "action", "value": "run_test" },
    { "key": "matched_hosts", "value": "1" },
    { "key": "status", "value": "awaiting operator confirmation (watcher or token)" }
  ]
}
```

> First call = preview, always. The intent states exactly what would run and
> where. For a tag/fleet run the intent lists the matched host **count**, and
> the confirmation is bound to that count — if membership changes, the model
> must re-preview and the operator must re-approve.

**Model:** I've prepared the run. A pending approval is registered — please
approve it in your watcher terminal, then ask me to proceed.

## The approval — in a terminal the model cannot read

```console
$ python scripts/confirm_action.py --watch
Watching for gated-action requests (~/.f0sectools/gating/requests) — Ctrl-C to stop.
projectachilles.run_test -> 3f9d…|web-01 — approve? [y/N] y
APPROVED projectachilles.run_test -> 3f9d…|web-01 (15 min, single use)
```

> This is the forge-resistant part. The approval is written to
> `$F0_GATING_DIR/approvals/` by the *operator's* CLI. No token, no approval
> text, nothing confirmable ever appears in model context — there is nothing
> the model could echo, replay, or invent. (Headless alternative:
> `confirm_action.py <action> "<target>"` prints a single-use token the
> operator passes along — same guarantees, hash-only at rest.)

## Path 2 — execution: the identical call consumes the approval

**Operator:** approved — go ahead.

**Tool call:** `run_test(test_id="3f9d…", hostname="web-01")` — the *identical*
call.

**Finding (result, abridged):**

```json
{
  "finding_type": "action", "severity": "info",
  "title": "Executed: run_test T1566-phish-sim on web-01 (task queued)",
  "evidence": [ { "key": "task_id", "value": "9c21…" } ]
}
```

> The gate consumed the stored approval — single-use, unlink-before-validate,
> so a concurrent duplicate call cannot also win. A second identical call now
> would return a fresh intent, not an execution.

**The audit line** (`$F0_GATING_DIR/audit.log`, local only):

```json
{"action": "projectachilles.run_test", "target": "3f9d…|web-01",
 "actor": "f0-pa-actions", "method": "approval", "token_ref": "a1b2c3d4…"}
```

*(`token_ref` is the first 16 hex chars of a SHA-256 — truncated here so the
fictional example doesn't trip secret scanners.)*

---

## What this demonstrates

| Property | Where it showed up |
|---|---|
| Fail closed, twice | flag off → refusal; flag on but unconfirmed → intent only |
| Out-of-band confirmation | approval happened in the watcher terminal, invisible to the model |
| Single-use, target-bound, TTL'd | the approval died on consumption; it named one action on one target; 15-minute expiry |
| Audited | one JSONL line linking execution to its confirmation by hash reference |

The convenience mode (`chat-confirm`, opt-in per platform) trades away the
out-of-band property for supervised reversible actions — its honest caveat is
in the [security model](../../docs/explanation/security-model.md#layer-2--human-confirmation-three-surfaces).
It is never wired to destructive actions.
