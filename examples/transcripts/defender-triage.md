# Transcript: triaging a Defender incident with a small local model

An annotated session showing the
[`triage-defender-incident`](../../skills/defender/triage-incident/SKILL.md)
skill driving the read-only `f0-defender` server — runtime: Hermes, model:
Qwen3 8B served by llama.cpp. *Illustrative recreation: values are fictional,
but every tool name, argument, and finding shape is exactly what the
live-validated server emits, and the flow follows the skill's procedure
step by step.*

> Annotations look like this — commentary on **why** the model did what it
> did, keyed to the skill's procedure.

---

**Operator:** what's going on with our incidents? only what matters now.

> The phrase matches the skill's *When to Use*; a skills-aware runtime loads
> it. Procedure step 1 says: `severity_min: high` when the user "only wants
> what matters now" — a flat enum arg, not a query language.

**Tool call:** `list_incidents(severity_min="high", limit=25)`

**Findings (2, redacted, abridged):**

```json
[
  {
    "source": "defender", "finding_type": "incident", "severity": "high",
    "title": "Defender incident: Multi-stage attack on web-01 (3 correlated alerts)",
    "entity": { "kind": "host", "id": "web-01", "name": "web-01.corp.local" },
    "evidence": [
      { "key": "alerts", "value": "3" },
      { "key": "status", "value": "active" }
    ],
    "recommended_action": {
      "summary": "Triage the correlated alerts; isolate the host if activity is ongoing.",
      "gated_action": "isolate_host", "confidence": "medium"
    }
  },
  {
    "source": "defender", "finding_type": "incident", "severity": "high",
    "title": "Defender incident: Suspicious mailbox rule for j.doe (1 alert)",
    "entity": { "kind": "user", "id": "j.doe", "name": "j.doe@corp.local" },
    "evidence": [ { "key": "alerts", "value": "1" }, { "key": "status", "value": "active" } ]
  }
]
```

> Bounded output (25 max), normalized shape. Note `gated_action:
> "isolate_host"` — the finding *names* the response tool but nothing is
> invoked; that would require the write flag plus a human confirmation.

**Model (interim):** Two active high-severity incidents. Pulling the
correlated alerts for the multi-stage attack first.

> Procedure step 3 — and the small-model discipline the skill enforces: one
> tool at a time, decide after each result.

**Tool call:** `list_alerts(severity_min="high", limit=25)`

**Findings (3, abridged):**

```json
[
  { "title": "Brute-force authentication against host web-01",
    "references": [ { "type": "mitre", "id": "T1110" } ],
    "evidence": [ { "key": "failed_logins", "value": "142 in 5m" } ] },
  { "title": "Suspicious PowerShell download cradle on web-01",
    "references": [ { "type": "mitre", "id": "T1059.001" } ] },
  { "title": "New inbox rule forwards external mail for j.doe",
    "references": [ { "type": "mitre", "id": "T1114.003" } ] }
]
```

**Model (final answer):**

> Procedure steps 4–5: per-incident summary — *what happened → entity →
> evidence → TTPs → status* — and a next action that stays honest about
> read-only mode.

**Incident 1 — Multi-stage attack on web-01 (HIGH, active).**
Brute-force authentication (T1110, 142 failed logins in 5 minutes) followed by
a PowerShell download cradle (T1059.001) on `web-01.corp.local`. Two of the
three correlated alerts affect this host directly.
*Recommended:* investigate `web-01` now; if activity is ongoing, host
isolation is the response — I'm read-only, so that action needs an operator
(the finding marks `isolate_host` as the gated action).

**Incident 2 — Suspicious mailbox rule for j.doe (HIGH, active).**
A new inbox rule forwards external mail (T1114.003) for `j.doe@corp.local` —
consistent with business-email-compromise persistence.
*Recommended:* review the rule and the account's recent sign-ins (the Entra
identity-risk skill covers that pivot).

---

## What this demonstrates

- **Flat args, closed enums** — the model filled `severity_min="high"` from
  natural language; there was no query syntax to get wrong.
- **Findings chain** — the incident's entity (`web-01`) let the model connect
  the alert list without any platform-specific parsing.
- **Reads never act** — the response action is *named* in the finding and
  explicitly deferred to the [gate](gated-run-test.md).
- **Every claim traces to a finding** — the skill's verification rule; nothing
  in the final answer is invented.

Reproduce the shape offline (no tenant needed):
`uv run python scripts/demo_mock_findings.py`. With a real tenant:
[getting started](../../docs/user-guide/getting-started.md), then ask your
runtime the same question.
