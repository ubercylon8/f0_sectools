# Example workflows

End-to-end tasks you can run today, with the prompts to use. These work in any
runtime; in Hermes prefix with `/personality <name>` to set the lens, elsewhere
say "as a <role>".

## Morning posture check (CISO)

> **Prompt:** "As a CISO, give me this morning's security posture."

The agent calls `get_secure_score` and `list_incidents`, then returns a short
rollup: Secure Score %, open incidents by severity, the top 2–3 exposures, and
one recommended focus. No IDs or raw JSON.

## Incident triage (SOC analyst / threat hunter)

> **Prompt:** "Triage our active high-severity incidents."

The `triage-defender-incident` skill runs: `list_incidents` (`severity_min:
high`) → for each, `list_alerts` to pull correlated alerts → a per-incident
summary (what happened, entity, evidence, MITRE techniques, status) → a
recommended next step. Containment is read-only/not available — it says so.

## Threat hunt (threat hunter)

> **Prompt:** "Hunt for PowerShell processes that downloaded files in the last
> day."

The `defender-threat-hunt` skill picks a bounded KQL query from
[`references/kql-starters.md`](../../skills/defender/threat-hunt/references/kql-starters.md),
calls `run_hunting_query`, reviews the returned rows, optionally refines, and
summarizes findings + TTPs. Hunting covers the **last 30 days**.

## Identity risk review (security engineer)

> **Prompt:** "As a security engineer, review our identity risk and privileged
> access."

Calls `list_risky_users` and `list_risk_detections` (Entra ID Protection, P2),
`list_conditional_access_policies` (flagging disabled/report-only), and
`list_privileged_role_assignments` (highlighting Global/Security Admins).
Returns concrete hardening recommendations.

## Detection coverage check (detection engineer)

> **Prompt:** "As a detection engineer, look at our recent alerts and coverage."

Calls `list_alerts`, maps them to MITRE techniques, flags noisy/low-signal
detections (e.g. repetitive DLP), and notes coverage gaps to tune.

## LimaCharlie endpoint investigation (SOC analyst / threat hunter) — default focus

> **Prompt:** "Investigate the endpoint web-01 in LimaCharlie."

The `investigate-lc-endpoint` skill calls `get_sensor` (status, platform), then a
bounded `query_telemetry` LCQL scoped to the host, and summarizes notable
activity with a recommended next step. This is the LimaCharlie server's default
focus — an underspecified LimaCharlie request resolves toward investigating
endpoints.

## LimaCharlie detection-coverage review (detection engineer / CISO)

> **Prompt:** "Review our LimaCharlie detection coverage."

The `review-detection-coverage` skill runs `get_org_overview` (sensors, rule
count, 24h detection volume), `list_dr_rules` (separating detection rules from
output/forwarding rules), and `list_detections`, then reports which rules are
firing, which are silent, and where coverage gaps are. This is the
offensive↔defensive loop — it reads back the D&R rules `f0_library` deploys.

## LimaCharlie threat hunt (threat hunter)

> **Prompt:** "Hunt for PowerShell download cradles across our endpoints."

The `limacharlie-threat-hunt` skill picks a bounded LCQL query from
[`references/lcql-starters.md`](../../skills/limacharlie/threat-hunt/references/lcql-starters.md),
runs `query_telemetry`, reviews the rows, refines, and summarizes findings + TTPs.

## ProjectAchilles defense posture (CISO)

> **Prompt:** "As a CISO, how validated is our defense in ProjectAchilles?"

The `review-defense-posture` skill runs `get_defense_score` (snapshot, then again
with `over_time=true` for the trend) and `get_weak_techniques`, then reports the %
of simulated attacks blocked/detected, the trend, the top weak MITRE techniques,
and the highest-value improvement. (The raw score can differ from the PA dashboard
depending on filters — treat it as directional.)

## ProjectAchilles coverage gaps (detection engineer)

> **Prompt:** "Where are our control gaps in ProjectAchilles?"

The `analyze-coverage-gaps` skill correlates `get_weak_techniques` with the
NOT-blocked `list_test_executions`, prioritizes by severity, and recommends
specific control/detection fixes for the techniques that aren't being blocked.

## ProjectAchilles validation fleet (security engineer)

> **Prompt:** "Is our security validation actually running across the estate?"

The `review-validation-fleet` skill uses `get_fleet_health`, `list_agents`, and
`list_risk_acceptances` to report test-agent coverage (online vs total),
offline/stale agents that leave endpoints unvalidated, and the risks formally
accepted.

## Gated write actions (isolate/release a host)

> **Prompt:** "Isolate device web-01, it's showing active ransomware behavior."

Defender's `isolate_host` / `release_host` are the only tools that change state
on a live platform, so they're gated read-only-by-default (Critical Rule 1) — a
small local model can never isolate a host on its own. The flow is two steps,
split across the model and the operator:

1. **Intent (the model's turn).** The agent calls `isolate_host` with no
   `confirmation_token`. This does **not** touch the API — it returns an
   `action` finding describing exactly what it intends to do (device, action,
   `gated_action: defender.isolate_host`) and asks you to confirm.
2. **Confirm (your turn, out-of-band).** In your own terminal — not through the
   model — run:

   ```bash
   uv run python scripts/confirm_action.py isolate_host <device_id>
   ```

   This prints a single-use confirmation token. The token is generated
   out-of-band in your shell; the model never sees it and cannot request or
   fabricate one, so it can never self-confirm. Paste the token back into the
   chat as the `confirmation_token` argument to re-run `isolate_host` — only
   then does the tool call the Defender isolate API.

Writes are also disabled at the config level unless `DEFENDER_ALLOW_WRITE=true`
is set in `.env.defender` — even with a valid token, the tool refuses if the
flag is off. Every executed action (and every refused attempt) is recorded to
the local audit trail at `audit-logs/actions.log`, which stores the actor,
target, action name, and a truncated SHA-256 **fingerprint** of the token —
never the plaintext token itself.

---

### What to expect when something isn't granted

If a permission or license is missing (or the platform is throttling), the tool
returns a `posture` finding like *"Permission 'IdentityRiskyUser.Read.All' not
granted"* or *"Rate limited — retry shortly"*. The agent relays it instead of
failing. See [troubleshooting](troubleshooting.md).
