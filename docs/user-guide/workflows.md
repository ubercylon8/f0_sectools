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

---

### What to expect when something isn't granted

If a permission or license is missing (or the platform is throttling), the tool
returns a `posture` finding like *"Permission 'IdentityRiskyUser.Read.All' not
granted"* or *"Rate limited — retry shortly"*. The agent relays it instead of
failing. See [troubleshooting](troubleshooting.md).
