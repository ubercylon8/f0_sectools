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

## ProjectAchilles test catalog (detection engineer / threat hunter)

> **Prompt:** "How many ProjectAchilles tests do we have for T1110, and what does the Kerberoast test cover?"

The `explore-test-catalog` skill uses `find_tests` (by technique, actor, tactic,
category, tag, or keyword) to enumerate the available tests — the library of what
*can* be run, not run history — and `get_test` for one test's full detail
(description, OS/target, techniques, tactics). Lead with the exact match count
from the summary finding.

## Run & manage validation tests (security engineer) — gated writes

> **Prompt:** "Run the Kerberoast test on the windows fleet, then show me the
> results per host."

The `run-validation-test` skill drives the **actions** server
(`f0-projectachilles-actions-mcp`). Every state-changing call is gated — it needs
a read-write `pa_` key, `PROJECTACHILLES_ALLOW_WRITE=true`, and a per-action human
confirmation — and each returns an intent preview first, so nothing runs until you
approve it:

- **Run or schedule** — `run_test` / `schedule_test` on a single host (`hostname`)
  **or a whole tag/fleet** (`tag` — every agent carrying it, fanned out in one
  gated action; the confirmation is bound to the matched host *count*, and a
  >200-host tag is refused).
- **Check progress** — `list_tasks(status="pending")` sweeps every task of a run
  in one call (per-host rows), instead of polling each task id.
- **Per-host results** — `list_test_executions` on the read server, scoped with
  `test=` and/or `tag=`, gives the outcome for each host (bundle runs roll up to
  one COMPLIANT / NON-COMPLIANT finding per host).
- **Cancel** — `cancel_tasks` cancels one task, or bulk-cancels a run's pending
  tasks by `status`/`search` in one count-bound gated action.

See [Gated write actions](getting-started.md) for the confirmation flow (watcher,
token, or opt-in chat-confirm).

## Intune device compliance (CISO / security engineer) — default focus

> **Prompt:** "How compliant are our Intune-managed devices?"

The `intune-device-compliance-review` skill runs `get_compliance_summary` and
`list_compliance_policies` to report how many devices are compliant vs
non-compliant/unknown, what the enforcing policies are, and the highest-value
next step. Unknown means unevaluated, not "safe".

## Intune coverage gaps (security engineer)

> **Prompt:** "Which devices are stale, non-compliant, or unencrypted?"

The `intune-coverage-gap-review` skill uses `get_compliance_summary`,
`list_stale_devices`, and `list_managed_devices` (non-compliant) to build a
prioritized remediation list — stale (not syncing), unencrypted, and
non-compliant devices first. (`list_stale_devices` is bounded to `limit`; raise
it to widen the net.)

## Intune device triage (SOC analyst) — cross-platform pivot

> **Prompt:** "What's the Intune state of the device in this incident?"

The `intune-device-triage` skill takes a device name (often from a Defender
incident) and runs `get_managed_device` to report its compliance, encryption,
owner, last sync, and assigned user — a device-first pivot during triage. If the
Defender name doesn't match, try the hostname variant.

## Tenable exposure posture (security engineer) — default focus

> **Prompt:** "As a security engineer, give me our Tenable exposure posture."

The `review-exposure-posture` skill (Tenable's default focus) calls
`get_vulnerability_summary` for the headline severity breakdown, then
`list_top_vulnerabilities` for the fix-first list and `list_scans` to flag any
stale-scan caveat.

## Tenable host vulnerability triage (SOC analyst)

> **Prompt:** "What's wrong with host web-01 in Tenable?"

The `triage-host-vulnerabilities` skill calls `list_assets` to confirm the
host, `get_asset_vulnerabilities` (severity_min=high) to enumerate its
vulnerabilities, and `get_vulnerability_info` for remediation detail on the
top findings.

## Tenable scan coverage review (security engineer)

> **Prompt:** "Are our Tenable scans covering everything?"

The `review-scan-coverage` skill runs `list_scans` to flag failed/stale scans
and `list_assets` to gauge the inventory those scans should cover, then
reports where coverage looks thin.

## Cross-platform incident triage (SOC analyst / threat hunter)

> **Prompt:** "Triage this Defender incident and give me the full picture."

The `triage-incident-cross-platform` skill pivots across multiple servers:
`list_incidents` (Defender) → for the involved user, `list_risky_users` /
`list_risk_detections` (Entra) → for the host, `get_sensor` + `query_telemetry`
(LimaCharlie) → for the technique, `get_weak_techniques` (ProjectAchilles). It
returns one correlated summary and flags any cross-platform join it could not
confirm by name. Read-only. Favours a capable local model (e.g. GPT-OSS 20B).

## Offensive/defensive loop (detection engineer)

> **Prompt:** "Turn our weak techniques into a retest plan."

The `validation-coverage-loop` skill runs `get_weak_techniques` (ProjectAchilles)
→ checks each against `list_dr_rules` / `list_detections` (LimaCharlie) → and
recommends which **f0_library** test to re-run for techniques that are weak and
uncovered. f0_library is the separate offensive repo the operator runs — the
skill only recommends. Read-only.

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
2. **Confirm (your turn, out-of-band).** Two equivalent ways, both single-use,
   target-bound, and expire in 15 minutes:

   - **Watcher (default).** In your own terminal — not through the model —
     run `python scripts/confirm_action.py --watch`. The pending request
     appears there automatically; approve it with one keypress. Then tell
     the agent to retry: it re-runs `isolate_host` with the SAME arguments
     and no `confirmation_token` — the gate consumes the stored approval, so
     no token ever enters model context.
   - **Token (fallback, headless/scripted).** In your own terminal — not
     through the model — run:

     ```bash
     uv run python scripts/confirm_action.py isolate_host <device_id>
     ```

     This prints a single-use confirmation token. The token is generated
     out-of-band in your shell; the model never sees it and cannot request or
     fabricate one, so it can never self-confirm. Paste the token back into
     the chat as the `confirmation_token` argument to re-run `isolate_host` —
     only then does the tool call the Defender isolate API.

Writes are also disabled at the config level unless `DEFENDER_ALLOW_WRITE=true`
is set in `.env.defender` — even with a valid token, the tool refuses if the
flag is off. Every action that actually executes is recorded to the local
audit trail at `$F0_GATING_DIR/audit.log` (default
`~/.f0sectools/gating/audit.log`; override via `DEFENDER_AUDIT_LOG_PATH` /
`PROJECTACHILLES_AUDIT_LOG_PATH`), which stores the actor, target, action
name, and a truncated SHA-256 **fingerprint** of the token — never the
plaintext token itself. (Refused attempts — flag off or an invalid token — are
rejected before execution and are not written to the audit trail; they surface
to the operator as a refusal finding instead.)

The MCP server and `scripts/confirm_action.py` do **not** need to be run from
the same working directory. Gating state (pending requests, approvals, and
tokens) lives under `$F0_GATING_DIR` (default `~/.f0sectools/gating/`), a
fixed location shared by every server and the CLI regardless of CWD.

---

### What to expect when something isn't granted

If a permission or license is missing (or the platform is throttling), the tool
returns a `posture` finding like *"Permission 'IdentityRiskyUser.Read.All' not
granted"* or *"Rate limited — retry shortly"*. The agent relays it instead of
failing. See [troubleshooting](troubleshooting.md).
