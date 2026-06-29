# Using skills & personas

Two complementary mechanisms shape how the agent uses the tools.

## Skills (playbooks)

Skills are step-by-step procedures the agent follows for a task. They live in
[`skills/`](../../skills/) as portable [agentskills.io](https://agentskills.io)
`SKILL.md` packages and work in any skills-aware runtime (Hermes, Claude Code).

| Skill | Use it for | Tools |
|-------|-----------|-------|
| `triage-defender-incident` | Investigate an incident: gather alerts, summarize, recommend | `list_incidents`, `list_alerts` |
| `defender-posture-summary` | Leadership rollup: secure score + open incidents | `get_secure_score`, `list_incidents` |
| `defender-threat-hunt` | Guided KQL hunting (last 30 days) with safe starters | `run_hunting_query` |
| `review-entra-identity-risk` | Review ID Protection risky users + detections (P2) | `list_risky_users`, `list_risk_detections` |
| `audit-conditional-access` | Audit CA policies; flag disabled/report-only | `list_conditional_access_policies` |
| `review-privileged-access` | Review privileged role holders; flag admin sprawl | `list_privileged_role_assignments` |
| `review-detection-coverage` | D&R coverage vs recent detections (the loop) | `get_org_overview`, `list_dr_rules`, `list_detections` |
| `investigate-lc-endpoint` | Investigate a sensor: status + telemetry | `get_sensor`, `list_sensors`, `query_telemetry` |
| `limacharlie-threat-hunt` | Guided LCQL telemetry hunting | `query_telemetry` |

In skills-aware runtimes they activate automatically by description, when you
name them, or via `/skill-name`. In non-skill UIs (LM Studio, Open WebUI) the
same guidance is baked into the
[portable system prompt](../../prompts/f0-sectools-system-prompt.md).

## Personas (role lenses)

A persona changes the agent's *focus and output style* — not what it can do.
The shared read-only / never-fabricate principles always apply.

| Persona | Focus | Output |
|---------|-------|--------|
| **CISO** | risk rollups, secure-score, top exposures | aggregated, business-framed, brief |
| **Threat hunter** | hypothesis-driven hunting, incident/alert correlation | technical, MITRE TTPs, timelines |
| **Detection engineer** | alert quality, coverage, tuning | detection gaps and fixes |
| **Security engineer** | misconfig, hardening, conditional access | concrete configuration changes |

- **Hermes:** switch with `/personality ciso` (defined in
  [`integrations/hermes/config.example.yaml`](../../integrations/hermes/config.example.yaml)).
- **LM Studio / Open WebUI / Claude Code:** the same modes are in the portable
  prompt — say "as a CISO…" / "switch to threat hunter".

## How they combine

Persona sets the lens; the skill provides the procedure. *"As a CISO, summarize
our posture"* → CISO persona frames the output, `defender-posture-summary` skill
runs the steps. *"As a threat hunter, look into the exfiltration incident"* →
hunter persona + `triage-defender-incident`.
