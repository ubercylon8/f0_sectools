# Using skills & personas

Two complementary mechanisms shape how the agent uses the tools.

## Skills (playbooks)

Skills are step-by-step procedures the agent follows for a task. They live in
[`skills/`](../../skills/) as portable [agentskills.io](https://agentskills.io)
`SKILL.md` packages and work in any skills-aware runtime (Hermes, Claude Code,
pi, opencode).

**The full, always-current list is the [skills catalog](../reference/skills.md)**
— all 25 skills by platform, generated from their `SKILL.md` frontmatter (so it
cannot drift). Each platform has a default-focus skill (e.g. Defender's
incident triage, Intune's compliance review, Tenable's exposure-posture
review); the [tool reference](../reference/tools/README.md) shows the inverse
mapping — which skills drive each tool.

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
- **pi:** invoke `/ciso` (prompt templates in
  [`integrations/pi/prompts/`](../../integrations/pi/prompts/)); the same four
  lenses.
- **LM Studio / Open WebUI / Claude Code:** the same modes are in the portable
  prompt — say "as a CISO…" / "switch to threat hunter".

## How they combine

Persona sets the lens; the skill provides the procedure. *"As a CISO, summarize
our posture"* → CISO persona frames the output, `defender-posture-summary` skill
runs the steps. *"As a threat hunter, look into the exfiltration incident"* →
hunter persona + `triage-defender-incident`.
