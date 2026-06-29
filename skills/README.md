# skills/

Portable **playbooks** that orchestrate the f0_sectools MCP servers to complete
a security task end-to-end (triage an incident, summarize posture, run a hunt).

## Format: the agentskills.io open standard

These are standard [Agent Skills](https://agentskills.io) — the open `SKILL.md`
format (originally Anthropic's, now an open standard adopted by Hermes, Claude
Code, Goose, OpenHands, Cursor, and many others). **One skill set works across
every skills-aware runtime** — we do not maintain runtime-specific copies.

Each skill is a directory:

```
skills/<category>/<skill-name>/
  SKILL.md            # required: YAML frontmatter (name, description, …) + instructions
  references/         # optional: supporting docs the agent loads on demand
  templates/ scripts/ assets/   # optional
```

`SKILL.md` frontmatter carries `name`, `description`, `version`, and an optional
`metadata.hermes` block (tags, category) that Hermes uses and other runtimes
ignore — so the additive metadata never breaks portability.

## How each runtime loads these

- **Hermes Agent** — point `~/.hermes/config.yaml → skills.external_dirs` at this
  folder (in place, no copying). See [`../integrations/hermes/`](../integrations/hermes/).
- **Claude Code / other agentskills.io clients** — discovered from their skills
  path; the same files work unmodified.
- **Non-skill UIs (LM Studio, Open WebUI)** — these have no skill system. Use the
  portable system prompt in [`../prompts/`](../prompts/) instead, which carries
  the same guidance as paste-in content.

## Tool-name prefixes (one portability note)

Skills refer to tools by **base name** (`list_incidents`, `get_secure_score`).
Runtimes prefix MCP tools differently — Hermes: `mcp_f0-defender_list_incidents`;
Claude Code: `mcp__f0-defender__list_incidents`. The model maps base name →
actual tool via the tool description; the per-runtime prefix is documented in
each server's README and the Hermes integration guide.

## Current skills

| Skill | Purpose |
|-------|---------|
| `defender/triage-incident` | Investigate a Defender incident: gather, summarize, recommend |
| `defender/posture-summary` | Secure score + open incidents → leadership rollup |
| `defender/threat-hunt` | Guided advanced-hunting (KQL) with safe starter queries |
| `entra/identity-risk-review` | Review ID Protection risky users + risk detections |
| `entra/conditional-access-audit` | Audit CA policies; flag disabled/report-only gaps |
| `entra/privileged-access-review` | Review privileged role holders; flag admin sprawl |
| `limacharlie/endpoint-investigation` | Investigate a sensor: status + telemetry (default focus) |
| `limacharlie/detection-coverage-review` | D&R rule coverage vs recent detections (the loop) |
| `limacharlie/threat-hunt` | Guided LCQL telemetry hunting with safe starters |
