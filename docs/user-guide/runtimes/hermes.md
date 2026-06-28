# Runtime: Hermes Agent

[Hermes Agent](https://hermes-agent.nousresearch.com/docs/) (Nous Research) is
the recommended runtime: skills-aware, native MCP, OpenAI-compatible backend, and
a profile system that maps directly onto our four personas.

Prerequisite: finish [getting started](../getting-started.md) (install +
credentials + verify).

## Setup

1. **Install Hermes** and point its model backend at your local
   OpenAI-compatible endpoint (vLLM / llama.cpp) per the Hermes config docs.

2. **Identity** — copy the base identity into place:
   ```bash
   cp integrations/hermes/SOUL.md ~/.hermes/SOUL.md
   ```
   It defines the shared read-only / never-fabricate operating principles.

3. **Config** — merge [`integrations/hermes/config.example.yaml`](../../../integrations/hermes/config.example.yaml)
   into `~/.hermes/config.yaml`. Adjust the absolute paths (`which uv`, your
   checkout). It wires:
   - `mcp_servers` → `f0-defender`, `f0-entra` (stdio, launched via
     `uv run --directory`)
   - `skills.external_dirs` → this repo's `skills/` (loaded **in place** — no
     copying, version-controlled with the code)
   - `agent.personalities` → `ciso`, `threat-hunter`, `detection-engineer`,
     `security-engineer`

## Use it

```text
skills_list                         # shows triage-defender-incident, defender-posture-summary, defender-threat-hunt
/personality ciso                   # adopt the CISO lens
give me a security posture summary  # → defender-posture-summary skill

/personality threat-hunter
hunt for PowerShell downloads today # → defender-threat-hunt skill
```

- **Skills** auto-activate by description, by `/skill-name`, or when you mention
  them; Hermes loads them with progressive disclosure (names first, full content
  on demand).
- **Personas** switch with `/personality <name>` and only change the lens — the
  SOUL.md principles always apply.

## Notes

- Hermes prefixes MCP tools as `mcp_<server>_<tool>` (e.g.
  `mcp_f0-defender_list_incidents`). Skills reference tools by base name; the
  model maps them via the tool descriptions.
- Everything is read-only; no gated write actions are exposed yet.
- The same `skills/` also work in Claude Code and other agentskills.io clients —
  this integration only adds Hermes-specific config and the four profiles.
- Per-server tool scoping (whitelist/blacklist) is available in `mcp_servers`
  via `tools.include` / `tools.exclude` if you want to expose a subset.
