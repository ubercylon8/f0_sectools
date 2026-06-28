# Running f0_sectools with Hermes Agent

[Hermes Agent](https://hermes-agent.nousresearch.com/docs/) (Nous Research) is a
skills-aware autonomous agent with native MCP support and an OpenAI-compatible
model backend — a first-class runtime for f0_sectools with a local model.

This integration gives you three things with **no duplicated logic**:

1. the read-only **Defender + Entra MCP servers** wired in,
2. the repo's **skills** loaded in place (agentskills.io standard), and
3. four switchable **role profiles** (CISO, threat hunter, detection engineer,
   security engineer).

## Setup

1. **Install Hermes** and point its model backend at your local OpenAI-compatible
   endpoint (vLLM or llama.cpp) per the Hermes configuration docs.

2. **Credentials** — fill `.env.defender` / `.env.entra` at the repo root (see
   each server's `.env.*.example`). They never enter Hermes config.

3. **Identity** — copy [`SOUL.md`](SOUL.md) to `~/.hermes/SOUL.md` (or
   `$HERMES_HOME/SOUL.md`). It defines the shared read-only / never-fabricate
   operating principles.

4. **Config** — merge [`config.example.yaml`](config.example.yaml) into
   `~/.hermes/config.yaml`, adjusting the absolute paths (`which uv`, your
   checkout path). It wires:
   - `mcp_servers` → `f0-defender`, `f0-entra`
   - `skills.external_dirs` → this repo's `skills/` (loaded in place)
   - `agent.personalities` → the four role profiles

5. **Verify** — start Hermes and try:
   - `skills_list` shows `triage-defender-incident`, `defender-posture-summary`,
     `defender-threat-hunt`.
   - `/personality ciso` then "give me a posture summary".
   - `/personality threat-hunter` then "hunt for PowerShell downloads today".

## Notes

- Hermes prefixes MCP tools as `mcp_<server>_<tool>` (e.g.
  `mcp_f0-defender_list_incidents`). Skills refer to tools by base name; the
  model maps them via the tool descriptions.
- Everything here is read-only. No gated write actions are exposed yet.
- The same `skills/` folder also works in Claude Code and other agentskills.io
  clients — this integration only adds the Hermes-specific config and profiles.
