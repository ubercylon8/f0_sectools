# Runtime: pi

[pi](https://pi.dev/docs/latest) (earendil-works) is a minimal, extensible
terminal agent harness. It speaks the same **agentskills.io** skill format we use,
carries personas as prompt templates, and runs local or hosted models — so for
fully-local, privacy-preserving operation, point it at your own endpoint (step 2).

**One caveat up front:** pi **intentionally ships no built-in MCP support**. Our
value is the MCP servers, so we bridge them with the production-ready
[`pi-mcp-extension`](https://pi.dev/packages/pi-mcp-extension) (step 3). No bridge
code is shipped from this repo — you install and configure the extension.

Prerequisite: finish [getting started](../getting-started.md).

## 1. Install pi

Install pi per its [quickstart](https://pi.dev/docs/latest/quickstart).

## 2. Point pi at your local model

Add a local OpenAI-compatible provider in `~/.pi/agent/models.json`:

```json
{
  "providers": {
    "f0-local": {
      "baseUrl": "http://localhost:8000/v1",
      "api": "openai-completions",
      "apiKey": "$OPENAI_API_KEY",
      "models": [
        { "id": "your-model-name" }
      ]
    }
  }
}
```

- `baseUrl` — your vLLM (`:8000`) or llama.cpp (`:8080`) endpoint.
- `apiKey` — a literal, `"$ENV_VAR"`, or `"!command"`. vLLM/llama.cpp accept any
  token; a dummy or env var is fine.

Select the model with `/model` (the file reloads without a restart).

## 3. Bridge in the MCP servers

Install the MCP client extension:

```bash
pi install npm:pi-mcp-extension
```

Then declare our servers in `~/.pi/agent/mcp.json` (or project-level
`.pi/mcp.json`). A ready copy lives at
[`integrations/pi/mcp.json`](../../../integrations/pi/mcp.json) — copy it and
replace the placeholder path with your checkout:

```json
{
  "settings": { "toolPrefix": "mcp", "requestTimeoutMs": 30000, "maxRetries": 5 },
  "mcpServers": {
    "f0-defender": {
      "command": "uv",
      "args": ["run", "--directory", "/ABSOLUTE/PATH/TO/sec-tools", "f0-defender-mcp"],
      "transport": "stdio",
      "lifecycle": "lazy"
    }
  }
}
```

(The shipped file wires all six servers.)

- `lifecycle: "lazy"` spawns a server on first use, not all six at startup.
- **No credentials here.** Each server loads its own `.env.<platform>` from the
  repo root — secrets never enter `mcp.json`.
- Bridged tools appear as `mcp_f0-<server>_<tool>` (e.g.
  `mcp_f0-defender_list_incidents`) — the same scheme Hermes uses, so our skills
  work unchanged.

## 4. Base identity (the SOUL.md equivalent)

pi has no `SOUL.md`; it auto-loads `AGENTS.md` context files. Copy our base
identity into place:

```bash
cp integrations/pi/AGENTS.md ~/.pi/agent/AGENTS.md
```

It carries the same read-only / never-fabricate principles as the Hermes
`SOUL.md`. (For a full system-prompt replacement instead, use `.pi/SYSTEM.md`.)

## 5. Skills

Load our skills unmodified by adding the directory to `~/.pi/agent/settings.json`:

```json
{ "skills": ["/ABSOLUTE/PATH/TO/sec-tools/skills"] }
```

They're the same agentskills.io `SKILL.md` packages Hermes uses. pi loads names
and descriptions at startup and reads the full skill on demand; invoke one
explicitly with `/skill:name`, or pass `--no-skills` to disable discovery.

## 6. Personas (prompt templates)

pi carries personas as **prompt templates** — one `.md` per lens, invoked as a
slash command. Point pi at ours in `settings.json`:

```json
{ "prompts": ["/ABSOLUTE/PATH/TO/sec-tools/integrations/pi/prompts"] }
```

This registers `/ciso`, `/threat-hunter`, `/detection-engineer`, and
`/security-engineer`. Each overlays the base `AGENTS.md` identity — the same
lenses as Hermes' `/personality`.

## 7. Use it

```text
/ciso
give me a security posture summary
# → defender-posture-summary skill → mcp_f0-defender_get_secure_score +
#   mcp_f0-defender_list_incidents, framed for an executive.

/threat-hunter
hunt for PowerShell downloads today
# → defender-threat-hunt skill → mcp_f0-defender_run_hunting_query (KQL, bounded).
```

## Notes

- Everything is read-only; no gated write actions are exposed.
- The `skills/` are the same files Hermes and Claude Code use — no pi-specific
  copies.
- pi extensions run with full permissions — install `pi-mcp-extension` only from
  the trusted source linked above.
- Wiring for this runtime lives in
  [`integrations/pi/`](../../../integrations/pi/) (`mcp.json`, `AGENTS.md`, and the
  four persona prompt templates).
