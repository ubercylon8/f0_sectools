# Example MCP client configs

Wiring an f0_sectools server into an MCP-capable agent. Each server ships a
console entry point (`f0-<platform>-mcp`, installed by `uv sync --all-packages`)
and runs as a stdio MCP server; it reads its credentials from `.env.<platform>`
in the repo root (never committed — see `.env.<platform>.example`).

**Tool names differ by runtime.** Skills refer to tools by base name
(`list_incidents`); runtimes prefix them — Hermes `mcp_f0-defender_list_incidents`,
Claude Code `mcp__f0-defender__list_incidents`.

- `mcp.json` — canonical multi-server config (all nine servers) for a generic
  MCP client / Claude Desktop.
- `claude-code.mcp.json` — a Claude Code `.mcp.json` wiring one server (Tenable).
- `generic-stdio.json` — a runtime-agnostic single stdio server entry to adapt.

Replace the `/ABSOLUTE/PATH/TO/sec-tools` placeholder with your checkout path.

**`f0-pa-actions` is reachable by default here — unlike every other template.**
This file ships `f0-pa-actions` (the gated-write ProjectAchilles actions
server) with no `enabled: false` equivalent: the generic MCP config format has
no such flag, so the server is wired in and reachable as soon as its
`.env.projectachilles` is populated. opencode and Hermes both ship it disabled;
this template cannot. Remove the `f0-pa-actions` entry, or leave its
`.env.projectachilles` unconfigured, unless you actually want a gated-write
server available to this client.

`integrations/test_integrations_valid.py` guards this file the same way it
guards the Hermes/pi/opencode templates — the server list is checked against
the live registry, the placeholder path is checked, and the caveat above is
checked to still be here, because on this template it is the only safeguard.
