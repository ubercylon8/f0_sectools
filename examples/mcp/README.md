# Example MCP client configs

Wiring an f0_sectools server into an MCP-capable agent. Each server is a stdio
MCP server launched with `uv run`; it reads its credentials from
`.env.<platform>` in the repo root (never committed — see `.env.<platform>.example`).

**Tool names differ by runtime.** Skills refer to tools by base name
(`list_incidents`); runtimes prefix them — Hermes `mcp_f0-defender_list_incidents`,
Claude Code `mcp__f0-defender__list_incidents`.

- `claude-code.mcp.json` — a Claude Code `.mcp.json` wiring the Tenable server.
- `generic-stdio.json` — a runtime-agnostic stdio server entry you can adapt.

Replace `/abs/path/to/f0_sectools` with your checkout path.
