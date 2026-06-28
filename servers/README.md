# servers/

One **thin MCP server per security platform**. Each server imports
[`core`](../core) and contains only what is platform-specific: the API client
and the tool definitions.

**Pattern (see [CONTRIBUTING.md](../CONTRIBUTING.md) and [../CLAUDE.md](../CLAUDE.md)):**

- Read tools first; target ≤ ~8 flat tools per server.
- All output goes through `core` (schema, redaction, paging) — never hand-rolled.
- Write actions route through `core/gating/` (config flag + confirmation token).
- Ship `.env.<platform>.example`, contract tests, and an `evals/` task set.

Planned: `wazuh-mcp` (reference), `elastic-mcp`, `splunk-mcp`, `sentinel-mcp`,
`defender-mcp`, `crowdstrike-mcp`, `sentinelone-mcp`, `sophos-mcp`, `entra-mcp`,
`misp-mcp`, `thehive-mcp`, `opencti-mcp`.
