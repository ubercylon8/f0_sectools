# servers/

One **thin MCP server per security platform**. Each server imports
[`core`](../core) and contains only what is platform-specific: the API client
and the tool definitions.

**Pattern (see [CONTRIBUTING.md](../CONTRIBUTING.md) and [../CLAUDE.md](../CLAUDE.md)):**

- Read tools first; target ≤ ~8 flat tools per server.
- All output goes through `core` (schema, redaction, paging) — never hand-rolled.
- Write actions route through `core/gating/` (config flag + confirmation token).
- Ship `.env.<platform>.example`, contract tests, and an `evals/` task set.

**Built & live-validated (8):** `defender-mcp`, `entra-mcp`, `limacharlie-mcp`,
`projectachilles-mcp`, `projectachilles-actions-mcp` (gated writes),
`intune-mcp`, `tenable-mcp`, `purview-mcp`. Each server's README documents its
tools, required credentials/permissions, and smoke test.

Planned: `wazuh-mcp`, `elastic-mcp`, `splunk-mcp`, `sentinel-mcp`,
`crowdstrike-mcp`, `sentinelone-mcp`, `sophos-mcp`, `misp-mcp`, `thehive-mcp`,
`opencti-mcp`.
