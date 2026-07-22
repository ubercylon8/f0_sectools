<!-- GENERATED FILE - do not edit. Regenerate with: uv run python scripts/gen_docs.py -->

# Tool reference

**51 tools across 8 MCP servers**, harvested from the live FastMCP registries. Every tool returns the normalized [findings schema](../../explanation/findings-schema.md); every server follows the [thin-server pattern](../../explanation/architecture.md#the-server-pattern).

Skills refer to tools by base name (`list_incidents`); runtimes prefix them (Hermes `mcp_f0-defender_list_incidents`, Claude Code `mcp__f0-defender__list_incidents`).

| Server | Platform module | Tools | Gated writes |
|---|---|---|---|
| [`f0-defender`](defender.md) | `f0_defender_mcp.server` | 7 | 2 |
| [`f0-entra`](entra.md) | `f0_entra_mcp.server` | 4 | — |
| [`f0-intune`](intune.md) | `f0_intune_mcp.server` | 6 | — |
| [`f0-limacharlie`](limacharlie.md) | `f0_limacharlie_mcp.server` | 6 | — |
| [`f0-projectachilles`](projectachilles.md) | `f0_projectachilles_mcp.server` | 8 | — |
| [`f0-pa-actions`](projectachilles-actions.md) | `f0_pa_actions_mcp.server` | 7 | 4 |
| [`f0-purview`](purview.md) | `f0_purview_mcp.server` | 6 | — |
| [`f0-tenable`](tenable.md) | `f0_tenable_mcp.server` | 7 | — |
