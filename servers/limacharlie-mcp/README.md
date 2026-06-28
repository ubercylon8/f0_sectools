# f0-limacharlie-mcp

Read-only [Model Context Protocol](https://modelcontextprotocol.io) server for
**[LimaCharlie](https://limacharlie.io)** (SecOps / EDR / XDR), built on
`f0-sectools-core` and the official `limacharlie` Python SDK.

It closes the **offensive↔defensive loop** in the F0RT1KA ecosystem: `f0_library`
writes D&R detections, and this server reads back whether they exist and fired.

## Tools (all read-only)

| Tool | Purpose |
|------|---------|
| `get_org_overview` | Sensor counts + recent detection volume → posture |
| `list_sensors` | Endpoints: hostname, platform, online status |
| `get_sensor` | Detail for one sensor |
| `list_dr_rules` | D&R rule inventory / coverage |
| `list_detections` | Recent detections (D&R hits) + severity |
| `query_telemetry` | Guided, bounded LCQL query |

Every tool returns `f0_sectools_core` findings and degrades gracefully (auth /
permission / rate-limit issues become a posture finding, not a crash).

## Configuration

Copy `.env.limacharlie.example` to `.env.limacharlie` and fill in the org ID and
a read-capable API key. See the example for details.

## Run

```bash
uv run f0-limacharlie-mcp   # stdio MCP server
```

## Relationship to the official server

[refractionPOINT/lc-mcp-server](https://github.com/refractionPOINT/lc-mcp-server)
is the official LimaCharlie MCP server (Go, 278 tools, write-capable, optional
cloud LLM generation) — ideal for frontier-model, full-admin automation. This
server is the opposite by design: a small, read-only, privacy-first set built for
**local small models** with the f0_sectools safety guarantees. Use whichever
fits; they are complementary.
