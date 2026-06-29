# f0-projectachilles-mcp

Read-only [Model Context Protocol](https://modelcontextprotocol.io) server for
**[ProjectAchilles](https://projectachilles.io)** — the F0RT1KA continuous
security-validation platform — built on `f0-sectools-core`.

ProjectAchilles measures **defensive posture validated by attack simulation**:
it runs `f0_library` tests against your endpoints and scores whether your
controls actually blocked or detected them. This server exposes that posture,
the underlying results, and the test-agent fleet to a local model.

## Tools (all read-only)

| Tool | Purpose |
|------|---------|
| `get_defense_score` | Defense score — current snapshot, or the trend with `over_time=true` |
| `get_weak_techniques` | Lowest-scoring MITRE techniques — where defenses fail |
| `list_test_executions` | Recent test executions (technique blocked or not, per host) |
| `list_risk_acceptances` | Risks deliberately accepted (not remediated) |
| `list_agents` | Test-agent fleet: hostname, OS, status |
| `get_fleet_health` | Fleet metrics: online/offline, uptime |

Every tool returns `f0_sectools_core` findings and degrades gracefully (auth /
permission / rate-limit issues become a posture finding, not a crash).

## Configuration

Copy `.env.projectachilles.example` to `.env.projectachilles` and fill in your
instance base URL and a **read**-scope `pa_` API key (Settings → API Keys). The
org is embedded in the key.

## Run

```bash
uv run f0-projectachilles-mcp   # stdio MCP server
```
