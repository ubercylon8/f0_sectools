# f0-defender-mcp

Read-only [Model Context Protocol](https://modelcontextprotocol.io) server for
**Microsoft Defender XDR**, built on `f0-sectools-core`.

## Tools (all read-only)

| Tool | Graph endpoint | Permission |
|------|----------------|------------|
| `get_secure_score` | `/security/secureScores` | `SecurityEvents.Read.All` |
| `list_incidents` | `/security/incidents` | `SecurityIncident.Read.All` |
| `list_alerts` | `/security/alerts_v2` | `SecurityAlert.Read.All` |
| `run_hunting_query` | `/security/runHuntingQuery` | `ThreatHunting.Read.All` |

Every tool returns `f0_sectools_core` findings and is **permission-aware**: if a
permission is not granted, the tool returns a posture finding naming the missing
permission instead of failing.

## Configuration

Copy `.env.defender.example` to `.env.defender` and fill in the app-registration
credentials. See the example file for the required Graph permissions.

## Run

```bash
uv run f0-defender-mcp   # stdio MCP server
```
