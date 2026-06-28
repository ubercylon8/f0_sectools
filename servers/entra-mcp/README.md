# f0-entra-mcp

Read-only [Model Context Protocol](https://modelcontextprotocol.io) server for
**Microsoft Entra ID**, built on `f0-sectools-core`.

## Tools (all read-only)

| Tool | Graph endpoint | Permission |
|------|----------------|------------|
| `list_risky_users` | `/identityProtection/riskyUsers` | `IdentityRiskyUser.Read.All` (P2) |
| `list_risk_detections` | `/identityProtection/riskDetections` | `IdentityRiskEvent.Read.All` (P2) |
| `list_conditional_access_policies` | `/identity/conditionalAccess/policies` | `Policy.Read.All` |
| `list_privileged_role_assignments` | `/roleManagement/directory/roleAssignments` | `RoleManagement.Read.Directory` |

Every tool returns `f0_sectools_core` findings and is **permission-aware**: if a
permission/license is not present, the tool returns a posture finding naming the
missing permission instead of failing.

## Configuration

Copy `.env.entra.example` to `.env.entra` and fill in the app-registration
credentials. See the example file for the required Graph permissions.

## Run

```bash
uv run f0-entra-mcp   # stdio MCP server
```
