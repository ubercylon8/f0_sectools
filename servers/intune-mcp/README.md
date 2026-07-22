# f0-intune-mcp

[Model Context Protocol](https://modelcontextprotocol.io) server for
**Microsoft Intune** device management, over Microsoft Graph — read-only,
built on `f0-sectools-core`. Covers the device-inventory / compliance /
policy-coverage questions an endpoint or security engineer asks first.

## Read tools

| Tool | Graph endpoint | Permission |
|------|----------------|------------|
| `list_managed_devices` | `/deviceManagement/managedDevices` | `DeviceManagementManagedDevices.Read.All` |
| `get_managed_device` | `/deviceManagement/managedDevices` | `DeviceManagementManagedDevices.Read.All` |
| `get_compliance_summary` | `/deviceManagement/deviceCompliancePolicyDeviceStateSummary` | `DeviceManagementManagedDevices.Read.All` |
| `list_stale_devices` | `/deviceManagement/managedDevices` (filtered by last sync) | `DeviceManagementManagedDevices.Read.All` |
| `list_compliance_policies` | `/deviceManagement/deviceCompliancePolicies` | `DeviceManagementConfiguration.Read.All` |
| `list_configuration_profiles` | `/deviceManagement/deviceConfigurations` | `DeviceManagementConfiguration.Read.All` |

Full parameter details (types, enums, defaults):
[generated tool reference](../../docs/reference/tools/intune.md).

Every tool returns `f0_sectools_core` findings and is **permission-aware**: a
missing permission or license produces a posture finding naming the exact
grant, never a crash. No write actions — this server is entirely read-only.

## Configuration

Copy `.env.intune.example` to `.env.intune` at the repo root and fill in the
Entra app-registration credentials (`INTUNE_TENANT_ID` / `INTUNE_CLIENT_ID` /
`INTUNE_CLIENT_SECRET`). Reusing the same app as `.env.entra` is fine — the
file stays separate for per-platform credential isolation. Grant the app
(admin consent): `DeviceManagementManagedDevices.Read.All` and
`DeviceManagementConfiguration.Read.All`. The tenant needs an active Intune
license.

## Run

```bash
uv run f0-intune-mcp   # stdio MCP server
```

## Live validation

✅ Live-validated against a real tenant:

```bash
uv run python scripts/live_smoke_intune.py
```

Skills: `intune-device-compliance-review` (default focus),
`intune-coverage-gap-review`, `intune-device-triage` — see the
[skills catalog](../../docs/reference/skills.md#intune).
