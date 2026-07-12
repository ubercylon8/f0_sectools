# f0-intune-mcp

Read-only MCP server for **Microsoft Intune** device management, over Microsoft Graph.

Reuses the shared `core/` Graph client and the same auth as the Entra/Defender servers
(a Microsoft Entra app, client-credentials). Configure `.env.intune` at the repo root
(`INTUNE_TENANT_ID` / `INTUNE_CLIENT_ID` / `INTUNE_CLIENT_SECRET`) and grant the app
`DeviceManagementManagedDevices.Read.All` + `DeviceManagementConfiguration.Read.All`
(admin consent). Requires an active Intune license on the tenant.

Tools (all read-only): `list_managed_devices`, `get_compliance_summary`,
`get_managed_device`, `list_stale_devices`, `list_compliance_policies`,
`list_configuration_profiles`.
