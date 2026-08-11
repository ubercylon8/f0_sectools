# f0-sentinel-mcp

Read-only MCP server over **Microsoft Sentinel**. Part of
[f0_sectools](../../README.md). Returns the normalized findings schema through
the shared `core/` redaction layer.

Sentinel is two APIs, not one, with different hosts, token audiences, and
Azure roles:

- **Logs** — `api.loganalytics.azure.com` (KQL over the workspace) — needs
  **Log Analytics Reader**.
- **Objects** — `management.azure.com` / `Microsoft.SecurityInsights` (ARM) —
  needs **Microsoft Sentinel Reader**.

The two halves fail independently: a tenant may grant one role and not the
other, and tools report that per-half rather than as a dead server.

## Credentials

Copy `.env.sentinel.example` to `./.env.sentinel` (repo root) and fill in an
Entra app registration (tenant/client ID + secret) and the workspace GUID.
The ARM coordinates (subscription, resource group, workspace name) are
optional — omit them and the ARM-only tool degrades gracefully instead of
breaking the server. `.env.sentinel` is gitignored.

## Status

Under active development (`feat/sentinel-mcp`). This package currently ships
`SentinelClient`, the thin async client driving both API surfaces; tools and
the server entry point land in follow-up work.

## Run

```bash
uv run f0-sentinel-mcp   # stdio server; Ctrl-C to stop
```
