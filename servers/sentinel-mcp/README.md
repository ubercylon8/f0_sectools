# f0-sentinel-mcp

Read-only [Model Context Protocol](https://modelcontextprotocol.io) server for
**Microsoft Sentinel**, built on `f0-sectools-core`. Part of
[f0_sectools](../../README.md). Returns the normalized findings schema through
the shared `core/` redaction layer.

Sentinel is two APIs, not one, with different hosts, token audiences, and
Azure roles — and this server treats them as two independently-authorized
halves rather than one monolithic connection:

- **Logs** — KQL over `https://api.loganalytics.azure.com/v1`, token scope
  `https://api.loganalytics.io/.default`, Azure role **Log Analytics
  Reader** on the Log Analytics workspace resource. Powers every telemetry
  tool: `list_data_sources`, `hunt_firewall`, `hunt_dns_web`,
  `search_office_activity`, `list_sentinel_incidents`, `run_kql`.
- **Objects** — ARM over `https://management.azure.com`, token scope
  `https://management.azure.com/.default`, Azure role **Microsoft Sentinel
  Reader** on the same resource, api-version `2024-09-01`. Powers only
  `get_detection_coverage` (the analytics-rule inventory).

Grant only Log Analytics Reader and every tool works except
`get_detection_coverage`, which returns a `posture` finding naming the
missing role and the three ARM env vars to set — never a crash and never a
silent empty result mistaken for "no rules". Grant only Sentinel Reader and
every KQL tool fails the same graceful way, naming Log Analytics Reader
instead. Grant both and the server is fully functional. A logs-only
deployment (no ARM coordinates at all) is a fully supported configuration.

## Read tools

| Tool | Surface | Permission | What it answers |
|------|---------|------------|------------------|
| `list_data_sources` | Logs | Log Analytics Reader | What telemetry does this workspace actually ingest (30d, by volume)? Start here — every workspace is different. |
| `hunt_firewall` | Logs | Log Analytics Reader | Firewall traffic (Check Point / Fortinet CEF) — connections, blocks, an IP/port indicator. |
| `hunt_dns_web` | Logs | Log Analytics Reader | DNS / web-proxy / remote-access VPN activity (Cisco Umbrella) — a domain, URL fragment, or IP. |
| `search_office_activity` | Logs | Log Analytics Reader | Microsoft 365 audit activity (who accessed/downloaded/shared what) — the fast path vs. Purview. |
| `list_sentinel_incidents` | Logs | Log Analytics Reader | The Sentinel SOC incident queue, with MITRE tactics, status, and owner. |
| `get_detection_coverage` | Objects (ARM) | Microsoft Sentinel Reader | Analytics-rule inventory and which MITRE tactics are uncovered — split into overall vs. custom (operator-authored) coverage. |
| `run_kql` | Logs | Log Analytics Reader | Escape hatch: a caller-supplied read-only KQL query, force-bounded. Prefer a guided tool above when one fits. |

Full parameter details (arguments, enums, defaults):
[generated tool reference](../../docs/reference/tools/sentinel.md).

Every tool returns `f0_sectools_core` findings and is **permission-aware**:
a missing role, an auth failure, throttling, or a query Sentinel rejects all
degrade to a `posture` finding naming the fix — never an unhandled exception.

## Behaviours worth knowing before you rely on this server

- **`hours` is capped at `SENTINEL_RETENTION_DAYS × 24`** (default 30 days ->
  720 hours) on every telemetry tool. This exists to prevent a specific
  failure: without the cap, a query with `hours` set past the workspace's
  actual retention would silently scan an empty range and report "no
  activity found" — which reads as *nothing happened* when what actually
  happened is *the data was never retained that far back*. The cap converts
  a confidently wrong answer into a query that at least covers everything
  that could possibly be there.
- **The `hunt_*` tools return an aggregate, not rows, when called without an
  `indicator`.** On the validation workspace the CEF firewall table alone
  carried roughly 112M rows over 7 days — returning individual rows by
  default would blow the context window on the first call. Pass an
  IP/port (`hunt_firewall`) or a domain/URL/IP (`hunt_dns_web`) to switch
  from "top talkers" to matching events.
- **`get_detection_coverage` separates operator-authored rules from
  Microsoft-managed ones.** Sentinel ships built-in analytics-rule kinds
  (`Fusion`, `MicrosoftSecurityIncidentCreation`, `MLBehaviorAnalytics`,
  `ThreatIntelligence`) that generate or import alerts through Microsoft's
  own logic, not anything the operator configured. Counting their MITRE
  tactics as "coverage" overstates what was actually built — the tool
  reports both an overall figure (`Scheduled`/`NRT` rules + built-ins) and a
  custom-only figure (`Scheduled`/`NRT` alone), and the recommendation is
  always keyed to the custom gap.

## Explicit non-goals

Each of these was considered and deliberately left out, so a future
contributor doesn't rediscover the reason by re-adding it:

- **No device-telemetry hunt tool.** Defender's device tables were not
  streaming into Sentinel on the validation workspace, and `f0-defender`
  already owns that surface directly — a duplicate here would recreate a
  known routing collision, not add capability.
- **No UEBA tool.** `BehaviorAnalytics` ingested roughly 462K rows on the
  validation workspace, but every one scored `InvestigationPriority = 0` —
  a tool over this table would return an empty list forever.
- **No incident-classification tool.** 100% of closed incidents on the
  validation workspace were classified `Undetermined` — the field carries
  no signal to surface.
- **No `list_connectors` tool.** The `dataConnectors` ARM API reported a
  single connector on a workspace with at least six tables actively
  ingesting, because AMA/DCR-based and codeless connectors never register
  there — the API answer would be misleading. `list_data_sources` reports
  actual ingest instead, read straight from `Usage`.
- **No sign-in tool.** `f0-entra` already owns identity sign-in data; a
  second sign-in surface here is routing collision for no new capability.
- **No writes in v1.** Read tools only. Incident close/classify/assign is a
  plausible future gated write through `core/gating/`, deliberately
  deferred rather than rushed.

## Configuration

Copy `.env.sentinel.example` to `./.env.sentinel` (repo root) and fill in an
Entra app registration and the workspace GUID:

| Variable | Required | Notes |
|---|---|---|
| `SENTINEL_TENANT_ID` | yes | Entra tenant ID. |
| `SENTINEL_CLIENT_ID` | yes | App registration (client) ID. |
| `SENTINEL_CLIENT_SECRET` | yes | App registration client secret. |
| `SENTINEL_WORKSPACE_ID` | yes | Log Analytics workspace GUID (workspace *Overview* -> *Workspace ID*, not the ARM resource name). |
| `SENTINEL_SUBSCRIPTION_ID` | optional | ARM subscription GUID — needed only for `get_detection_coverage`. |
| `SENTINEL_RESOURCE_GROUP` | optional | Resource group holding the workspace — needed only for `get_detection_coverage`. |
| `SENTINEL_WORKSPACE_NAME` | optional | ARM workspace resource name — needed only for `get_detection_coverage`. |
| `SENTINEL_RETENTION_DAYS` | optional | Workspace log retention in days, default `30`. Caps `hours` on every telemetry tool — see above. |
| `SENTINEL_VERIFY_TLS` | optional | TLS certificate verification, default on. |

Grant the app registration **Log Analytics Reader** on the Log Analytics
workspace resource for the logs half, and **Microsoft Sentinel Reader** on
the same resource for the objects half (`get_detection_coverage`). Omit the
three ARM variables entirely for a logs-only deployment — the server starts
and every tool except `get_detection_coverage` works normally.
`.env.sentinel` is gitignored.

## Run

```bash
uv run f0-sentinel-mcp   # stdio MCP server; Ctrl-C to stop
```

## Live validation

✅ Live-validated against a real Sentinel workspace (2026-08-11), which is
also where the field-name and value quirks documented in the tool docstrings
and the non-goals above were surfaced — including the tactics/techniques
JSON-blob shape on `SecurityIncident`, the built-in analytics-rule kinds, and
the `OfficeWorkload` value strings:

```bash
uv run python scripts/live_smoke_sentinel.py
```

Skills: `network-investigation` (default focus), `data-source-coverage`,
`detection-coverage` — see the
[skills catalog](../../docs/reference/skills.md#sentinel).
