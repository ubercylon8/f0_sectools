# f0-purview-mcp

Read-only MCP server for **Microsoft Purview** — the data-risk pillar:

| Tool | What it answers |
|---|---|
| `get_dlp_summary` | How much data-loss pressure are we under? (alert rollup) |
| `list_dlp_alerts` | Recent DLP alerts, bounded, by severity |
| `list_insider_risk_alerts` | Recent Insider Risk Management alerts |
| `list_sensitivity_labels` | Is classification deployed? (label inventory) |
| `search_audit_log` | Who did what? (guided unified-audit search, async) |
| `get_audit_results` | Fetch results of a still-running audit search |

All Microsoft Graph: DLP/IRM alerts via `security/alerts_v2` (GA); audit via
the Purview Audit Search API (`security/auditLog/queries`, async two-phase —
served on Graph **beta**: the documented v1.0 path 404s on real tenants);
labels via Graph **beta**. Credentials/permissions:
`.env.purview.example`.

**Explicit non-goal:** the Compliance Manager compliance score has **no public
API** (portal-only) — see the Defender-for-Cloud roadmap item for the
API-accessible compliance alternative. Deep per-event DLP forensics (O365
Management Activity API) is also out of scope.

Findings-schema output, core redaction at the boundary, graceful
permission/licensing degradation — same contract as every f0_sectools server.
