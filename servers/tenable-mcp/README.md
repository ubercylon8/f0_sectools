# f0-tenable-mcp

Read-only MCP server over **Tenable Vulnerability Management** (Workbenches API).
Part of [f0_sectools](../../README.md). Returns the normalized findings schema
through the shared `core/` redaction layer.

## Credentials

Copy `.env.tenable.example` to `./.env.tenable` (repo root) and fill in a Tenable
**access key** and **secret key** (Tenable UI → *My Account → API Keys → Generate*).
Sent as `X-ApiKeys: accessKey=<>;secretKey=<>`. Secrets are never logged or returned.

A read-only Tenable role is sufficient. `.env.tenable` is gitignored.

## Tools (all read-only)

| Tool | What it returns |
|---|---|
| `get_vulnerability_summary` | Environment-wide vulnerability counts by severity |
| `list_top_vulnerabilities` | Worst plugins/CVEs by severity + VPR (fix-first) |
| `list_assets` | Asset inventory (filter by hostname) |
| `get_asset_vulnerabilities` | Vulnerabilities on one host (hostname/ip/UUID) |
| `get_vulnerability_info` | One plugin: CVSS/VPR, description, remediation |
| `list_vulnerability_assets` | Hosts affected by one plugin (patch-scoping) |
| `list_scans` | Scan inventory + last-run freshness |

Full parameter details:
[generated tool reference](../../docs/reference/tools/tenable.md).

## Run

```bash
uv run f0-tenable-mcp   # stdio server; Ctrl-C to stop
```

## Live validation

✅ Live-validated against a real Tenable VM tenant:

```bash
uv run python scripts/live_smoke_tenable.py
```

Skills: `review-exposure-posture` (default focus),
`triage-host-vulnerabilities`, `review-scan-coverage` — see the
[skills catalog](../../docs/reference/skills.md#tenable).
