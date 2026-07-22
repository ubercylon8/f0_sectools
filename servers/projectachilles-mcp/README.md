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
| `list_test_executions` | Recent test executions per host — two `check_kind`s: attack simulations (blocked / NOT blocked) and cyber-hygiene control checks (passed / not passed). Bundle runs are rolled up into one per-run COMPLIANT/NON-COMPLIANT finding (X/Y controls), not one finding per control. Optionally scope to one run with `test` (name or uuid), `tag` (fleet), or `hostname` (single host) — the fleet-triage alternative to eyeballing an unfiltered page. |
| `list_risk_acceptances` | Risks deliberately accepted (not remediated) |
| `list_agents` | Test-agent fleet: hostname, OS, status |
| `get_fleet_health` | Fleet metrics: online/offline, uptime |
| `find_tests` | Search the test catalog by `technique`/`actor`/`tactic`/`category`/`tag`/`keyword` (the library of runnable tests, not run history) |
| `get_test` | Full detail for one catalog test by uuid or name — description, OS, techniques, tactics |

Every tool returns `f0_sectools_core` findings and degrades gracefully (auth /
permission / rate-limit issues become a posture finding, not a crash). Full
parameter details:
[generated tool reference](../../docs/reference/tools/projectachilles.md).
Write actions (run/schedule/pause/cancel tests) live in the separate
[`projectachilles-actions-mcp`](../projectachilles-actions-mcp/README.md)
server, gated.

## Configuration

Copy `.env.projectachilles.example` to `.env.projectachilles` and fill in your
instance base URL and a **read**-scope `pa_` API key (Settings → API Keys). The
org is embedded in the key.

## Run

```bash
uv run f0-projectachilles-mcp   # stdio MCP server
```

## Live validation

✅ Live-validated against a real tenant (note: the API lives on the `agent`
subdomain — `https://<org>.agent.projectachilles.io`, not the web-UI host):

```bash
uv run python scripts/live_smoke_projectachilles.py
```

Skills: `review-defense-posture`, `analyze-coverage-gaps`,
`review-validation-fleet`, `explore-test-catalog` — see the
[skills catalog](../../docs/reference/skills.md#projectachilles).
