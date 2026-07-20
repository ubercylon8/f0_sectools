# f0-defender-mcp

[Model Context Protocol](https://modelcontextprotocol.io) server for
**Microsoft Defender XDR**, built on `f0-sectools-core`. Read tools by default,
plus two **gated write actions** (host isolate/release) that are disabled unless
explicitly enabled and human-confirmed.

## Read tools

| Tool | Graph endpoint | Permission |
|------|----------------|------------|
| `get_secure_score` | `/security/secureScores` | `SecurityEvents.Read.All` |
| `list_incidents` | `/security/incidents` | `SecurityIncident.Read.All` |
| `list_alerts` | `/security/alerts_v2` | `SecurityAlert.Read.All` |
| `run_hunting_query` | `/security/runHuntingQuery` | `ThreatHunting.Read.All` |
| `hunt` | `/security/runHuntingQuery` (guided — the server builds the KQL from a `category` + `indicator`) | `ThreatHunting.Read.All` |

Every tool returns `f0_sectools_core` findings and is **permission-aware**: if a
permission is not granted, the tool returns a posture finding naming the missing
permission instead of failing.

## Gated write actions

| Tool | API call | Permission |
|------|----------|------------|
| `isolate_host` | `POST /machines/{device_id}/isolate` | `Machine.Isolate` (WindowsDefenderATP, on `api.security.microsoft.com`) |
| `release_host` | `POST /machines/{device_id}/unisolate` | `Machine.Isolate` (WindowsDefenderATP) |

These change state on a live tenant, so they are **read-only-by-default and
gated** through `core/gating` (see the repo CLAUDE.md → *Gated Write Actions*):

1. **Disabled unless enabled** — the action is unavailable unless
   `DEFENDER_ALLOW_WRITE=true` is set in `.env.defender`.
2. **Intent first** — call the tool **without** `confirmation_token` and it
   returns the *intended* action as a finding (which device, what it will do) —
   it does **not** execute.
3. **Human confirmation** — the operator approves it out-of-band with
   `python scripts/confirm_action.py --watch` (one keypress), or passes a
   single-use token from `python scripts/confirm_action.py isolate_host
   <device_id>` (`--platform` defaults to `defender`). The agent then repeats
   the identical call.
4. **Execute + audit** — on a valid confirmation the action runs and is written
   to the local audit trail (actor, target, method). No confirmation → no
   execution.

A small local model can never isolate a host on its own: the write flag plus the
out-of-band human confirmation is the hard stop.

## Configuration

Copy `.env.defender.example` to `.env.defender` and fill in the app-registration
credentials. The example file documents the required read permissions, the
`Machine.Isolate` write permission, and the `DEFENDER_ALLOW_WRITE` flag (default
`false`).

## Run

```bash
uv run f0-defender-mcp   # stdio MCP server
```
