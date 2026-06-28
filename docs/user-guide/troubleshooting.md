# Troubleshooting

By design, most failure modes surface as a **`posture` finding** (an actionable
message) rather than a crash. Here's how to read them.

## "Permission '<X>' not granted"

The app registration lacks a Microsoft Graph permission (or admin consent
wasn't granted). Add the permission listed in the finding to your app
registration, grant admin consent, and retry.

- Defender incidents → `SecurityIncident.Read.All`
- Defender hunting → `ThreatHunting.Read.All`
- Defender alerts → `SecurityAlert.Read.All`
- Entra risky users → `IdentityRiskyUser.Read.All` (needs **Entra ID P2**)
- Entra risk detections → `IdentityRiskEvent.Read.All` (needs **Entra ID P2**)

The required permissions are documented in each server's `.env.<platform>.example`.

## "Rate limited by the platform — temporarily unavailable"

Microsoft Graph throttled the request (HTTP 429) and the client's retries were
exhausted. The Identity Protection endpoints (`riskyUsers`, `riskDetections`)
throttle aggressively, especially after repeated calls. **Wait a few minutes and
retry once** — don't hammer it, which refreshes the throttle window.

## The model doesn't call any tool

- Confirm the model is **tool-calling capable** (Qwen3 / GPT-OSS / Gemma 4) and
  that tool use is enabled in the runtime.
- Make sure the system prompt / persona is set (non-skill UIs) so the model
  knows the tools and when to use them.
- Small models pick the wrong tool when too many are present — start with one
  server, or use per-server tool scoping.
- Score the model with the [eval harness](getting-started.md#optional-measure-your-models-tool-calling-reliability);
  a low tool-selection rate means that model isn't good enough for the task.

## "Missing required environment variables"

The server couldn't find its credentials. Ensure `.env.defender` / `.env.entra`
exist at the **repo root** and the runtime launches the server with
`uv run --directory <repo-root>` (so it loads them).

## Tool not found / wrong name

Runtimes prefix MCP tool names differently (Hermes
`mcp_f0-defender_list_incidents`, Claude Code `mcp__f0-defender__list_incidents`).
Use the name your client lists; skills refer to the base name and the model
maps it.

## A server won't start

Run it directly to see the error:
```bash
uv run f0-defender-mcp     # stdio server; Ctrl-C to stop
```
If `uv` isn't found by your runtime, use its absolute path (`which uv`).

## Still stuck

Run the smoke script for a clean, redacted end-to-end check:
```bash
uv run python scripts/live_smoke_defender.py
```
