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

The server couldn't find a credential it needs. The error names the missing
variables *and* where it looked, which tells you which of two problems you have:

- **`found .env.<platform> in <dir>`** — the file exists but is missing a key.
  Add it there. Compare against
  `servers/<platform>-mcp/.env.<platform>.example`.
- **`no .env.<platform> was found`** — there is no credential file. Create one
  at the repo root, or set `F0_SECTOOLS_ENV_DIR` to the directory holding your
  `.env.*` files (useful for keeping credentials outside the checkout).

Servers locate `.env.<platform>` by searching the working directory and its
parents, then the installed package's checkout — so launching your runtime from
a subdirectory of the repo works. Variables already exported in the environment
always win over the file, which is how container and systemd deployments supply
credentials without a file at all.

**Only `<PLATFORM>_*` variables are read from the file.** Anything else in it is
ignored, so one platform's file cannot set another platform's credential or
change the process environment (a stray `HTTPS_PROXY` in a `.env` would
otherwise be honoured on outbound calls carrying a live token). If you need a
proxy or other process-wide setting, export it in the environment that launches
your runtime rather than putting it in a `.env.<platform>` file.

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
