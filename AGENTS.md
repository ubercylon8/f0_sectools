# f0_sectools — agent entry point

Two different jobs happen in this checkout, and they need different
instructions. pi and opencode both load the first context file they find in a
directory, and `AGENTS.md` sorts ahead of `CLAUDE.md` — so this file is read
*instead of* the build guide, not alongside it, and it routes rather than
assuming which job you are on. It is deliberately not an operator persona —
see below for those.

## Developing f0_sectools

Read **[CLAUDE.md](CLAUDE.md)**: the Critical Rules that govern every change,
the architecture, the findings schema, the gated-write machinery, and the
workflow (`uv run pytest`, `ruff`, `mypy`, conventional commits, never push
autonomously). That is the default assumption for work inside this repository.

Rule 5 is the one to internalise first: **tools must be small-model-safe.**
Flat argument schemas, short enums, few tools per server, bounded output. It is
the repo's reason to exist.

## Operating a SOC

**Load a persona first.** The baseline identity lives in
[`integrations/pi/AGENTS.md`](integrations/pi/AGENTS.md); the four lenses layer
the analyst's job on top of it.

| Runtime | How to load one |
|---|---|
| pi | `/ciso`, `/threat-hunter`, `/detection-engineer`, `/security-engineer` |
| Hermes | `personalities` in `integrations/hermes/distribution/config.yaml` |
| opencode | the same prompts, pasted or wired as agents |

The skills in `skills/` are the runbooks, one portable set for every runtime —
follow their Procedure and Pitfalls literally rather than improvising a
platform query.

The nine MCP servers load only when a runtime is started **from this checkout**
(`.pi/mcp.json` for pi, `opencode.json` for opencode) — that is deliberate, so
their tool schemas stay out of unrelated sessions. Re-render them after a pull
with `uv run python scripts/sync_pi_config.py`.

## True either way

- **Read-only by default.** Anything that changes state on a live platform is a
  gated write action: config flag *and* per-action human confirmation, out-of-band
  for anything destructive. Never route around that gate.
- **Never fabricate a tool result.** No tool output, no claim — and never call a
  live platform to "just check" without being asked.
- **Secrets never reach the model.** Per-platform `.env.<platform>` files stay on
  the host; nothing is inlined, logged, or echoed into context.
- **Findings, not prose.** Every tool returns the structured findings schema, and
  every payload passes the core redaction layer before the agent sees it.
