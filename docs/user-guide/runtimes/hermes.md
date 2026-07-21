# Runtime: Hermes Agent

[Hermes Agent](https://hermes-agent.nousresearch.com/docs/) (Nous Research) is the
recommended runtime for f0_sectools: skills-aware, native MCP, an
OpenAI-compatible model backend you point at your local endpoint, and a
first-class persona system.

Prerequisite: finish [getting started](../getting-started.md) (install +
credentials + verify).

## What Hermes gives us

- **Native MCP** — our stdio servers plug in directly via `mcp_servers`, no bridge.
- **agentskills.io skills** — our `skills/` load in place with progressive
  disclosure.
- **Two-layer personas** — a durable base identity (`SOUL.md`) plus switchable
  session lenses (`agent.personalities` + `/personality`). Our four role personas
  are the lenses — see [Personas](#personas-the-two-layer-model).
- **Profiles** — isolated Hermes installations for multi-tenant or dedicated-bot
  deployments. A *different* thing from personas — see
  [Profiles](#profiles-deployment-pattern).

## Setup

Hermes profiles let you install f0_sectools in one command. The recommended path:

### Install the distribution (recommended)

1. **Clone and sync** the f0_sectools repo:
   ```bash
   git clone https://github.com/ubercylon8/f0_sectools.git
   cd f0_sectools
   uv sync --all-packages
   ```

2. **Create credential files** at the repo root, one per platform:
   ```bash
   # Copy the templates from each server directory and fill in your API credentials
   cp servers/defender-mcp/.env.defender.example .env.defender
   cp servers/entra-mcp/.env.entra.example .env.entra
   cp servers/limacharlie-mcp/.env.limacharlie.example .env.limacharlie
   cp servers/projectachilles-mcp/.env.projectachilles.example .env.projectachilles
   cp servers/intune-mcp/.env.intune.example .env.intune
   cp servers/tenable-mcp/.env.tenable.example .env.tenable
   ```
   No credentials are stored in Hermes — the MCP servers load them from these files at the repo root.

3. **Install the f0sectools profile** into Hermes:
   ```bash
   hermes profile install ./integrations/hermes/distribution
   ```
   This creates `~/.hermes/profiles/f0sectools/` with:
   - `SOUL.md` (base identity: read-only / never-fabricate principles)
   - `config.yaml` (the seven MCP servers — defender, entra, limacharlie,
     projectachilles, pa-actions, intune, tenable — under `mcp_servers`, plus
     personas and skills). Hermes reads MCP servers from `config.yaml`, not a
     separate `mcp.json`.

4. **Set the checkout path** in the profile's environment:
   ```bash
   echo "F0_SECTOOLS_DIR=$(pwd)" >> ~/.hermes/profiles/f0sectools/.env
   ```
   The MCP servers use this to load your `.env.<platform>` files and run tools via
   `uv run --directory`.

5. **Point Hermes at your model**:
   ```bash
   hermes -p f0sectools model
   ```
   Enter the URL of your local OpenAI-compatible endpoint (vLLM, llama.cpp, etc.).

6. **Launch the chat**:
   ```bash
   f0sectools chat
   ```
   (Hermes alias for `hermes -p f0sectools chat`.)

**Security notes:**
- Read-only tools are the default and are always available.
- The `f0-pa-actions` MCP server exposes gated-write tools for ProjectAchilles (run/schedule tests, cancel tasks). These tools are **inert by default** — they do nothing without the `PROJECTACHILLES_ALLOW_WRITE=true` flag set in `.env.projectachilles`. Even when enabled, each action requires explicit human confirmation (watcher approval or a single-use token) before execution. No action runs autonomously.

### Manual config merge (alternative)

If you prefer to configure Hermes manually:

1. **Install Hermes** and point its model backend at your local OpenAI-compatible
   endpoint (vLLM / llama.cpp) per the Hermes config docs.

2. **Copy the base identity**:
   ```bash
   cp integrations/hermes/distribution/SOUL.md ~/.hermes/SOUL.md
   ```

3. **Merge the config** — combine [`integrations/hermes/config.example.yaml`](../../../integrations/hermes/config.example.yaml)
   into your `~/.hermes/config.yaml`, adjusting paths as needed. It wires:
   - `mcp_servers` → the seven f0_sectools servers (defender, entra, limacharlie,
     projectachilles, pa-actions, intune, tenable), launched via `uv run --directory`.
   - `skills.external_dirs` → this repo's `skills/` (loaded **in place**, version-controlled).
   - `agent.personalities` → `ciso`, `threat-hunter`, `detection-engineer`,
     `security-engineer`.

## Skills

Hermes loads skills with **progressive disclosure**: names and descriptions
first, the full `SKILL.md` on demand. They activate three ways — automatically by
description, when you name one, or via `/skill-name`:

```text
skills_list                          # list available skills
give me a security posture summary   # → defender-posture-summary (by description)
/defender-threat-hunt                # invoke explicitly
```

## Personas: the two-layer model

Hermes separates a **durable identity** from **session lenses** — and our four
personas are the lenses:

- **`SOUL.md`** is the base identity (system-prompt slot #1): the read-only /
  never-fabricate principles that follow you everywhere.
- **`agent.personalities`** defines named role lenses, switched at runtime with
  `/personality <name>`. Each overlays `SOUL.md` without replacing it.

```text
/personality ciso                    # executive risk framing
give me a posture summary            # → defender-posture-summary, exec-framed

/personality threat-hunter
hunt for PowerShell downloads today  # → defender-threat-hunt (KQL)
```

The four lenses (`ciso`, `threat-hunter`, `detection-engineer`,
`security-engineer`) are defined in
[`config.example.yaml`](../../../integrations/hermes/config.example.yaml) and
summarized in [using skills & personas](../using-skills-and-personas.md).

> **Personas are `agent.personalities`, not Profiles.** Profiles are a separate,
> heavier concept — see below.

## Optimal use for small local models

f0_sectools targets small local models, where **fewer, well-scoped tools = better
tool selection**. Hermes gives you the knobs:

- **Per-server tool scoping** — expose only the tools a session needs with
  `tools.include` / `tools.exclude` under an `mcp_servers` entry. Trim a broad
  server to the two or three tools a task actually calls.
- **`agent.reasoning_effort`** — raise it for multi-step correlation, lower it for
  simple lookups.
- **`agent.disabled_toolsets`** — drop built-in *non-core* toolsets you don't want
  competing for the model's attention. Note: core tools (`terminal`, `read_file`)
  can't be removed this way in Hermes v0.18.2, so a full "security-only" lockdown
  isn't achievable from config alone yet.

Keeping the live tool count small is the single highest-leverage thing you can do
for reliability on a local model.

## Profiles: deployment pattern

A Hermes **profile** is a fully isolated installation — its own `HERMES_HOME`
with separate `config.yaml`, `.env`, `SOUL.md`, memory, sessions, and gateway.
This is **not** a role lens (that's `/personality`); it's a deployment boundary.
Two ways it helps security operations:

- **Multi-tenant / per-engagement isolation.** Run one profile per customer
  tenant. Each carries its own platform credentials, memory, and session history —
  no cross-tenant bleed, reinforcing our per-platform credential isolation.
  ```bash
  hermes profile create acme
  hermes -p acme chat            # drives ACME's tenant only
  hermes profile use acme        # make it the sticky default
  ```
- **Persona-as-a-bot.** Package a single persona into a standalone, always-on bot
  — its own `SOUL.md` (e.g. the CISO lens as the base identity), scoped
  credentials, and a Slack/Discord gateway — for a dedicated "CISO advisor"
  service.

Manage profiles with `hermes profile list|show|rename|delete|export|import`.

> **Security note:** profiles isolate *state*, not the *filesystem* — they are not
> a sandbox. Our read-only tool design remains the safety boundary.

## Notes

- Hermes prefixes MCP tools as `mcp_<server>_<tool>` (e.g.
  `mcp_f0-defender_list_incidents`). Skills reference tools by base name; the model
  maps them via the tool descriptions.
- Everything is read-only; no gated write actions are exposed.
- The same `skills/` also work in pi, Claude Code, and other agentskills.io
  clients — this integration only adds Hermes-specific config, the base `SOUL.md`,
  and the four personas.
