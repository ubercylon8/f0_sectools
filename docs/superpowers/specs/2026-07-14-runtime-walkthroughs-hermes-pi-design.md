# Runtime Walkthroughs: Hermes Agent & pi — Design Spec

**Date:** 2026-07-14
**Status:** Approved for planning
**Type:** Documentation + runtime wiring (no `core/` or server behaviour change)

## Goal

Turn our two thin runtime pages into **full, runnable walkthroughs** that show an
operator the optimal use of each runtime's capabilities with f0_sectools, and
correctly map our **four personas** onto each runtime's real persona mechanism.
Add **pi** as a first-class runtime (it was not previously documented) by
configuring the existing `pi-mcp-extension` bridge — no bridge code is written or
shipped from this repo.

## Why now / what triggered this

Reviewing the Hermes docs surfaced a **correctness bug** in our shipped material:
`docs/user-guide/runtimes/hermes.md` says Hermes' **profile system** "maps
directly onto our four personas." That is wrong. Hermes has two *distinct*
concepts, and our personas map onto the other one. This spec bakes in the
correction and documents Profiles for their real purpose.

## Verified facts (the source of truth the docs must match)

Every claim below was verified against the primary-source page cited. The
walkthroughs must not assert anything outside this set without a fresh citation.

### Hermes Agent

- **Personas = `agent.personalities` + `/personality <name>`.** Session-level
  system-prompt overlays layered on top of `SOUL.md`; switch mid-session. The
  documented YAML is exactly what our `integrations/hermes/config.example.yaml`
  already ships:
  ```yaml
  agent:
    personalities:
      codereviewer: >
        You are a meticulous code reviewer. Identify bugs, security issues,
        performance concerns, and unclear design choices.
  ```
  Activate with `/personality codereviewer`. Built-in personalities also exist
  (`helpful`, `concise`, `technical`, `teacher`, plus fun variants).
  Source: https://hermes-agent.nousresearch.com/docs/user-guide/features/personality
- **`SOUL.md`** is the durable base identity (system-prompt slot #1); `/personality`
  is a session overlay on top of it. Source: same page.
- **Profiles = isolated Hermes installations**, NOT a role lens. Each profile is
  its own `HERMES_HOME` with separate `config.yaml`, `.env`, `SOUL.md`, memory,
  sessions, and gateway. Managed via `hermes profile create|use|list|show|rename|
  delete|export|import|install|update`; each gets a command alias at
  `~/.local/bin/<name>` and can be selected with `-p <name>` / `--profile=<name>`
  or a sticky `hermes profile use <name>`. Sources:
  https://hermes-agent.nousresearch.com/docs/user-guide/profiles and
  https://hermes-agent.nousresearch.com/docs/reference/cli-commands
- **Config keys we rely on exist:** `mcp_servers`, `skills.external_dirs`,
  `agent.personalities`, `agent.reasoning_effort`, `agent.disabled_toolsets`,
  per-server `tools.include`/`tools.exclude` scoping. Source:
  https://hermes-agent.nousresearch.com/docs/user-guide/configuration
- **Tool naming:** `mcp_<server>_<tool>` (e.g. `mcp_f0-defender_list_incidents`).

### pi (earendil-works/pi)

- **pi omits native MCP by design** ("intentionally does not include built-in
  MCP"). Source: https://pi.dev/docs/latest/usage
- **`pi-mcp-extension`** is a production-ready MCP client extension: stdio/http/sse
  transports, tool discovery, `registerTool` bridging, reconnection.
  - Install: `pi install npm:pi-mcp-extension` (or try with `pi -e npm:pi-mcp-extension`).
  - Config: `~/.pi/agent/mcp.json` (global) or `.pi/mcp.json` (project); top-level
    `mcpServers` object with `command`/`args`/`transport`/`env`/`lifecycle`, plus a
    `settings` block (`toolPrefix` default `"mcp"`, `requestTimeoutMs`, `maxRetries`).
  - Tool names: `<toolPrefix>_<server>_<tool>` → default `mcp_f0-defender_list_incidents`
    — **identical to Hermes' scheme**, so our skills need no pi-specific edits.
  - Source: https://pi.dev/packages/pi-mcp-extension
- **Skills = agentskills.io SKILL.md**, loaded unmodified. External dirs via
  `settings.skills: ["/abs/path/to/sec-tools/skills"]`; also `--skill <path>`,
  `~/.pi/agent/skills/`, `.pi/skills/`. Source: https://pi.dev/docs/latest/skills
- **Personas = prompt templates.** `.md` file + YAML frontmatter (`description`,
  `argument-hint`, both optional); **filename → `/command`** (`ciso.md` → `/ciso`).
  Stored in `~/.pi/agent/prompts/*.md`, `.pi/prompts/*.md`, or loaded from an
  external dir via `settings.prompts: [...]`; also `--prompt-template <path>`.
  Support `$1`/`$@`/`$ARGUMENTS` substitution. Source:
  https://pi.dev/docs/latest/prompt-templates
- **Base identity (SOUL.md equivalent) = context files.** pi auto-loads
  `AGENTS.md` or `CLAUDE.md` from `~/.pi/agent/AGENTS.md` (global), the project
  dir, and ancestor dirs. Full replacement: `.pi/SYSTEM.md` / `~/.pi/agent/SYSTEM.md`;
  append: `APPEND_SYSTEM.md`. Disable with `--no-context-files`. Source:
  https://pi.dev/docs/latest/usage
- **Local model = `~/.pi/agent/models.json`:**
  ```json
  {
    "providers": {
      "f0-local": {
        "baseUrl": "http://localhost:8000/v1",
        "api": "openai-completions",
        "apiKey": "$OPENAI_API_KEY",
        "models": [{ "id": "your-model-name" }]
      }
    }
  }
  ```
  `apiKey` accepts a literal, `"$ENV_VAR"`, or `"!command"`. vLLM/llama.cpp accept
  any token; a dummy (`"sk-local"`) or env var is fine. `/model` reloads the file.
  Sources: https://pi.dev/docs/latest/models and https://pi.dev/docs/latest/providers

## Structural parallel (drives the symmetric docs)

| Concern | Hermes | pi |
|---|---|---|
| Base identity | `SOUL.md` | `AGENTS.md` (or `SYSTEM.md`) |
| Persona lens | `agent.personalities` + `/personality <name>` | prompt template `.md` → `/<name>` |
| MCP servers | native `mcp_servers` | `pi-mcp-extension` + `mcp.json` |
| Skills | `skills.external_dirs` | `settings.skills: [...]` |
| Tool names | `mcp_f0-defender_…` | `mcp_f0-defender_…` (identical) |
| Local model | Hermes model backend config | `models.json` provider |

## Non-goals (YAGNI / out of scope)

- **Writing our own MCP→pi bridge.** `pi-mcp-extension` exists and is
  production-ready; we configure it, we do not fork or vendor it.
- **Shipping any TypeScript** from this Python repo.
- **Packaging f0_sectools as a pi package** (`pi.skills`/`pi.prompts` in a
  `package.json`). Direct external-dir config is enough for v0.1.x.
- **Any change to `core/` or a server's runtime behaviour.** Docs + wiring only.
- **A single-source persona refactor.** Personas remain "authored once, delivered
  per-runtime" (the existing pattern: Hermes personalities YAML + portable-prompt
  modes; pi adds prompt-template files). Faithful mirrors + cross-references, not a
  new canonical `personas.md`. If personas are ever enriched, both runtimes' copies
  must be updated together — noted in the files.
- **The `v0.1.0` tag and public-visibility flip** (user-gated, tracked elsewhere).

## Deliverables

### D1 — `docs/user-guide/runtimes/hermes.md` (rewrite → full walkthrough)

Grow from setup notes into an end-to-end optimal-use walkthrough. Sections:

1. **What Hermes gives us** (skills-aware, native MCP, OpenAI-compatible backend).
   Fix the current wrong line — replace "a profile system that maps directly onto
   our four personas" with the correct two-concept framing.
2. **Setup** (keep existing, verified): install; point model backend at the local
   OpenAI-compatible endpoint; `cp integrations/hermes/SOUL.md ~/.hermes/SOUL.md`;
   merge `config.example.yaml`.
3. **Skills** — progressive disclosure (names first, full content on demand);
   activate by description / `/skill-name` / mention; `skills_list`.
4. **Personas — the two-layer model.** `SOUL.md` = durable base identity;
   `agent.personalities` + `/personality <name>` = session overlay. Show the four
   f0_sectools lenses and switching. State plainly: **personas are `agent.personalities`,
   NOT Profiles.**
5. **Optimal-use knobs.** Per-server **tool scoping** (`tools.include`/`tools.exclude`)
   to keep the registry small for small models; `agent.reasoning_effort`;
   `agent.disabled_toolsets`; note our small-model-safe thesis (fewer tools →
   better selection).
6. **Profiles — deployment pattern (new).** What a profile is (isolated
   `HERMES_HOME`). Two concrete f0_sectools uses:
   (a) **multi-tenant / per-engagement isolation** — one profile per customer
   tenant, each with its own `.env.*` credentials, memory, and sessions (no
   cross-tenant bleed — reinforces our per-platform credential-isolation rule);
   (b) **persona-as-a-bot** — package a persona into a standalone profile (own
   `SOUL.md` + credentials + gateway to Slack/Discord) for a dedicated, always-on
   "CISO advisor" bot. Commands: `hermes profile create`, `use`, `-p`, `list`.
   Security note: profiles do **not** sandbox the filesystem and are not a
   substitute for our read-only tool design.
7. **Notes** (keep verified ones): tool-name prefixing; read-only; same skills as
   other runtimes.

### D2 — `docs/user-guide/runtimes/pi.md` (new → full walkthrough)

Mirror hermes.md's shape. Sections:

1. **What pi is + the MCP caveat.** Minimal TypeScript harness; agentskills.io
   skills; prompt-template personas. Honest callout: **pi omits native MCP by
   design; the `pi-mcp-extension` bridge fills the gap** (production-ready, we
   only configure it). Note pi runs local or hosted models — for local-only
   privacy use a local endpoint per step 2.
2. **Install pi** and **point it at your local model** — `~/.pi/agent/models.json`
   provider block (verified example above); pick with `/model`.
3. **Bridge in the MCP servers** — `pi install npm:pi-mcp-extension`, then a
   `mcp.json` (ship one at `integrations/pi/mcp.json`; copy to `~/.pi/agent/mcp.json`
   or `.pi/mcp.json`). Explain `lifecycle: "lazy"`, `toolPrefix`, and that
   **credentials are not in `mcp.json`** — each server loads its own `.env.<platform>`
   from the repo root (consistent with our secrets model). Tools appear as
   `mcp_f0-<server>_<tool>`.
4. **Base identity (SOUL.md equivalent)** — copy `integrations/pi/AGENTS.md` to
   `~/.pi/agent/AGENTS.md` (or use `.pi/SYSTEM.md`). Same read-only /
   never-fabricate principles as Hermes' `SOUL.md`.
5. **Skills** — `settings.skills: ["/abs/path/to/sec-tools/skills"]`; loaded
   unmodified; `/skill:name` and auto-discovery; `--no-skills` to disable.
6. **Personas — prompt templates.** `settings.prompts: ["/abs/path/to/sec-tools/integrations/pi/prompts"]`;
   invoke `/ciso`, `/threat-hunter`, `/detection-engineer`, `/security-engineer`.
   Explain these overlay the base `AGENTS.md`.
7. **Use it / verify** — a short session (e.g. `/ciso` then "give me a posture
   summary" → `defender-posture-summary` skill → `mcp_f0-defender_*` tools).
8. **Notes** — read-only; same skills as Hermes/Claude Code; extension runs with
   full permissions (install from trusted source only).

### D3 — `integrations/pi/` (new wiring; mirrors `integrations/hermes/`; rule 9 = wiring only, no skill content)

- `integrations/pi/README.md` — file table + pointer to the canonical
  `docs/user-guide/runtimes/pi.md` (single source of truth; no duplicated setup).
- `integrations/pi/mcp.json` — `pi-mcp-extension` config for all six servers via
  `uv run --directory <ABS_PATH> f0-<platform>-mcp`, `transport: "stdio"`,
  `lifecycle: "lazy"`, and a `settings` block with `toolPrefix: "mcp"`. Placeholder
  path `/ABSOLUTE/PATH/TO/sec-tools` (same convention as `examples/mcp/`). No
  secrets. Exact content:
  ```json
  {
    "settings": {
      "toolPrefix": "mcp",
      "requestTimeoutMs": 30000,
      "maxRetries": 5
    },
    "mcpServers": {
      "f0-defender":       { "command": "uv", "args": ["run", "--directory", "/ABSOLUTE/PATH/TO/sec-tools", "f0-defender-mcp"],       "transport": "stdio", "lifecycle": "lazy" },
      "f0-entra":          { "command": "uv", "args": ["run", "--directory", "/ABSOLUTE/PATH/TO/sec-tools", "f0-entra-mcp"],          "transport": "stdio", "lifecycle": "lazy" },
      "f0-limacharlie":    { "command": "uv", "args": ["run", "--directory", "/ABSOLUTE/PATH/TO/sec-tools", "f0-limacharlie-mcp"],    "transport": "stdio", "lifecycle": "lazy" },
      "f0-projectachilles":{ "command": "uv", "args": ["run", "--directory", "/ABSOLUTE/PATH/TO/sec-tools", "f0-projectachilles-mcp"],"transport": "stdio", "lifecycle": "lazy" },
      "f0-intune":         { "command": "uv", "args": ["run", "--directory", "/ABSOLUTE/PATH/TO/sec-tools", "f0-intune-mcp"],         "transport": "stdio", "lifecycle": "lazy" },
      "f0-tenable":        { "command": "uv", "args": ["run", "--directory", "/ABSOLUTE/PATH/TO/sec-tools", "f0-tenable-mcp"],        "transport": "stdio", "lifecycle": "lazy" }
    }
  }
  ```
  (Verify the six console-script names against each server's `pyproject.toml`
  `[project.scripts]` during the plan — must match `examples/mcp/` exactly.)
- `integrations/pi/AGENTS.md` — base identity: the read-only / never-fabricate /
  ground-every-statement operating principles, mirroring `integrations/hermes/SOUL.md`
  **minus** the Hermes-specific `/personality` line (pi uses `/ciso` etc.). Add a
  one-line note that persona lenses are pi prompt templates in `integrations/pi/prompts/`.
- `integrations/pi/prompts/{ciso,threat-hunter,detection-engineer,security-engineer}.md`
  — four prompt templates, each with `description:` frontmatter and the same lens
  text as the corresponding `agent.personalities` entry in
  `integrations/hermes/config.example.yaml` (faithful mirror; skill/tool references
  stay by name — they resolve identically under pi's `mcp_f0-*` prefix). Example
  shape:
  ```markdown
  ---
  description: CISO lens — executive risk framing, posture rollups
  ---
  Operate as a CISO advisor. Audience is executive: lead with risk and business
  impact, keep it short, avoid tool names, IDs, and raw JSON. Prefer the
  defender-posture-summary skill ... (verbatim mirror of the Hermes ciso lens)
  ```

### D4 — cross-cutting doc updates

- `docs/user-guide/README.md` — support matrix: promote **pi** to a first-class,
  local-capable runtime (skills ✓, personas ✓ via prompt templates, MCP ✓ via
  `pi-mcp-extension`); ensure Hermes row reflects personalities+profiles.
- `docs/user-guide/using-skills-and-personas.md` — add a "personas per runtime"
  mapping: Hermes `agent.personalities`/`/personality` · pi prompt templates
  (`/ciso` …) · portable-prompt modes (LM Studio / Open WebUI).
- `CLAUDE.md` (Skills, Personas & Runtimes → Runtimes) — add one line for pi
  (agentskills.io client; MCP via `pi-mcp-extension`); note `integrations/pi/`.
- `README.md` — add pi to any runtime list; keep single-source-of-truth (link to
  the runtime page, don't duplicate steps).

## Constraints (carry into every task)

- **Docs + wiring only.** No edits under `core/` or any `servers/*/` package;
  no change to tool behaviour, schemas, or the findings contract.
- **Secrets never in committed files.** `mcp.json` and all examples carry no
  credentials; servers load `.env.<platform>` themselves. No real `.env` staged.
- **DRY / rule 9.** `integrations/` and `prompts/` carry runtime wiring only; skill
  *content* stays in `skills/`. Persona lens text in `integrations/pi/prompts/`
  must stay a faithful mirror of the Hermes `agent.personalities` text.
- **Every runtime claim traces to a cited primary-source page** in the Verified
  Facts section. No plausible-but-unverified assertions.
- **Single source of truth.** Runtime pages under `docs/user-guide/runtimes/` are
  canonical; `integrations/*/README.md` point to them, never duplicate steps.

## Verification (docs discipline — TDD does not apply to prose)

Per task, use grep/link/JSON checks instead of failing tests:

1. **Link check** — markdown links in new/edited pages resolve (lychee or manual);
   all external doc URLs are the ones in Verified Facts.
2. **JSON validity** — `integrations/pi/mcp.json` and any inline JSON parse
   (`python -m json.tool`).
3. **Claim trace** — each config key / command / file path in the walkthroughs
   appears in the Verified Facts section (grep the spec).
4. **Console-script names** — the six `f0-*-mcp` names in `mcp.json` match the
   servers' `pyproject.toml` `[project.scripts]` and `examples/mcp/`.
5. **Persona parity** — each `integrations/pi/prompts/*.md` lens matches the
   corresponding Hermes `agent.personalities` lens (diff-review).
6. **Repo gates unaffected** — `uv run pytest`, `uv run ruff check .`, and
   `skills/test_skills_valid.py` stay green (nothing they cover changed).
7. **No secrets staged** — `git diff --cached` carries no `.env`; secret-scan clean.

## Packaging

Docs-only branch. Suggested two-commit grouping (plan may refine):
- Hermes walkthrough + Profiles + correctness fix (D1) and cross-cutting (D4-Hermes).
- pi walkthrough (D2) + `integrations/pi/` wiring (D3) + cross-cutting (D4-pi).

Push is user-gated (surface the hash, wait). No new runtime code, so CI touches
only markdown/JSON.
