# Runtime Walkthroughs: Hermes Agent & pi — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the Hermes and pi runtime pages into full, runnable walkthroughs; correct the "Profiles = personas" bug; add pi as a first-class runtime via the existing `pi-mcp-extension` bridge; ship `integrations/pi/` wiring.

**Architecture:** Docs + runtime wiring only. No `core/` or `servers/*/` changes. `integrations/pi/` mirrors `integrations/hermes/` file-for-file. Skills load unmodified in both runtimes (identical `mcp_f0-*` tool-name scheme).

**Tech Stack:** Markdown docs, JSON config (`pi-mcp-extension` `mcp.json`), pi prompt-template `.md` files.

## Global Constraints

Every task's requirements implicitly include these (from the approved spec, `docs/superpowers/specs/2026-07-14-runtime-walkthroughs-hermes-pi-design.md`):

- **Docs + wiring only.** No edit under `core/` or any `servers/*/` package; no change to tool behaviour, schemas, or the findings contract.
- **Every runtime claim must trace to a verified primary-source page.** The allowed facts and their citations are the spec's "Verified Facts" section. Assert nothing outside it.
- **Personas = Hermes `agent.personalities` + `/personality`, NOT Profiles.** Profiles are documented separately as a deployment pattern.
- **pi omits native MCP by design; the `pi-mcp-extension` bridge fills it.** No bridge code is written or shipped from this repo. No TypeScript.
- **Secrets never in committed files.** `mcp.json` and examples carry no credentials; each server loads its own `.env.<platform>`. Placeholder path is `/ABSOLUTE/PATH/TO/sec-tools` (matches `examples/mcp/`). No real `.env` staged.
- **DRY / rule 9.** `integrations/` carries wiring only; skill *content* stays in `skills/`. Persona lens text in `integrations/pi/prompts/*.md` is a **faithful verbatim mirror** of the matching `agent.personalities` lens in `integrations/hermes/config.example.yaml`.
- **Single source of truth.** Runtime pages under `docs/user-guide/runtimes/` are canonical; `integrations/*/README.md` point to them, never duplicate steps.
- **Verified console-script names** (from each server's `pyproject.toml` `[project.scripts]`): `f0-defender-mcp`, `f0-entra-mcp`, `f0-limacharlie-mcp`, `f0-projectachilles-mcp`, `f0-intune-mcp`, `f0-tenable-mcp`.
- **Push is user-gated.** Commit locally; do not push.

## File Structure

- `docs/user-guide/runtimes/hermes.md` — rewrite (full walkthrough + Profiles + fix).
- `docs/user-guide/runtimes/pi.md` — new (full walkthrough).
- `integrations/pi/README.md` — new (file table → canonical guide).
- `integrations/pi/mcp.json` — new (`pi-mcp-extension` config, 6 servers).
- `integrations/pi/AGENTS.md` — new (base identity; SOUL.md equivalent).
- `integrations/pi/prompts/ciso.md` — new (persona prompt template).
- `integrations/pi/prompts/threat-hunter.md` — new.
- `integrations/pi/prompts/detection-engineer.md` — new.
- `integrations/pi/prompts/security-engineer.md` — new.
- `docs/user-guide/README.md` — edit (support matrix: fix Hermes line, add pi row + runtime list).
- `docs/user-guide/using-skills-and-personas.md` — edit (personas-per-runtime mapping).
- `CLAUDE.md` — edit (Runtimes section: add pi bullet).
- `README.md` — edit (runtime lists mention pi).

No two tasks edit the same file (Task 1 → hermes.md; Task 2 → pi.md; Task 3 → integrations/pi/*; Task 4 → the four index docs). Safe to review independently.

---

### Task 1: Rewrite the Hermes walkthrough

**Files:**
- Modify (full rewrite): `docs/user-guide/runtimes/hermes.md`

**Interfaces:**
- Consumes: `integrations/hermes/SOUL.md`, `integrations/hermes/config.example.yaml` (already exist; referenced by relative link).
- Produces: canonical Hermes runtime page that Task 4 links to and whose persona framing Task 4's matrix must match.

- [ ] **Step 1: Replace the entire file** `docs/user-guide/runtimes/hermes.md` with:

````markdown
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

1. **Install Hermes** and point its model backend at your local OpenAI-compatible
   endpoint (vLLM / llama.cpp) per the Hermes config docs — any compliant endpoint
   works.

2. **Base identity** — copy the shared identity into place:
   ```bash
   cp integrations/hermes/SOUL.md ~/.hermes/SOUL.md
   ```
   It defines the read-only / never-fabricate operating principles that always
   apply.

3. **Config** — merge [`integrations/hermes/config.example.yaml`](../../../integrations/hermes/config.example.yaml)
   into `~/.hermes/config.yaml` and adjust the absolute paths (`which uv`, your
   checkout). It wires:
   - `mcp_servers` → `f0-defender`, `f0-entra` (stdio, launched via
     `uv run --directory`). Add the other servers the same way
     (`f0-limacharlie`, `f0-projectachilles`, `f0-intune`, `f0-tenable`).
   - `skills.external_dirs` → this repo's `skills/` (loaded **in place** — no
     copying, version-controlled with the code).
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
- **`agent.disabled_toolsets`** — drop built-in toolsets you don't want competing
  for the model's attention.

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
````

- [ ] **Step 2: Verify the correctness fix and key claims are present**

Run:
```bash
cd /home/jimx/F0RT1KA/sec-tools
grep -q "Personas are \`agent.personalities\`, not Profiles" docs/user-guide/runtimes/hermes.md && \
grep -q "hermes profile create acme" docs/user-guide/runtimes/hermes.md && \
grep -q "tools.include" docs/user-guide/runtimes/hermes.md && \
! grep -qi "profile system that maps directly onto our" docs/user-guide/runtimes/hermes.md && \
echo "CLAIMS OK"
```
Expected: `CLAIMS OK` (the two-concept fix present; the old wrong wording gone).

- [ ] **Step 3: Verify relative links resolve**

Run:
```bash
cd /home/jimx/F0RT1KA/sec-tools/docs/user-guide/runtimes && \
test -f ../getting-started.md && \
test -f ../../../integrations/hermes/SOUL.md && \
test -f ../../../integrations/hermes/config.example.yaml && \
test -f ../using-skills-and-personas.md && \
echo "LINKS OK"
```
Expected: `LINKS OK`.

- [ ] **Step 4: Commit**

```bash
cd /home/jimx/F0RT1KA/sec-tools
git add docs/user-guide/runtimes/hermes.md
git commit -m "docs(hermes): full walkthrough; fix Profiles↔personas; add Profiles deployment section"
```

---

### Task 2: New pi walkthrough

**Files:**
- Create: `docs/user-guide/runtimes/pi.md`

**Interfaces:**
- Consumes (by relative link — created in Task 3, but the link targets are known now): `integrations/pi/mcp.json`, `integrations/pi/AGENTS.md`, `integrations/pi/` dir.
- Produces: canonical pi runtime page that Task 4 links to.

Note: this task's links point at files Task 3 creates. If Task 2 runs before Task 3, the link-existence check in Step 2 will be limited to the already-existing targets; the `integrations/pi/*` existence is verified in Task 3. This is acceptable — the two tasks are sequential and the final Task 4 gates whole-tree links.

- [ ] **Step 1: Create** `docs/user-guide/runtimes/pi.md` with:

````markdown
# Runtime: pi

[pi](https://pi.dev/docs/latest) (earendil-works) is a minimal, extensible
terminal agent harness. It speaks the same **agentskills.io** skill format we use,
carries personas as prompt templates, and runs local or hosted models — so for
fully-local, privacy-preserving operation, point it at your own endpoint (step 2).

**One caveat up front:** pi **intentionally ships no built-in MCP support**. Our
value is the MCP servers, so we bridge them with the production-ready
[`pi-mcp-extension`](https://pi.dev/packages/pi-mcp-extension) (step 3). No bridge
code is shipped from this repo — you install and configure the extension.

Prerequisite: finish [getting started](../getting-started.md).

## 1. Install pi

Install pi per its [quickstart](https://pi.dev/docs/latest/quickstart).

## 2. Point pi at your local model

Add a local OpenAI-compatible provider in `~/.pi/agent/models.json`:

```json
{
  "providers": {
    "f0-local": {
      "baseUrl": "http://localhost:8000/v1",
      "api": "openai-completions",
      "apiKey": "$OPENAI_API_KEY",
      "models": [
        { "id": "your-model-name" }
      ]
    }
  }
}
```

- `baseUrl` — your vLLM (`:8000`) or llama.cpp (`:8080`) endpoint.
- `apiKey` — a literal, `"$ENV_VAR"`, or `"!command"`. vLLM/llama.cpp accept any
  token; a dummy or env var is fine.

Select the model with `/model` (the file reloads without a restart).

## 3. Bridge in the MCP servers

Install the MCP client extension:

```bash
pi install npm:pi-mcp-extension
```

Then declare our servers in `~/.pi/agent/mcp.json` (or project-level
`.pi/mcp.json`). A ready copy lives at
[`integrations/pi/mcp.json`](../../../integrations/pi/mcp.json) — copy it and
replace the placeholder path with your checkout:

```json
{
  "settings": { "toolPrefix": "mcp", "requestTimeoutMs": 30000, "maxRetries": 5 },
  "mcpServers": {
    "f0-defender": {
      "command": "uv",
      "args": ["run", "--directory", "/ABSOLUTE/PATH/TO/sec-tools", "f0-defender-mcp"],
      "transport": "stdio",
      "lifecycle": "lazy"
    }
  }
}
```

(The shipped file wires all six servers.)

- `lifecycle: "lazy"` spawns a server on first use, not all six at startup.
- **No credentials here.** Each server loads its own `.env.<platform>` from the
  repo root — secrets never enter `mcp.json`.
- Bridged tools appear as `mcp_f0-<server>_<tool>` (e.g.
  `mcp_f0-defender_list_incidents`) — the same scheme Hermes uses, so our skills
  work unchanged.

## 4. Base identity (the SOUL.md equivalent)

pi has no `SOUL.md`; it auto-loads `AGENTS.md` context files. Copy our base
identity into place:

```bash
cp integrations/pi/AGENTS.md ~/.pi/agent/AGENTS.md
```

It carries the same read-only / never-fabricate principles as the Hermes
`SOUL.md`. (For a full system-prompt replacement instead, use `.pi/SYSTEM.md`.)

## 5. Skills

Load our skills unmodified by adding the directory to `~/.pi/agent/settings.json`:

```json
{ "skills": ["/ABSOLUTE/PATH/TO/sec-tools/skills"] }
```

They're the same agentskills.io `SKILL.md` packages Hermes uses. pi loads names
and descriptions at startup and reads the full skill on demand; invoke one
explicitly with `/skill:name`, or pass `--no-skills` to disable discovery.

## 6. Personas (prompt templates)

pi carries personas as **prompt templates** — one `.md` per lens, invoked as a
slash command. Point pi at ours in `settings.json`:

```json
{ "prompts": ["/ABSOLUTE/PATH/TO/sec-tools/integrations/pi/prompts"] }
```

This registers `/ciso`, `/threat-hunter`, `/detection-engineer`, and
`/security-engineer`. Each overlays the base `AGENTS.md` identity — the same
lenses as Hermes' `/personality`.

## 7. Use it

```text
/ciso
give me a security posture summary
# → defender-posture-summary skill → mcp_f0-defender_get_secure_score +
#   mcp_f0-defender_list_incidents, framed for an executive.

/threat-hunter
hunt for PowerShell downloads today
# → defender-threat-hunt skill → mcp_f0-defender_run_hunting_query (KQL, bounded).
```

## Notes

- Everything is read-only; no gated write actions are exposed.
- The `skills/` are the same files Hermes and Claude Code use — no pi-specific
  copies.
- pi extensions run with full permissions — install `pi-mcp-extension` only from
  the trusted source linked above.
- Wiring for this runtime lives in
  [`integrations/pi/`](../../../integrations/pi/) (`mcp.json`, `AGENTS.md`, and the
  four persona prompt templates).
````

- [ ] **Step 2: Verify key claims and the pre-existing link**

Run:
```bash
cd /home/jimx/F0RT1KA/sec-tools
grep -q "intentionally ships no built-in MCP" docs/user-guide/runtimes/pi.md && \
grep -q "pi install npm:pi-mcp-extension" docs/user-guide/runtimes/pi.md && \
grep -q "mcp_f0-<server>_<tool>" docs/user-guide/runtimes/pi.md && \
grep -q "AGENTS.md" docs/user-guide/runtimes/pi.md && \
test -f docs/user-guide/getting-started.md && \
echo "PI CLAIMS OK"
```
Expected: `PI CLAIMS OK`.

- [ ] **Step 3: Commit**

```bash
cd /home/jimx/F0RT1KA/sec-tools
git add docs/user-guide/runtimes/pi.md
git commit -m "docs(pi): add full pi runtime walkthrough (local model, pi-mcp-extension, skills, personas)"
```

---

### Task 3: `integrations/pi/` wiring

**Files:**
- Create: `integrations/pi/README.md`
- Create: `integrations/pi/mcp.json`
- Create: `integrations/pi/AGENTS.md`
- Create: `integrations/pi/prompts/ciso.md`
- Create: `integrations/pi/prompts/threat-hunter.md`
- Create: `integrations/pi/prompts/detection-engineer.md`
- Create: `integrations/pi/prompts/security-engineer.md`

**Interfaces:**
- Consumes: the four persona lens texts from `integrations/hermes/config.example.yaml` (mirror verbatim).
- Produces: files the pi walkthrough (Task 2) links to.

- [ ] **Step 1: Create** `integrations/pi/README.md`:

````markdown
# pi integration

Files for running f0_sectools under [pi](https://pi.dev/docs/latest):

| File | Purpose |
|------|---------|
| `mcp.json` | [`pi-mcp-extension`](https://pi.dev/packages/pi-mcp-extension) config wiring the six MCP servers (stdio via `uv run --directory`). Copy to `~/.pi/agent/mcp.json` or `.pi/mcp.json`. |
| `AGENTS.md` | Base agent identity — read-only / never-fabricate principles (the `SOUL.md` equivalent). Copy to `~/.pi/agent/AGENTS.md`. |
| `prompts/*.md` | The four persona lenses as prompt templates → `/ciso`, `/threat-hunter`, `/detection-engineer`, `/security-engineer`. Point `settings.prompts` at this dir. |

pi has no native MCP — the `mcp.json` is consumed by the `pi-mcp-extension`
bridge, not by pi directly.

**Full setup and usage:** see the canonical guide at
[`docs/user-guide/runtimes/pi.md`](../../docs/user-guide/runtimes/pi.md).
(Single source of truth — don't duplicate setup steps here.)
````

- [ ] **Step 2: Create** `integrations/pi/mcp.json`:

```json
{
  "settings": {
    "toolPrefix": "mcp",
    "requestTimeoutMs": 30000,
    "maxRetries": 5
  },
  "mcpServers": {
    "f0-defender": {
      "command": "uv",
      "args": ["run", "--directory", "/ABSOLUTE/PATH/TO/sec-tools", "f0-defender-mcp"],
      "transport": "stdio",
      "lifecycle": "lazy"
    },
    "f0-entra": {
      "command": "uv",
      "args": ["run", "--directory", "/ABSOLUTE/PATH/TO/sec-tools", "f0-entra-mcp"],
      "transport": "stdio",
      "lifecycle": "lazy"
    },
    "f0-limacharlie": {
      "command": "uv",
      "args": ["run", "--directory", "/ABSOLUTE/PATH/TO/sec-tools", "f0-limacharlie-mcp"],
      "transport": "stdio",
      "lifecycle": "lazy"
    },
    "f0-projectachilles": {
      "command": "uv",
      "args": ["run", "--directory", "/ABSOLUTE/PATH/TO/sec-tools", "f0-projectachilles-mcp"],
      "transport": "stdio",
      "lifecycle": "lazy"
    },
    "f0-intune": {
      "command": "uv",
      "args": ["run", "--directory", "/ABSOLUTE/PATH/TO/sec-tools", "f0-intune-mcp"],
      "transport": "stdio",
      "lifecycle": "lazy"
    },
    "f0-tenable": {
      "command": "uv",
      "args": ["run", "--directory", "/ABSOLUTE/PATH/TO/sec-tools", "f0-tenable-mcp"],
      "transport": "stdio",
      "lifecycle": "lazy"
    }
  }
}
```

- [ ] **Step 3: Create** `integrations/pi/AGENTS.md`:

````markdown
# f0_sectools — agent identity

You are the **f0_sectools** security-operations assistant. You help SOC analysts,
security engineers, threat hunters, and CISOs understand their security posture
and decide on the right course of action, using **read-only** tools that connect
to their own security platforms (Microsoft Defender, Entra ID, LimaCharlie,
ProjectAchilles, Intune, Tenable). You run on the operator's own infrastructure
with a local model — privacy is the point.

## Operating principles (always)

- **Read-only.** You investigate, summarize, and recommend; you cannot change
  anything. If asked to take an action (isolate a host, disable a user), explain
  that it is not available in read-only mode and recommend the manual step.
- **Never fabricate.** Report only what tools return — real incidents, scores,
  IDs, rows. If you have no tool result for a claim, do not make the claim.
- **One tool at a time.** Call a tool, wait for the result, then decide the next
  step. Don't chain guesses.
- **Relay degradation.** If a tool returns a `posture` finding (missing
  permission, rate-limited), tell the user plainly and stop — don't retry blindly.
- **Ground every statement** in a finding's `evidence`/`references`. Prefer "the
  tool shows…" over bare assertion.

## Style

- Direct, concise, security-literate. Lead with the answer.
- No hype, no filler, no false confidence.
- Use the structured findings (severity, entity, evidence, recommended action) as
  the backbone of every response.

## Output

- Default shape: **finding → evidence → recommended next action**.
- Match depth to the audience. Switch lenses with the persona prompt templates
  (`/ciso`, `/threat-hunter`, `/detection-engineer`, `/security-engineer`):
  tactical for analysts and hunters, configuration-level for engineers, aggregated
  and business-framed for the CISO.
````

- [ ] **Step 4: Create** `integrations/pi/prompts/ciso.md` (lens text verbatim from `config.example.yaml`'s `ciso`):

````markdown
---
description: CISO lens — executive risk framing, posture rollups
---
Operate as a CISO advisor. Audience is executive: lead with risk and business
impact, keep it short, avoid tool names, IDs, and raw JSON. Prefer the
defender-posture-summary skill — report Secure Score, open incidents by severity,
the top 2-3 exposures, and the single highest-value next step. For endpoint
posture, use LimaCharlie's get_org_overview (sensor coverage, detection volume).
For device-management posture, use the intune-device-compliance-review skill
(managed / compliant / encrypted counts). Quantify risk plainly; never speculate
beyond tool results.
````

- [ ] **Step 5: Create** `integrations/pi/prompts/threat-hunter.md` (verbatim from `config.example.yaml`'s `threat-hunter`):

````markdown
---
description: Threat-hunter lens — hypothesis-driven, MITRE, timelines
---
Operate as a threat hunter. Be hypothesis-driven and technical. Hunt with the
defender-threat-hunt skill (KQL, last 30 days) and the limacharlie-threat-hunt
skill (LCQL endpoint telemetry); correlate with triage-defender-incident and
investigate-lc-endpoint. Reference MITRE ATT&CK techniques, reconstruct timelines,
and state what evidence confirms or refutes the hypothesis. For a device's Intune
management state during triage, use the intune-device-triage skill. Bound every
query; report only returned rows.
````

- [ ] **Step 6: Create** `integrations/pi/prompts/detection-engineer.md` (verbatim from `config.example.yaml`'s `detection-engineer`):

````markdown
---
description: Detection-engineer lens — coverage, tuning, ATT&CK mapping
---
Operate as a detection engineer. Focus on detection quality, coverage, and
tuning. For Microsoft, pull alerts/incidents and map them to MITRE, flagging noisy
detections (e.g. repetitive DLP). For LimaCharlie, use the review-detection-coverage
skill: compare deployed D&R rules against what actually fired (the
offensive↔defensive loop), separating detection rules from output/forwarding
rules. Recommend concrete detection or tuning changes; stay grounded in the
findings.
````

- [ ] **Step 7: Create** `integrations/pi/prompts/security-engineer.md` (verbatim from `config.example.yaml`'s `security-engineer`):

````markdown
---
description: Security-engineer lens — hardening, misconfig, coverage gaps
---
Operate as a security engineer. Focus on configuration and hardening. Use Secure
Score improvement actions and the Entra tools (conditional access policies,
privileged role assignments) to surface misconfigurations and excessive privilege;
use LimaCharlie sensors for endpoint coverage gaps (e.g. offline or missing
agents); and use the intune-coverage-gap-review skill for device gaps (stale,
non-compliant, and unencrypted devices). Recommend specific, actionable fixes
(enable a disabled CA policy, reduce Global Admin count, deploy a missing sensor,
remediate an unencrypted device). Report exactly what the tools show.
````

- [ ] **Step 8: Verify JSON validity, no secrets, and persona parity**

Run:
```bash
cd /home/jimx/F0RT1KA/sec-tools
python -m json.tool integrations/pi/mcp.json > /dev/null && echo "JSON OK"
# All six console-script names present and correct:
for s in f0-defender-mcp f0-entra-mcp f0-limacharlie-mcp f0-projectachilles-mcp f0-intune-mcp f0-tenable-mcp; do
  grep -q "\"$s\"" integrations/pi/mcp.json || { echo "MISSING $s"; exit 1; }
done && echo "SERVERS OK"
# No credentials leaked into wiring:
! grep -riE "(api[_-]?key|secret|token|password)\s*[:=]\s*[\"'][^\"']" integrations/pi/ && echo "NO SECRETS"
# Persona parity — the four lens files exist with frontmatter:
for p in ciso threat-hunter detection-engineer security-engineer; do
  test -f "integrations/pi/prompts/$p.md" && head -1 "integrations/pi/prompts/$p.md" | grep -q '^---$' || { echo "BAD $p"; exit 1; }
done && echo "PERSONAS OK"
```
Expected: `JSON OK`, `SERVERS OK`, `NO SECRETS`, `PERSONAS OK`.

- [ ] **Step 9: Verify persona lens text matches the Hermes source (manual diff-review)**

Run:
```bash
cd /home/jimx/F0RT1KA/sec-tools
# Spot-check a distinctive phrase from each lens is mirrored:
grep -q "the single highest-value next step" integrations/pi/prompts/ciso.md && \
grep -q "LCQL endpoint telemetry" integrations/pi/prompts/threat-hunter.md && \
grep -q "offensive↔defensive loop" integrations/pi/prompts/detection-engineer.md && \
grep -q "reduce Global Admin count" integrations/pi/prompts/security-engineer.md && \
echo "PARITY OK"
```
Expected: `PARITY OK`. (These phrases are copied verbatim from the matching `agent.personalities` entries in `integrations/hermes/config.example.yaml`.)

- [ ] **Step 10: Commit**

```bash
cd /home/jimx/F0RT1KA/sec-tools
git add integrations/pi/
git commit -m "feat(integrations): add pi wiring — mcp.json, AGENTS.md identity, four persona prompt templates"
```

---

### Task 4: Cross-cutting index docs (matrix, personas map, CLAUDE.md, README)

**Files:**
- Modify: `docs/user-guide/README.md`
- Modify: `docs/user-guide/using-skills-and-personas.md`
- Modify: `CLAUDE.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: the canonical pages from Tasks 1–2 and the wiring from Task 3 (links must resolve).

- [ ] **Step 1: Fix the support-matrix Hermes line and add the pi row** in `docs/user-guide/README.md`.

Replace this exact block (the runtimes table, currently lines ~58-66):
```markdown
| Runtime | Skills | Personas | MCP transport | Guide |
|---------|--------|----------|---------------|-------|
| Hermes Agent | ✅ native | ✅ profiles | stdio | [hermes.md](runtimes/hermes.md) |
| Claude Code | ✅ native | via prompt | stdio | [claude-code.md](runtimes/claude-code.md) |
| LM Studio | ➖ system prompt | ➖ prompt modes | stdio | [lm-studio.md](runtimes/lm-studio.md) |
| Open WebUI | ➖ system prompt | ➖ prompt modes | HTTP via `mcpo` | [open-webui.md](runtimes/open-webui.md) |
```
with:
```markdown
| Runtime | Skills | Personas | MCP transport | Guide |
|---------|--------|----------|---------------|-------|
| Hermes Agent | ✅ native | ✅ `/personality` | stdio | [hermes.md](runtimes/hermes.md) |
| pi | ✅ native | ✅ prompt templates | stdio via `pi-mcp-extension` | [pi.md](runtimes/pi.md) |
| Claude Code | ✅ native | via prompt | stdio | [claude-code.md](runtimes/claude-code.md) |
| LM Studio | ➖ system prompt | ➖ prompt modes | stdio | [lm-studio.md](runtimes/lm-studio.md) |
| Open WebUI | ➖ system prompt | ➖ prompt modes | HTTP via `mcpo` | [open-webui.md](runtimes/open-webui.md) |
```

- [ ] **Step 2: Add pi to the "Pick your runtime" list** in `docs/user-guide/README.md`.

Replace this exact list item:
```markdown
   - **[Claude Code](runtimes/claude-code.md)** — terminal agent (skills + MCP).
```
with:
```markdown
   - **[Claude Code](runtimes/claude-code.md)** — terminal agent (skills + MCP).
   - **[pi](runtimes/pi.md)** — minimal terminal harness (skills + personas; MCP
     via the `pi-mcp-extension` bridge).
```

- [ ] **Step 3: Add the personas-per-runtime mapping** in `docs/user-guide/using-skills-and-personas.md`.

Replace this exact block (the two runtime bullets under "## Personas (role lenses)"):
```markdown
- **Hermes:** switch with `/personality ciso` (defined in
  [`integrations/hermes/config.example.yaml`](../../integrations/hermes/config.example.yaml)).
- **LM Studio / Open WebUI / Claude Code:** the same modes are in the portable
  prompt — say "as a CISO…" / "switch to threat hunter".
```
with:
```markdown
- **Hermes:** switch with `/personality ciso` (defined in
  [`integrations/hermes/config.example.yaml`](../../integrations/hermes/config.example.yaml)).
- **pi:** invoke `/ciso` (prompt templates in
  [`integrations/pi/prompts/`](../../integrations/pi/prompts/)); the same four
  lenses.
- **LM Studio / Open WebUI / Claude Code:** the same modes are in the portable
  prompt — say "as a CISO…" / "switch to threat hunter".
```

- [ ] **Step 4: Add the pi runtime bullet** in `CLAUDE.md`.

Replace this exact line (in the "### Runtimes" list):
```markdown
- **Claude Code / other agentskills.io clients** — the same `skills/` load unmodified.
```
with:
```markdown
- **Claude Code / other agentskills.io clients** — the same `skills/` load unmodified.
- **pi** ([pi.dev](https://pi.dev/docs/latest)) — minimal agentskills.io terminal harness; the same `skills/` load unmodified. No native MCP — bridge our servers with the `pi-mcp-extension`. `integrations/pi/` holds `mcp.json`, `AGENTS.md` (base identity), and the four persona prompt templates. See `docs/user-guide/runtimes/pi.md`.
```

- [ ] **Step 5: Mention pi in the root README runtime list.**

In `README.md`, replace this exact text (line ~32):
```markdown
See the **[User Guide](docs/user-guide/README.md)** for per-runtime setup (Hermes, LM Studio, Open WebUI, Claude Code), skills, personas, and example workflows.
```
with:
```markdown
See the **[User Guide](docs/user-guide/README.md)** for per-runtime setup (Hermes, pi, LM Studio, Open WebUI, Claude Code), skills, personas, and example workflows.
```

And replace this exact architecture-diagram label (line ~122):
```markdown
      RT["Hermes · Claude Code · LM Studio<br/>skills + personas"]
```
with:
```markdown
      RT["Hermes · pi · Claude Code · LM Studio<br/>skills + personas"]
```

- [ ] **Step 6: Verify all edits landed and links resolve**

Run:
```bash
cd /home/jimx/F0RT1KA/sec-tools
grep -q "✅ \`/personality\`" docs/user-guide/README.md && \
grep -q "runtimes/pi.md" docs/user-guide/README.md && \
grep -q "integrations/pi/prompts/" docs/user-guide/using-skills-and-personas.md && \
grep -q "pi-mcp-extension" CLAUDE.md && \
grep -q "Hermes, pi, LM Studio" README.md && \
! grep -q "✅ profiles" docs/user-guide/README.md && \
echo "EDITS OK"
# Link targets exist:
test -f docs/user-guide/runtimes/pi.md && test -d integrations/pi/prompts && echo "LINKS OK"
```
Expected: `EDITS OK`, `LINKS OK`.

- [ ] **Step 7: Confirm repo gates unaffected (nothing under core/ or servers/ changed)**

Run:
```bash
cd /home/jimx/F0RT1KA/sec-tools
git diff --cached --name-only  # sanity: no .env, no core/ or servers/ files
uv run python skills/test_skills_valid.py 2>/dev/null || uv run pytest skills/test_skills_valid.py -q
uv run ruff check . && uv run pytest -q
```
Expected: skills-validity passes, ruff clean, pytest green (no Python changed, so this only confirms no accidental breakage).

- [ ] **Step 8: Commit**

```bash
cd /home/jimx/F0RT1KA/sec-tools
git add docs/user-guide/README.md docs/user-guide/using-skills-and-personas.md CLAUDE.md README.md
git commit -m "docs: wire pi into the support matrix, personas map, CLAUDE.md, and README"
```

---

## Self-Review (completed by plan author)

- **Spec coverage:** D1 → Task 1; D2 → Task 2; D3 → Task 3; D4 → Task 4. All deliverables mapped.
- **Placeholder scan:** `/ABSOLUTE/PATH/TO/sec-tools` and `your-model-name` are intentional config placeholders (match `examples/mcp/`); no `TBD`/`TODO`.
- **Type/name consistency:** the six console-script names are identical across the plan, verified against `pyproject.toml`. Tool-name scheme `mcp_f0-<server>_<tool>` is consistent in both walkthroughs. Persona file names (`ciso`, `threat-hunter`, `detection-engineer`, `security-engineer`) match the slash commands `/ciso` etc. and the Hermes `agent.personalities` keys.
- **No file overlap between tasks:** confirmed (Task 1 hermes.md · Task 2 pi.md · Task 3 integrations/pi/* · Task 4 four index docs).
- **Verification is grep/link/JSON** (TDD N/A for prose), plus a single repo-gates run in Task 4.
