# CLAUDE.md

This file provides essential guidance to Claude Code (and other agents) when working with this repository.

## Overview

**f0_sectools** is an open-source library of **tools and skills for AI agents that connect to security platforms** — SIEM/XDR, EDR, identity, and threat-intelligence systems — to understand security posture, assess risk, and help take the right course of action for a **SOC analyst, security engineer, threat hunter, or CISO**.

It is the **defensive / operational counterpart** to [`f0_library`](../f0_library) (offensive EDR detection testing). Both are part of the **F0RT1KA** brand and the **ProjectAchilles** ecosystem, licensed under **Apache 2.0**.

### The thesis: privacy-preserving security operations with small, local models

The entire repo is designed so organizations can run security-operations agents **on their own infrastructure, with small open-weight models** — GPT-OSS (20b/120b), Gemma 4, Qwen3 — served locally via **vLLM** or **llama.cpp**. No telemetry, no sensitive security data leaving the host, no dependency on a frontier cloud API.

This single constraint drives almost every design rule below. Small local models are now genuinely good at tool calling, but their reliability degrades sharply with complex schemas, too many tools, aggressive quantization, and oversized payloads. **Our job is to build tools these models can actually drive, reliably, on real security data.**

### Form factor

- **MCP servers** (`servers/`) — one thin Model Context Protocol server per platform, exposing read tools (and gated write actions). Runtime-agnostic: they target the OpenAI-compatible API surface, so they work behind vLLM, llama.cpp, or any compliant front-end.
- **Skills** (`skills/`) — higher-level playbooks that orchestrate the servers (e.g. "triage a Defender incident", "build a posture summary for the CISO"). They follow the **[agentskills.io](https://agentskills.io) open standard** (`SKILL.md`) — originally Anthropic's Agent Skills format, now adopted by Hermes, Claude Code, Goose, and others. **One portable set, no runtime-specific forks.**
- **Personas** — four role lenses (CISO, threat hunter, detection engineer, security engineer) that shape output. Delivered as Hermes `agent.personalities` profiles and mirrored as switchable modes in the portable system prompt.
- **Runtimes** — primary target is **Hermes Agent** (skills-aware, native MCP, OpenAI-compatible backend; see `integrations/hermes/`). The same skills run under Claude Code and other agentskills.io clients. For non-skill chat UIs (LM Studio, Open WebUI) a portable system prompt in `prompts/` carries the same guidance. See [Skills, Personas & Runtimes](#skills-personas--runtimes).

---

## Critical Rules (NEVER VIOLATE)

1. **Read-only by default.** Every tool that queries a platform is read-only. Any tool that *changes state* on a live platform (isolate host, disable user, quarantine file, close incident) is a **gated write action** — see [Gated Write Actions](#gated-write-actions). It MUST require both an explicit config flag AND a per-action human confirmation token.
2. **Secrets never leave the host and never reach the model.** Credentials are loaded from per-platform `.env` files. They are **never logged, never included in tool output, never passed into a prompt or model context, never sent off-box.**
3. **Redact before returning.** All tool output passes through the core redaction layer before it is returned to the agent. Strip API keys, tokens, raw PII, and secrets from every payload — including error messages and stack traces.
4. **Every tool returns the structured findings schema.** No tool returns ad-hoc text. Output is normalized JSON (see [The Findings Schema](#the-findings-schema)) so agents — and small models especially — can parse and chain results predictably.
5. **Tools must be small-model-safe.** Flat argument schemas, short enums, few tools per server, no deeply nested objects, bounded/paginated output. See [Designing Tools for Small Models](#designing-tools-for-small-models). This is the repo's reason to exist — do not regress it for convenience.
6. **All safety logic lives in `core/`, never in a server.** Redaction, secret handling, the findings schema, and the gated-action machinery are implemented once, in the shared core, and imported by every server. A server must not re-implement or bypass them.
7. **Per-platform credential isolation.** Each platform has its own `.env.<platform>`. No cross-platform credential bleed; a server only loads its own platform's secrets.
8. **Audit every write action.** Gated actions are logged (who/what/when/which target/confirmation token) to a local audit trail — never to an external service.
9. **Skills are one portable set, not per-runtime forks.** All skills follow the agentskills.io `SKILL.md` standard and live once in `skills/`. Runtime-specific wiring (Hermes config/personas, the LM Studio system prompt) lives in `integrations/` and `prompts/` and must not duplicate skill *content* — same DRY discipline as rule 6.

---

## Designing Tools for Small Models

This is the core differentiator of f0_sectools. A tool can be functionally perfect and still **fail because a small local model cannot reliably call it.** Design every tool against these rules.

**Assume the model is GPT-OSS-20b / Gemma 4 / Qwen3 at 8-bit quant, served locally.** Treat that as the floor, not the ceiling.

### Do

- **Keep argument schemas flat.** Top-level scalar parameters (`host_id: str`, `severity_min: int`). Avoid nested objects and arrays-of-objects as inputs.
- **Use short, closed enums.** `severity: "low" | "medium" | "high" | "critical"` — not a free-form string, and not a 40-value enum the model picks wrong from.
- **Keep few tools per server** (target ≤ ~8). Tool-selection accuracy drops as the registered tool count grows. Split a sprawling platform across focused servers rather than registering 20 tools.
- **Name parameters descriptively.** `alert_id` not `id`, `time_window_hours` not `t`. The name *is* the model's primary cue.
- **Bound and paginate every output.** Security APIs return enormous result sets. Default to a small page size, return a `next_cursor`, and summarize counts. An unbounded dump blows the context window and silently degrades tool accuracy.
- **Make reads idempotent and deterministic.** Same args → same shape, every time.
- **Write tool descriptions for a model, not a human.** One clear sentence on *when* to use it and *what it returns*.

### Don't

- ❌ Nested/object-valued arguments or polymorphic params.
- ❌ Long free-text arguments the model must construct (e.g. raw KQL/SPL) without a guided, validated helper.
- ❌ Registering many tools "just in case."
- ❌ Returning raw, unbounded platform JSON.
- ❌ Relying on the model to remember multi-step state across calls — encode it in args or in a skill.

### Why (grounding)

Documented failure modes for this model class: degraded tool accuracy when context exceeds VRAM (silent CPU fallback), regressions under 4-bit quantization, mis-selection among many tools, and mangled nested arguments. The [small-model eval harness](#testing--evaluation) exists to **measure** callability so these defects fail CI instead of surfacing in production.

---

## Architecture

**Shared core library + thin per-platform servers.** All cross-cutting and safety-critical logic lives in `core/`; each server is a thin adapter that knows only its platform's API and tool definitions.

```
f0_sectools/
  core/                     # shared package — imported by every server
    schema/                 # the findings schema + validators
    redaction/              # secret/PII stripping (applied to ALL output)
    auth/                   # per-platform .env loading, token refresh
    paging/                 # pagination, truncation, rate-limiting
    smallmodel/             # tool helpers: flat-arg builders, enum guards, arg validation
    gating/                 # gated write-action machinery + audit log
    renderers/              # persona renderers (analyst/engineer/ciso/hunter)
  servers/                  # one thin MCP server per platform
    wazuh-mcp/
    elastic-mcp/
    splunk-mcp/
    sentinel-mcp/
    defender-mcp/
    crowdstrike-mcp/
    sentinelone-mcp/
    sophos-mcp/
    entra-mcp/
    misp-mcp/
    thehive-mcp/
    opencti-mcp/
  skills/                   # portable agentskills.io playbooks (SKILL.md) — load in any skills-aware runtime
    defender/
      triage-incident/      # SKILL.md (+ references/, templates/)
      posture-summary/
      threat-hunt/
  integrations/             # runtime-specific wiring (NO skill content — see rule 9)
    hermes/                 # SOUL.md + config.example.yaml (mcp_servers, external skills dir, 4 personas)
  prompts/                  # portable system prompts for non-skill UIs (LM Studio, Open WebUI)
  evals/                    # small-model tool-calling eval harness + task sets
  docs/
```

**The rule:** a server defines its tools and calls its platform's API. *Everything else* — auth, redaction, schema normalization, pagination, gating, rendering — it gets from `core/`. This keeps the safety guarantees enforceable in one auditable place and prevents drift across a dozen integrations.

> We deliberately start with a single shared-core layout (not independently-published packages). If we later decide to ship servers individually (`pip install f0-sectools-wazuh`), we graduate to a monorepo-packages layout then — not before (YAGNI).

---

## The Findings Schema

Every tool returns a normalized finding (or a list of them). This is the source of truth; human-readable views are rendered from it.

```jsonc
{
  "schema_version": "1.0",
  "source": "wazuh",                 // which platform produced this
  "finding_type": "alert",           // alert | misconfig | risk | ioc | posture | action_result
  "severity": "high",                // low | medium | high | critical | info
  "title": "Brute-force authentication against host web-01",
  "entity": {                        // what this is about
    "kind": "host",                  // host | user | file | ip | account | rule | tenant
    "id": "web-01",
    "name": "web-01.corp.local"
  },
  "evidence": [                      // bounded, redacted supporting facts
    { "key": "failed_logins", "value": "142 in 5m" }
  ],
  "recommended_action": {
    "summary": "Isolate host and reset affected credentials",
    "gated_action": "defender.isolate_host",   // null if read-only/no action
    "confidence": "medium"
  },
  "references": [                    // MITRE ATT&CK, KB articles, source IDs
    { "type": "mitre", "id": "T1110" }
  ],
  "observed_at": "2026-06-28T10:00:00Z"
}
```

### Persona renderers

The same finding is rendered differently per audience via `core/renderers/`:

- **SOC analyst** — per-incident, tactical: what happened, evidence, next triage step.
- **Security engineer** — config-level: the misconfig/coverage gap and the fix.
- **CISO / risk leader** — aggregated rollups, risk scoring, exec-framed summaries.
- **Threat hunter / IR** — timeline, pivots, case-building across MISP/TheHive/OpenCTI.

Tools always emit the structured finding; the persona view is a presentation layer, never a different data contract.

> **Two persona layers, don't confuse them.** `core/renderers/` (above, planned) shapes how a *finding's text* is presented. The **agent personas** in [Skills, Personas & Runtimes](#skills-personas--runtimes) shape the *agent's behaviour* — which skills/tools it favours and how it frames a whole response. They compose; the renderer is optional polish, the agent persona is the primary mechanism today.

---

## Skills, Personas & Runtimes

How a local model actually drives these tools. The mechanism differs by runtime, but the **content is authored once**.

> **Operator-facing instructions live in the [User Guide](docs/user-guide/README.md)** (`docs/user-guide/`) — per-runtime setup, workflows, troubleshooting. This section is the builder's view; keep the two in sync when adding a runtime, skill, or persona, and update the User Guide's support matrix.

### Skills (one portable set)

Skills live in `skills/` as **[agentskills.io](https://agentskills.io) `SKILL.md`** packages (the open standard, originally Anthropic's, now adopted by Hermes, Claude Code, Goose, OpenHands, Cursor, …). A skill is a directory with a `SKILL.md` (YAML frontmatter: `name`, `description` ≤60 chars, `version`, optional `metadata.hermes`) plus `## When to Use / Procedure / Pitfalls / Verification`, and optional `references/`. Loaded via progressive disclosure. The same files work in **every** skills-aware runtime — never fork them per runtime (Critical Rule 9). Each skill refers to tools by **base name** (`list_incidents`); runtimes prefix differently (Hermes `mcp_f0-defender_list_incidents`, Claude Code `mcp__f0-defender__list_incidents`).

Current skills: `defender/{triage-incident,posture-summary,threat-hunt}`, `entra/{identity-risk-review,conditional-access-audit,privileged-access-review}`, `limacharlie/{endpoint-investigation,detection-coverage-review,threat-hunt}` (endpoint investigation is the LimaCharlie default focus). A test (`skills/test_skills_valid.py`) enforces valid frontmatter and the ≤60-char description limit on every `SKILL.md`.

### Personas (four role lenses)

CISO, threat hunter, detection engineer, security engineer — each a behavioural lens (focus + output style + which skills/tools to favour). Shared identity and the read-only / never-fabricate principles live in one place; each persona only adds its lens. Delivered as **Hermes `agent.personalities`** (switch with `/personality <name>`) and mirrored as switchable **modes** in the portable prompt.

### Runtimes

- **Hermes Agent** (primary) — skills-aware, native MCP, OpenAI-compatible backend. `integrations/hermes/` holds `SOUL.md` (base identity) and `config.example.yaml` (wires `mcp_servers`, points `skills.external_dirs` at this repo's `skills/` in place, defines the four personalities). See its README.
- **Claude Code / other agentskills.io clients** — the same `skills/` load unmodified.
- **Non-skill chat UIs (LM Studio, Open WebUI)** — no skill system; paste `prompts/f0-sectools-system-prompt.md` (persona-switchable) as the system prompt. See `docs/running-with-local-models.md`.

**Rule of thumb:** skill *content* and persona *definitions* are authored once; `integrations/` and `prompts/` only carry runtime wiring, never copies of skill logic.

---

## Gated Write Actions

Any tool that changes state on a live platform is **read-only-by-default and gated**. The pattern, implemented once in `core/gating/`:

1. **Disabled unless enabled.** The action is unavailable unless the operator sets the platform's write flag (e.g. `DEFENDER_ALLOW_WRITE=true` in `.env.defender`).
2. **Dry-run / intent first.** When invoked, the tool returns the *intended* action as a finding (`finding_type: "action"`) describing exactly what it will do and to which target — it does **not** execute yet.
3. **Confirmation token required.** Execution requires a fresh, single-use confirmation token supplied by a human (or an explicitly human-in-the-loop step). No token → no execution.
4. **Execute + audit.** On a valid token, the action runs and the result, target, actor, and token are written to the local audit trail.

A small local model **must never be able to isolate a host or disable an account on its own.** The flag + token gate is the hard stop.

---

## Platform Integrations

Targets (build incrementally — start with Wazuh as the reference implementation):

| Platform | Category | Auth | Read | Gated write (examples) |
|---|---|---|---|---|
| Wazuh | SIEM/XDR (OSS) | API user/token | alerts, agents, rules, posture | — |
| Elastic / OpenSearch | SIEM (OSS) | API key | detections, queries | — |
| Splunk | SIEM | token | searches, notables | — |
| Microsoft Sentinel | SIEM | Entra app | incidents, analytics | close incident |
| Microsoft Defender | EDR | Entra app | incidents, devices | isolate host |
| CrowdStrike | EDR | OAuth2 | detections, hosts | contain host |
| SentinelOne | EDR | API token | threats, agents | quarantine, isolate |
| Sophos | EDR | API cred | alerts, endpoints | isolate |
| Entra ID / Azure | Identity | Entra app | sign-ins, risky users, roles | disable user |
| MISP | Threat intel (OSS) | API key | events, IOCs, enrichment | — |
| TheHive / Cortex | IR (OSS) | API key | cases, observables, analyzers | create/close case |
| OpenCTI | Threat intel (OSS) | API token | entities, relationships | — |
| LimaCharlie | SecOps/EDR/XDR | OID + API key (SDK) | sensors, detections, D&R rules, LCQL telemetry | isolate sensor (future) |

Each integration follows `.env.<platform>` and the thin-server pattern. Read tools first; gated writes only where operationally valuable and clearly worth the risk.

**Implemented & live-validated:** `defender-mcp`, `entra-mcp`. **Implemented:** `limacharlie-mcp` (uses the official `limacharlie` Python SDK; closes the offensive↔defensive loop with `f0_library`'s D&R rules). The official Go [lc-mcp-server](https://github.com/refractionPOINT/lc-mcp-server) is a different tool (278 tools, write-capable, optional cloud LLM) — referenced in the user guide as the frontier-model alternative, intentionally not incorporated (it's incompatible with the small-model-safe, local-only, read-only-gated thesis).

---

## Secrets & Privacy

- **Per-platform `.env`.** `.env.wazuh`, `.env.defender`, `.env.entra`, … Each server loads only its own. All `.env*` files are gitignored.
- **Nothing leaves the host.** No telemetry, no analytics, no external calls except to the operator's own configured security platforms.
- **Secrets never reach the model.** Credentials live in `core/auth/`; they are used to make API calls and are never placed in tool output, prompts, or model context.
- **Redaction is mandatory and centralized.** Every return path goes through `core/redaction/`, including error/exception paths.

---

## Testing & Evaluation

Two layers, both expected. **Contract tests are mandatory from day one; the small-model eval is built alongside the first server** so schema habits are validated before they harden.

### Layer A — Contract tests (mandatory)

Run each server against **mocked platform APIs**. Verify:
- Tools return correctly-shaped findings (schema validation).
- Redaction strips secrets/PII from output **and** error paths.
- Gated writes refuse without the flag and without a valid confirmation token.
- Pagination/truncation behave under large mocked result sets.

Deterministic, fast, no model or live platform required.

### Layer B — Small-model tool-calling eval

A harness in `evals/` that points a **real local model** (GPT-OSS-20b, Gemma 4, Qwen3) — served via vLLM or llama.cpp's OpenAI-compatible endpoint — at a server's tools and measures **callability**, not just code correctness:

- **Tool-selection accuracy** — given a natural-language task, does the model pick the right tool?
- **Argument-filling success rate** — does it populate args correctly, N runs each?
- **Degradation signals** — flag tools that score poorly (too many tools, enum too large, nested args) as **design defects to fix**, reported as success rates, not pass/fail.

Task sets live as YAML in `evals/`. The eval can run locally against a GPU box or as a scheduled (e.g. nightly) job rather than on every commit.

> If a tool passes Layer A but fails Layer B, **the tool's design is wrong** — simplify the schema, don't lower the bar.

---

## Development Workflow

This repo mirrors `f0_library`'s house workflow.

### Autonomous Mode

Claude Code operates in **autonomous mode** for repository/code work — proceed without asking for standard development operations:

- Create/edit/delete files and directories in the project
- Git add, commit, branch, checkout (**push is gated — see below**)
- Run builds, tests, linters, dependency installs (`uv`, `pip`)
- Fix build/import/test errors

### When TO Ask for Permission

- **Any `git push` to remote** — never push autonomously. Commit locally, surface the pending commit hash, and wait for the user to say "push" (or push themselves).
- **Destructive git operations** — `git push --force`, `git reset --hard` to remote.
- **Any tool call against a LIVE security platform** — calling a real Wazuh/Defender/Entra/etc. endpoint (especially any gated write) requires explicit confirmation; do not hit production platforms autonomously.
- **Credential / `.env` operations** — never create, print, or exfiltrate secrets.
- **Ambiguous requirements** — when intent is unclear.

### Commit Style

Conventional commits; **do not push autonomously.** Stage specific files rather than `git add -A` to avoid pulling in `.env*`, secrets, or unrelated work.

```bash
git add <specific-files> && git commit -m "feat(wazuh): add read-only alert query tool"
# After commit: report the commit hash, wait for explicit push instruction.
```

> Note: this directory is not yet a git repository. Run `git init` before the first commit; add a LICENSE (Apache 2.0), NOTICE, README, and `.gitignore` (must ignore `.env*`, `.venv/`, caches) consistent with `f0_library`.

---

## Tech Stack & Tooling

- **Language:** Python (3.11+).
- **Protocol:** Model Context Protocol (MCP) Python SDK for servers.
- **Model serving (targets):** vLLM and llama.cpp via their OpenAI-compatible endpoints; stay runtime-agnostic — do not special-case a runtime.
- **Packaging/env:** `uv` (or `hatch`) workspace; per-server entry points importing `core/`.
- **Testing:** `pytest` for contract tests; the `evals/` harness for small-model callability.
- **Lint/format:** ruff.

---

## Quick Reference

| If you're… | Then… |
|---|---|
| Adding a platform | Create `servers/<platform>-mcp/`, import `core/`, define ≤~8 flat read tools first |
| Adding a write action | Route through `core/gating/`; require flag + confirmation token; audit it |
| Returning data | Emit the findings schema; let `core/redaction/` and `core/renderers/` do the rest |
| Designing a tool arg | Flat scalar, descriptive name, short closed enum — never nested/objects |
| Tempted to dump platform JSON | Paginate, bound, summarize — protect the context window |
| Writing a skill | One `SKILL.md` in `skills/` (agentskills.io); refer to tools by base name; never fork per runtime |
| Adding a persona/runtime wiring | Hermes → `integrations/hermes/`; non-skill UI → `prompts/`. Wiring only, no skill content |
| About to push | Don't. Commit, surface the hash, wait for the user |
