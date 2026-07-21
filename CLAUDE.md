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
- **Personas** — four role lenses (CISO, threat hunter, detection engineer, security engineer) that shape output. Delivered as Hermes `agent.personalities` (switched with `/personality`, **not** Profiles) and mirrored as switchable modes in the portable system prompt.
- **Runtimes** — primary target is **Hermes Agent** (skills-aware, native MCP, OpenAI-compatible backend; see `integrations/hermes/`). The same skills run under Claude Code and other agentskills.io clients. For non-skill chat UIs (LM Studio, Open WebUI) a portable system prompt in `prompts/` carries the same guidance. See [Skills, Personas & Runtimes](#skills-personas--runtimes).

---

## Critical Rules (NEVER VIOLATE)

1. **Read-only by default.** Every tool that queries a platform is read-only. Any tool that *changes state* on a live platform (isolate host, disable user, quarantine file, close incident) is a **gated write action** — see [Gated Write Actions](#gated-write-actions). It MUST require an explicit config flag AND per-action human confirmation, in one of two modes: **(a) forge-resistant** — a single-use confirmation token or a watcher approval delivered out-of-band on a channel the model cannot read; this is the default and the **only** permitted mode for destructive or irreversible actions. **(b) chat-confirm** — an opt-in, per-platform mode (off by default) where the operator's in-chat "approved" is the confirmation; it is convenient for supervised, reversible actions but is **not** forge-resistant (a misaligned model could fabricate it), so it is never used for destructive actions.
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
    renderers/              # persona renderers (analyst/engineer/ciso/hunter/detection-engineer)
  servers/                  # one thin MCP server per platform
    defender-mcp/           # built + live-validated
    entra-mcp/              # built + live-validated
    limacharlie-mcp/        # built + live-validated
    projectachilles-mcp/    # built + live-validated
    projectachilles-actions-mcp/   # built + live-validated — gated writes
    intune-mcp/             # built + live-validated
    tenable-mcp/            # built + live-validated
    purview-mcp/            # built — live validation pending (data risk: DLP, insider risk, labels, audit)
    # planned: wazuh, elastic, splunk, sentinel, crowdstrike, sentinelone,
    #          sophos, misp, thehive, opencti (see Platform Integrations)
  skills/                   # portable agentskills.io playbooks (SKILL.md) — load in any skills-aware runtime
    defender/               # triage-incident, posture-summary, threat-hunt
    entra/                  # identity-risk-review, conditional-access-audit, privileged-access-review
    limacharlie/            # endpoint-investigation, detection-coverage-review, threat-hunt
    tenable/                # exposure-posture-review, host-vulnerability-triage, scan-coverage-review
    cross-platform/         # multi-server correlation: incident triage, offensive<->defensive loop
  integrations/             # runtime-specific wiring (NO skill content — see rule 9)
    hermes/                 # config.example.yaml (manual-merge) + distribution/ (installable profile: distribution.yaml + config.yaml + SOUL.md)
    pi/                     # mcp.json + AGENTS.md + persona prompt templates
    opencode/               # README only — the wiring is in-repo: /opencode.json + /.opencode/{skills,agents}
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
- **Detection engineer** — alert quality and coverage: findings grouped by ATT&CK technique, unmapped findings flagged.

Tools always emit the structured finding; the persona view is a presentation layer, never a different data contract.

> **Two persona layers, don't confuse them.** `core/renderers/` (above) shapes how a *finding's text* is presented. The **agent personas** in [Skills, Personas & Runtimes](#skills-personas--runtimes) shape the *agent's behaviour* — which skills/tools it favours and how it frames a whole response. They compose; the renderer is optional polish, the agent persona is the primary mechanism today.

---

## Skills, Personas & Runtimes

How a local model actually drives these tools. The mechanism differs by runtime, but the **content is authored once**.

> **Operator-facing instructions live in the [User Guide](docs/user-guide/README.md)** (`docs/user-guide/`) — per-runtime setup, workflows, troubleshooting. This section is the builder's view; keep the two in sync when adding a runtime, skill, or persona, and update the User Guide's support matrix.

### Skills (one portable set)

Skills live in `skills/` as **[agentskills.io](https://agentskills.io) `SKILL.md`** packages (the open standard, originally Anthropic's, now adopted by Hermes, Claude Code, Goose, OpenHands, Cursor, …). A skill is a directory with a `SKILL.md` (YAML frontmatter: `name`, `description` ≤60 chars, `version`, optional `metadata.hermes`) plus `## When to Use / Procedure / Pitfalls / Verification`, and optional `references/`. Loaded via progressive disclosure. The same files work in **every** skills-aware runtime — never fork them per runtime (Critical Rule 9). Each skill refers to tools by **base name** (`list_incidents`); runtimes prefix differently (Hermes `mcp_f0-defender_list_incidents`, Claude Code `mcp__f0-defender__list_incidents`).

Current skills: `defender/{triage-incident,posture-summary,threat-hunt}`, `entra/{identity-risk-review,conditional-access-audit,privileged-access-review}`, `limacharlie/{endpoint-investigation,detection-coverage-review,threat-hunt}` (endpoint investigation is the LimaCharlie default focus), `projectachilles/{defense-posture-review,coverage-gap-analysis,validation-fleet-review,explore-test-catalog,run-validation-test}`, `intune/{device-compliance-review,coverage-gap-review,device-triage}` (device-compliance review is the Intune default focus), `tenable/{exposure-posture-review,host-vulnerability-triage,scan-coverage-review}` (exposure-posture review is the Tenable default focus), and `cross-platform/{triage-incident-cross-platform,validation-coverage-loop}` (multi-server correlation playbooks — favour a capable local model). A test (`skills/test_skills_valid.py`) enforces valid frontmatter and the ≤60-char description limit on every `SKILL.md`.

### Personas (four role lenses)

CISO, threat hunter, detection engineer, security engineer — each a behavioural lens (focus + output style + which skills/tools to favour). Shared identity and the read-only / never-fabricate principles live in one place; each persona only adds its lens. Delivered as **Hermes `agent.personalities`** (switch with `/personality <name>`) and mirrored as switchable **modes** in the portable prompt.

### Runtimes

- **Hermes Agent** (primary) — skills-aware, native MCP, OpenAI-compatible backend. `integrations/hermes/` holds `config.example.yaml` (the manual-merge template — wires `mcp_servers`, points `skills.external_dirs` at this repo's `skills/` in place, defines the four personalities) and **`distribution/`** — a **git-installable profile distribution** (`distribution.yaml` manifest + `config.yaml` + `SOUL.md`; `hermes profile install ./integrations/hermes/distribution`). NB: Hermes reads MCP servers from `config.yaml`'s `mcp_servers` (a distribution `mcp.json` is **not** auto-loaded by the CLI), and the gated-write server ships **disabled-by-default**. See its README + `docs/user-guide/runtimes/hermes.md`.
- **Claude Code / other agentskills.io clients** — the same `skills/` load unmodified.
- **pi** ([pi.dev](https://pi.dev/docs/latest)) — minimal agentskills.io terminal harness; the same `skills/` load unmodified. No native MCP — bridge our servers with the `pi-mcp-extension`. `integrations/pi/` holds `mcp.json`, `AGENTS.md` (base identity), and the four persona prompt templates. See `docs/user-guide/runtimes/pi.md`.
- **opencode** ([opencode.ai](https://opencode.ai), ≥1.18) — terminal agent with native MCP **and** native SKILL.md skills. Wiring ships **in-repo**: root `opencode.json` (7 servers, relative commands, `f0-pa-actions` disabled), `.opencode/skills/` (22 committed symlinks into `skills/` — no forks), `.opencode/agents/` (4 persona agents). Run opencode from the checkout and it all auto-loads. See `integrations/opencode/README.md` + `docs/user-guide/runtimes/opencode.md`.
- **Non-skill chat UIs (LM Studio, Open WebUI)** — no skill system; paste `prompts/f0-sectools-system-prompt.md` (persona-switchable) as the system prompt. See `docs/running-with-local-models.md`.

**Rule of thumb:** skill *content* and persona *definitions* are authored once; `integrations/` and `prompts/` only carry runtime wiring, never copies of skill logic.

---

## Gated Write Actions

Any tool that changes state on a live platform is **read-only-by-default and gated**. The pattern, implemented once in `core/gating/`:

1. **Disabled unless enabled.** The action is unavailable unless the operator sets the platform's write flag (e.g. `DEFENDER_ALLOW_WRITE=true` in `.env.defender`).
2. **Dry-run / intent first.** When invoked, the tool returns the *intended* action as a finding (`finding_type: "action"`) describing exactly what it will do and to which target — it does **not** execute yet.
3. **Human confirmation required.** Three surfaces, implemented in
   `core/gating/`. The first two are **forge-resistant** (single-use,
   target-bound, TTL'd, and the confirmation never round-trips through model
   context) and are the default and the **only** modes permitted for
   destructive or irreversible actions; the third is **opt-in and
   model-forgeable** — see the caveat below.
   - **Watcher (default):** the intent registers a pending request; the
     operator approves it in `python scripts/confirm_action.py --watch`
     (one keypress), and the agent repeats the *identical* tool call — the
     gate consumes the stored approval. No token ever enters model context.
   - **Token (headless/scripted):** `confirm_action.py <action> "<target>"`
     prints a single-use token passed as `confirmation_token` (used by e.g.
     the live-smoke `--execute` flows).
   - **Chat-confirm (opt-in, off by default):** enabled per-platform via
     `<PLATFORM>_CONFIRM_MODE=chat` (today: `PROJECTACHILLES_CONFIRM_MODE`,
     the `projectachilles-actions` server only). The operator simply replies
     "approved" in the chat; the agent re-calls the same tool passing
     `confirmation_token` equal to the `confirmation_target` shown in the
     intent finding. Execution is audited with `method=chat-confirm`, same
     as any other gated action.
   Gating state lives under `$F0_GATING_DIR` (default `~/.f0sectools/gating/`),
   shared by servers and the CLI regardless of working directory. No
   confirmation → no execution.
4. **Execute + audit.** On a valid token or consumed approval, the action runs and the result, target, actor, and token/method are written to the local audit trail.

A small local model **must never be able to isolate a host or disable an account on its own.** The flag + human confirmation (watcher approval or token) is the hard stop.

**Chat-confirm's honest caveat:** unlike the watcher and token surfaces, chat-confirm's "confirmation" is text the model itself can see and echo back — there is no out-of-band channel the model is locked out of. A misaligned or jailbroken model could, in principle, fabricate the operator's "approved" and confirm its own action. It exists only as a low-friction convenience for supervised, reversible operations (e.g. running a validation test) where the operator is watching every turn — it is off by default, must stay opt-in per platform, and **must never be wired to a destructive or irreversible action** (isolate host, disable user, quarantine file, close incident, delete anything). If in doubt, use the watcher or token surface instead. It is also **not single-use or time-limited**: `confirmation_token == target` authorizes *every* call while the write flag is on, including a silent re-execute if the model retries a failed run with the same arguments — the operator must give a fresh "approved" before each re-call, and the model must never reuse the echo to retry a failed execution. This is by design (making it single-use would reintroduce a token and defeat the point of chat mode), so chat-confirm suits supervised sessions only, never unattended operation.

Note: the gate's guarantee holds only when confirm_action.py runs in a terminal the model cannot drive — in runtimes where the model has shell access, treat the approval CLI (especially --approve) as operator-only and keep write flags off.

---

## Platform Integrations

Targets (build incrementally — the six built servers below are the reference implementations):

| Platform | Category | Auth | Read | Gated write (examples) |
|---|---|---|---|---|
| Wazuh | SIEM/XDR (OSS) | API user/token | alerts, agents, rules, posture | — |
| Elastic / OpenSearch | SIEM (OSS) | API key | detections, queries | — |
| Splunk | SIEM | token | searches, notables | — |
| Microsoft Sentinel | SIEM | Entra app | incidents, analytics | close incident |
| Microsoft Defender | EDR | Entra app | incidents, devices, guided hunt | isolate host |
| CrowdStrike | EDR | OAuth2 | detections, hosts | contain host |
| SentinelOne | EDR | API token | threats, agents | quarantine, isolate |
| Sophos | EDR | API cred | alerts, endpoints | isolate |
| Entra ID / Azure | Identity | Entra app | sign-ins, risky users, roles | disable user |
| MISP | Threat intel (OSS) | API key | events, IOCs, enrichment | — |
| TheHive / Cortex | IR (OSS) | API key | cases, observables, analyzers | create/close case |
| OpenCTI | Threat intel (OSS) | API token | entities, relationships | — |
| LimaCharlie | SecOps/EDR/XDR | OID + API key (SDK) | sensors, detections, D&R rules, LCQL telemetry | isolate sensor (future) |
| ProjectAchilles | Security validation (F0RT1KA) | `pa_` API key (Bearer) | defense score, test results, weak techniques, agents | run/schedule/pause/cancel test (actions server) |
| Intune | Identity/Endpoint mgmt | Entra app | devices, compliance, policies | — |
| Tenable | Vulnerability Management | API key (access+secret) | vulnerabilities, assets, scans | — |
| Microsoft Purview | Data security/compliance | Entra app | DLP alerts, insider-risk alerts, sensitivity labels, unified-audit search | — |

Each integration follows `.env.<platform>` and the thin-server pattern. Read tools first; gated writes only where operationally valuable and clearly worth the risk.

**Implemented & live-validated:** `defender-mcp`, `entra-mcp`, `limacharlie-mcp` (the last uses the official `limacharlie` Python SDK and closes the offensive↔defensive loop with `f0_library`'s D&R rules). **Implemented & live-validated:** `projectachilles-mcp` (read-only over the PA REST API with a `pa_` Bearer key — defense score, test results, weak techniques, agents). The PA API lives on the `agent` subdomain (e.g. `https://<org>.agent.projectachilles.io`). **Implemented & live-validated:** `tenable-mcp` (read-only over the Tenable Vulnerability Management Workbenches API with `X-ApiKeys` access/secret keys — vulnerability summary, top vulnerabilities, assets, per-asset vulnerabilities, plugin detail, scans, plugin affected-hosts). The official Go [lc-mcp-server](https://github.com/refractionPOINT/lc-mcp-server) is a different tool (278 tools, write-capable, optional cloud LLM) — referenced in the user guide as the frontier-model alternative, intentionally not incorporated (it's incompatible with the small-model-safe, local-only, read-only-gated thesis). `projectachilles-actions-mcp` is built (7 tools: 4 gated writes — `run_test`, `schedule_test`, `set_schedule_status`, `cancel_tasks` (single task_id **or** a bulk status/search filter, count-bound confirmation, 200 cap) — + 3 reads — `list_schedules`, `get_task_status`, `list_tasks`), the second consumer of `core/gating/` after Defender, **live-validated** on a real tenant with a read-write-scope `pa_` key (single-host and tag/fleet runs, count-bound bulk cancel).

---

## Adding a New Platform Server (repeatable recipe)

The four built servers (`defender`, `entra`, `limacharlie`, `projectachilles`) follow an **identical pattern**. To add a platform, replicate it — `core/` does not change. Do it in this order; TDD each code step.

1. **Config** — add `<Platform>Config` (dataclass + `from_env(prefix=...)`, required vars, optional `verify_tls`/`allow_write`, secrets never logged) to `core/auth/config.py`, with a test in `core/tests/test_config.py`.
2. **Scaffold** `servers/<platform>-mcp/`: `pyproject.toml` (deps `f0-sectools-core`, `mcp`, + the platform's client lib), `README.md`, `.env.<platform>.example` (document the exact required permissions/scopes), `f0_<platform>_mcp/__init__.py`, `tests/`. Then `uv sync --all-packages`.
3. **Client** (`client.py`) — thin wrapper exposing only the read methods needed. Async `httpx` for REST (static Bearer or OAuth); for a **synchronous vendor SDK**, wrap it and have the server run tools via `asyncio.to_thread`.
4. **Errors** (`errors.py`) — `map_<platform>_error(e, capability, …)` mapping auth → posture finding, `403` → `Finding.permission_missing`, `429` → `Finding.rate_limited`, gateway `502/503/504` → "API unavailable" posture finding. **Every failure becomes a finding, never an exception.**
5. **Tools** (`tools.py`) — ≤ ~8 flat read tools returning `list[Finding]`; each catches platform errors → graceful finding else re-raise; defensive dict access. Write the contract tests first (fake client) — **live data validates real field names**.
6. **Server** (`server.py`) — `FastMCP`, one `@mcp.tool()` per tool, build the client from config, **redact at the boundary** (`redact_obj(f.model_dump())`).
7. **Evals** — `evals/<platform>/tasks.yaml` (≥1 task per tool) + add the server to `SERVERS` in `evals/test_eval_coverage.py` and `SERVER_MODULES` in `evals/run.py`.
8. **Smoke script** — `scripts/live_smoke_<platform>.py`.
9. **Live-test** — create `.env.<platform>` at the repo root (gitignored), run the smoke script **with network/sandbox enabled**, and fix-forward field-name/shape mismatches (this step always finds 1–3 — mocks encode assumptions; the live API is truth). Mark live-validated once clean.
10. **Skills** (after the server is validated) — three `SKILL.md` under `skills/<platform>/` (a posture/coverage skill, a gap/investigation skill, a platform-native one). Pick a default focus and say so. Wire into Hermes personas if relevant.
11. **Docs & runtime wiring** — update the Platform Integrations table + Architecture tree here, the README status, the user-guide support matrix + workflows, **and the runtime integration templates** (`integrations/pi/mcp.json`, `integrations/hermes/config.example.yaml`, `integrations/hermes/distribution/config.yaml`). The templates are drift-guarded: `integrations/test_integrations_valid.py` derives the server list from the workspace `[project.scripts]` entries and fails CI if any template is missing a server, references a removed one, or leaks a real local path (placeholders only — operators render locally, e.g. `scripts/sync_pi_config.py`).
12. **Verify & ship** — `uv run pytest`, `uv run ruff check .`, markdown link check, secret scan (no real `.env` staged), commit (conventional, with the Co-Authored-By/session trailers), **push only on explicit instruction**.

**Auth models already handled** (none required a `core/` change): Microsoft Graph OAuth client-credentials, a synchronous vendor SDK (LimaCharlie), and a static `Bearer` REST key (ProjectAchilles). See the Quick Reference table for the one-liners.

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

### Continuous Integration (GitHub Actions)

Every push/PR runs (`.github/workflows/`):

- **ci** — `uv run pytest` (offline contract + harness-logic tests) + `uv run ruff check .` + `uv run mypy .` (strict) — all **hard gates**. mypy is scoped to shipped source (`core/` + each server's package); tests, `evals/`, `scripts/`, and `skills/` are excluded (strict-typing mocks/fixtures/tooling is high-noise, low-value).
- **secret-scan** (gitleaks) and **semgrep** (SAST, gate on `p/python`; `p/security-audit` advisory) — **hard gates**.
- **deps** (pip-audit), **links** (lychee), **codeql** (dormant until the repo is public) — advisory, not required checks.

Live-model evals and live-platform smoke scripts are **never** run in CI (no creds/GPU) — they stay local. Mark only `ci`, `secret-scan`, and `semgrep` as required status checks in branch protection.

**Claude PR review** is provided by the **Claude Code GitHub App** (installed on the repo), which ships two workflows: `claude-code-review.yml` (auto-reviews every PR via the `code-review` plugin — it reads this CLAUDE.md, so the Critical Rules stay in scope) and `claude.yml` (responds to `@claude` mentions in issues/PR comments). Both authenticate with the `CLAUDE_CODE_OAUTH_TOKEN` secret; they post advisory comments and do not block merge. The earlier self-hosted `claude-review.yml` action (var-gated on `ENABLE_CLAUDE_REVIEW` + `ANTHROPIC_API_KEY`) was removed in favour of the app — the `ENABLE_CLAUDE_REVIEW` variable and the now-unused `ANTHROPIC_API_KEY` secret can be deleted from repo settings.

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
