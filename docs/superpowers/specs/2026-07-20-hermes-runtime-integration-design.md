# Hermes Agent Runtime Integration — Design

**Date:** 2026-07-20
**Status:** Phase A COMPLETE (executed 2026-07-20, see §3.5); Phase B next
**Goal:** Live-validate f0_sectools under the **Hermes Agent** runtime (v0.18.2,
the library's primary intended target), then ship it as a one-command
**profile distribution** — without disturbing the operator's existing general
Hermes agent.

---

## 1. Background — what we learned from the installed runtime

The prior plan assumed a fresh Hermes install and a config template that would
be rendered over `~/.hermes/config.yaml`. Inspecting the **actually-installed
Hermes Agent v0.18.2** invalidated both assumptions:

- **`~/.hermes/` is a live daily driver**, not a blank install — a 17 KB
  `config.yaml` with WhatsApp/Slack gateways, kanban, pets, memories, sessions,
  and **8 existing personalities**. Rendering our template over it would clobber
  a working setup. **We will not write to the `default` profile's config.**
- **Our `integrations/hermes/config.example.yaml` is structurally valid** (an
  initial read misdiagnosed `mcp_servers:` as drift — corrected below).
  Validated block-by-block against the installed source:

  | Template block | Verdict | Notes for v0.18.2 |
  |---|---|---|
  | `mcp_servers:` (top-level) | ✅ Real — populated by `hermes mcp add` | Absent until the profile has ≥1 server (which caused the initial mis-read); `mcp.json` is the same map as a distribution-owned file |
  | `skills.external_dirs:` | ✅ Real (has source + tests) | Loads skills from the repo in place |
  | `agent.personalities:` | ✅ Real | Switched with `/personality <name>`; coexists with the 8 stock personas |

### Two Hermes primitives, not one

- **Personality** — a text lens layered on *one* agent (`/personality ciso`),
  sharing that agent's tools, skills, and memory. Our 4 role personas are
  personalities.
- **Profile** — a *fully isolated Hermes instance* (own config, MCP servers,
  skills, SOUL, memory; own HERMES_HOME on disk). `hermes profile use <name>`
  switches the sticky default; `default` lives at `/home/jimx/.hermes`.

The operator's goal ("switch to sec-tools while keeping Hermes as a general
agent") **is the profile mechanism**, with our 4 personas living *inside* that
profile as personalities.

### Why isolation is the *architecturally correct* choice (not just tidy)

`hermes mcp add` has **no `--profile` flag** (open upstream issue #61765) — it
writes to the **active** profile. The library's entire thesis is that small
local models degrade with too many registered tools. Putting all 7 sec-tools
servers (~45 tools) in the general `default` profile would trigger exactly that
failure mode for *both* general and security use. An isolated profile scopes the
45 tools to the security agent and leaves the general agent clean.

---

## 2. Decisions locked (with the operator)

| Decision | Choice | Rationale |
|---|---|---|
| Direction | **A → B**: stand up a local isolated profile now, validate, then graduate to a git-installable distribution | Validate live before packaging (mirrors the repo's add-a-platform recipe: "validate live → then package") |
| Model backend | **Qwen3.5-9B** via **llama.cpp** at `http://localhost:8081/v1` | Our reference small-model tool-caller and the eval-scorecard baseline; already live. Frontier `kimi-k3` stays on `default`. |
| First validation pass | **Read-only sweep** across all 7 servers | Shake out schema/callability drift with zero state change; gated-write live test deferred to a later, explicit pass |
| Phase-A reproducibility | Direct `hermes` CLI commands (no throwaway script) | Phase B's distribution *is* the reusable installer; a Phase-A script would be superseded |

**GPU note:** only one local model fits the 16 GB GPU at a time. Qwen3.5-9B is
loaded on :8081; the sec-tools profile uses it. `default`/kimi-k3 is cloud and
unaffected. Do not run Ollama (:11434) models concurrently with :8081.

---

## 3. Phase A — Isolated profile + read-only live validation

### 3.1 Stand up the profile (local, reversible, isolated)

Ordering is **load-bearing** because `mcp add` targets the active profile:

1. `hermes profile create f0sectools --clone --description "f0_sectools security-operations agent: read-only SOC/IR/CISO tooling over Defender, Entra, LimaCharlie, ProjectAchilles, Intune, Tenable, driven by a local small model."`
   - `--clone` copies `config.yaml`, `.env`, `SOUL.md`, and skills from the
     active (`default`) profile, so the security profile inherits a working base
     (providers, tool defaults). We then override the security-specific pieces.
2. `hermes profile use f0sectools` — make it the sticky-active profile.
3. **Verify active** (`hermes profile list` shows `◆ f0sectools`) *before any
   `mcp add`.* This is the guard against polluting `default`.
4. **Model backend** → point the profile at Qwen3.5-9B. Either `hermes model`
   (interactive picker after adding the :8081 provider) or edit the profile's
   `config.yaml`:
   ```yaml
   model:
     base_url: http://localhost:8081/v1
     default: Qwen3.5-9B
     provider: local-8081
     api_key: dummy          # llama.cpp ignores it
     api_mode: chat_completions
   providers:
     local-8081:
       api: http://localhost:8081/v1
       name: Local llama.cpp (Qwen3.5-9B)
       default_model: Qwen3.5-9B
   ```
5. **MCP servers** (into the *now-active* f0sectools profile) — one `add` per
   server; the server loads its own `.env.<platform>` via `uv run --directory`,
   so **no secrets enter Hermes config** (`--env` unused):
   ```
   hermes mcp add f0-defender        --command <abs-uv> --args run --directory <checkout> f0-defender-mcp
   hermes mcp add f0-entra           --command <abs-uv> --args run --directory <checkout> f0-entra-mcp
   hermes mcp add f0-limacharlie     --command <abs-uv> --args run --directory <checkout> f0-limacharlie-mcp
   hermes mcp add f0-projectachilles --command <abs-uv> --args run --directory <checkout> f0-projectachilles-mcp
   hermes mcp add f0-pa-actions      --command <abs-uv> --args run --directory <checkout> f0-projectachilles-actions-mcp
   hermes mcp add f0-intune          --command <abs-uv> --args run --directory <checkout> f0-intune-mcp
   hermes mcp add f0-tenable         --command <abs-uv> --args run --directory <checkout> f0-tenable-mcp
   ```
   `<abs-uv>` = `which uv`; `<checkout>` = `/home/jimx/F0RT1KA/sec-tools`.
   `f0-pa-actions` write tools stay inert unless `PROJECTACHILLES_ALLOW_WRITE=true`
   (not set for the read-only pass).
6. **Skills** — point the profile at the repo skills in place (no copy):
   ```yaml
   skills:
     external_dirs:
       - <checkout>/skills
   ```
7. **SOUL + personas** — copy `integrations/hermes/SOUL.md` to the profile's
   `SOUL.md`, and add our 4 personas under `agent.personalities`
   (ciso / threat-hunter / detection-engineer / security-engineer) from
   `integrations/hermes/config.example.yaml`.

### 3.2 Read-only validation sweep

Start Qwen3.5-9B on :8081, launch `hermes chat` in the f0sectools profile, and
drive one representative read task per server (each **user-gated** — a real
tenant call). Confirm the tool is **selected**, **arg-filled**, and returns a
well-shaped **finding** (not just "no crash" — verify field shapes, per the
recipe's step-9 lesson):

| Server | Representative read | Default skill |
|---|---|---|
| f0-defender | Secure score + open incidents | defender-posture-summary |
| f0-entra | Risky users / privileged roles | entra-identity-risk-review |
| f0-limacharlie | Org overview / endpoint investigation | investigate-lc-endpoint |
| f0-projectachilles | Defense score / weak techniques | pa-defense-posture-review |
| f0-pa-actions | `list_tasks` / `get_task_status` (reads only) | — |
| f0-intune | Device compliance review | intune-device-compliance-review |
| f0-tenable | Exposure posture review | tenable-exposure-posture-review |

Also verify: `/personality` switching changes response framing; a `posture`
finding (missing permission / rate-limit) is relayed plainly and halts.

### 3.3 Fix-forward

Each drift/callability bug found → branch → PR → merge (house rules; push only
on explicit instruction). Expect 1–3 (mocks/templates encode assumptions; the
live runtime is truth). After **any** tool-description edit, re-run the affected
server's eval (descriptions are a shared namespace — the #47 lesson).

**Exit criteria for Phase A:** all 7 servers return correctly-shaped findings
under Qwen3.5-9B in Hermes; personas switch; degradation relayed. The
`default` profile is provably untouched.

---

## 3.5 Phase A — Results (executed 2026-07-20)

Phase A ran end-to-end and is complete. What actually happened, and the
mechanics the pre-execution plan above got wrong (carry these into Phase B):

**Stood up & validated.** Isolated `f0sectools` profile created
(`~/.hermes/profiles/f0sectools`), pointed at Qwen3.5-9B on `:8081`, 7 MCP
servers / 45 tools wired, 22 skills via `external_dirs`, security SOUL + 4
personas. The `default` profile was never touched (0 MCP servers, still
kimi-k3). **Read-sweep passed on all 7 servers** (Defender, Entra, LimaCharlie,
ProjectAchilles, pa-actions reads, Intune, Tenable) with real-tenant data.
**Gated writes validated** (chat-confirm): single-host *and* fleet-by-tag — an
8-host `group-b` fleet resolved with a count-bound intent `<uuid>@tag:group-b:8`.

**Plan corrections (important for Phase B):**
- **`hermes mcp add` is interactive** ("Enable all N tools?") and has **no
  `--profile` flag** (upstream issue #61765) — it writes to the *active*
  profile. Scope via the `hermes -p <profile>` wrapper; pipe `Y` for
  non-interactive add. The distribution's `mcp.json` sidesteps this entirely.
- **`toolsets:` is NOT an enforcing whitelist** in the chat/`-z` path (Hermes
  defaults to the `hermes-cli` bundle, `cli.py:15493`). The security-only
  **lockdown must use `agent.disabled_toolsets`** + a session restart — set it
  in the distribution `config.yaml`. (A `toolsets: [<mcp names>]` whitelist edit
  was a no-op and was reverted.)
- `mcp_servers:` top-level **is a real key**, populated by `hermes mcp add` (the
  Phase-A "not a real key" read was mistaken — it checked the *default* profile,
  which has no servers, so the key was simply absent). `mcp.json` is the same
  `mcp_servers` map as a distribution-owned file. `config.example.yaml` is
  **not** drifted; a distribution ships `mcp.json` because it is *replaced* on
  update while `config.yaml` is *preserved*.

**Bugs found → fixed → merged** (the fix-forward the live run was for):
- **#1 Entra output bounding** — `list_privileged_role_assignments` returned
  ~100 findings (~123 KB) past Hermes' 50 KB `tool_output` cap; the small model
  silently saw a fraction. Fixed (default 100→25 + `clamp_limit` +
  "more available" note, criticals-first preserved). **PR #53, merged.**
- **#2 pa-actions fleet-by-tag routing** — a multi-turn "run the *same* test on
  the hosts with tag X" made the model enumerate hosts instead of passing `tag`.
  Sharpened `run_test`/`schedule_test` descriptions. **PR #52, merged.**

**Key lesson.** The isolated eval routes `tag` at 100% even with distractor
tools; single-turn tag runs work. The failure only appears under a realistic
loaded context (skills + 45 tools + multi-turn history, ~78 K tokens). **The
vacuum eval structurally cannot reproduce context-load small-model degradation —
Hermes itself is the test instrument** for that class of bug. (Env note: the
`:8081` llama.cpp backend is flaky under sustained eval load; single `-z` calls
are fine.)

## 4. Phase B — Profile distribution (the shippable artifact)

Package the *validated* profile as a git-installable distribution so anyone runs
`hermes profile install github.com/ubercylon8/f0_sectools` and gets the whole
security agent (skills + MCP + personas + SOUL), keeping their own keys/memory.

Distribution layout (authored in the repo, likely under
`integrations/hermes/distribution/` or a dedicated path — decided in the Phase-B
plan):

- `distribution.yaml` — manifest: name, version, and **env-var requirements**
  (documents the per-platform `.env` the operator must supply; never ships
  secrets).
- `SOUL.md` — the security identity (from `integrations/hermes/SOUL.md`).
- `config.yaml` — model/tool defaults + the 4 `agent.personalities`.
- `mcp.json` — the 7 servers (the distribution-owned form of the `mcp_servers`
  map, chosen because it is *replaced* on update, unlike the *preserved*
  `config.yaml`), using `${F0_SECTOOLS_DIR}` for the per-user checkout path.
- `skills/` — bundled, or referenced via `skills.external_dirs` to the repo.
- (optional) `cron/` — deferred; no scheduled tasks in v1.

Phase B **keeps `integrations/hermes/config.example.yaml`** (the valid "manually
merge `mcp_servers:` into your profile" path, optionally repointed to
`${F0_SECTOOLS_DIR}`) and adds the distribution alongside it, and updates
`docs/user-guide/runtimes/hermes.md`. The drift-guard test
(`integrations/test_integrations_valid.py`) is **extended** to also assert the
distribution `mcp.json` wires all 7 servers — keeping both the template and the
distribution in sync with `servers/*`.

Phase B is a code deliverable → it gets its own `writing-plans` plan and
subagent-driven execution once Phase A validates.

---

## 5. Out of scope (this design)

- Live **gated-write** test under Hermes (deferred to an explicit later pass;
  the confirmation flow itself is already validated under pi).
- Hermes **gateway/messaging** (WhatsApp/Slack/Telegram) integration for
  sec-tools — the `default` profile already owns those; not a security-agent goal.
- **Cron**/scheduled security tasks — YAGNI for v1.
- Editing the **`default`** profile in any way.

---

## 6. Risks / open items

- **Profile disk layout** — confirmed each profile is an isolated HERMES_HOME;
  the exact path for `f0sectools` is revealed on `create` (default is
  `~/.hermes`; no `profiles/` dir exists yet). Verify before editing its config.
- **`hermes model` is interactive** — if scripting the provider add is awkward,
  edit the profile `config.yaml` directly (§3.1 step 4). Confirm the provider key
  format matches the installed schema (`providers.<key>.api`), which we read from
  the live config.
- **Literal-enum `""`/case caveat (#46)** — if Hermes validates MCP input
  schemas strictly, watch whether the promoted `Literal` enums reject empty or
  wrong-case values during the sweep; note any such interaction.
- **GPU contention** — one local model at a time (§2). Keep :8081 loaded; don't
  start :11434 models during the sweep.
