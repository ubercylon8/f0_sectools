# f0_sectools v0.1.0 Public-Release Prep — Design

**Status:** approved-for-planning
**Date:** 2026-07-13
**Author:** James Pichardo (with Claude Code)

## Goal

Make the f0_sectools repository ready for a **great** first public impression as
`v0.1.0`, without changing any shipped code behaviour. This is a
documentation-, community-health-, and showcase-polish effort. The two
irreversible switches — the `v0.1.0` git tag and flipping the repo public — are
**user-gated** and explicitly out of scope for autonomous execution; this work
only *prepares* them.

## Context (repo state at design time)

- 6 live-validated MCP servers: `defender`, `entra`, `limacharlie`,
  `projectachilles`, `intune`, `tenable` (34 read tools total).
- `core/` foundation, 20 portable skills, 4 personas, Hermes integration,
  eval + agentic-eval harness, scorecard.
- CI: 7 GitHub Actions; `ci` / `secret-scan` / `semgrep` are hard gates and
  green. Secret-history gate clean — no real `.env` tracked (only
  `.env.*.example`); `.gitignore` correctly ignores `.env.*`.
- `LICENSE` (Apache-2.0), `NOTICE`, `CONTRIBUTING.md`, `SECURITY.md` already
  present and good quality.
- Full suite green; `ruff` + `mypy` clean.

**The problem this solves:** a visitor landing on the repo today cannot tell it
is real. The README's platform section is titled *"(target roadmap)"* and leads
with unbuilt platforms (Wazuh/Splunk/CrowdStrike…), while the 6 working servers
are a single paragraph at the bottom. The project's most distinctive proof point
— that small local models *measurably* drive these tools (the scorecard) — is
invisible on the front page.

## Decisions (locked)

- **Scope:** maximal / showcase.
- **README audience:** two-track, balanced — practitioner value first, the
  small-model engineering story as the differentiator immediately after.
- **Security contact:** `security@fortika.io` (confirmed to route).
- **Demo asset:** a **mock/eval-based** recording now (no live platform, no GPU
  required), because a live skill run is user-gated and a real local-model run
  needs power/GPU the operator does not have at authoring time. A real
  local-model recording may be added later; it is not a release blocker.
- **Packaging:** one `docs/release-prep-v0.1.0` branch → **two reviewable PRs**
  (release-docs, then showcase). Push is user-gated as always.

## Non-goals (YAGNI)

- No code/behaviour changes to `core/` or any server.
- No new platform servers, tools, or skills.
- No live-platform calls and no GPU/model runs.
- Not creating the git tag or flipping the repo public (user does both).
- No badge sprawl — only badges that reflect a real, green signal.

---

## Deliverables

### PR-1 — Release docs & community health

#### D1. README rewrite (`README.md`)

Full rewrite, working-servers-first, two-track. Required sections in order:

1. **Title + one-line description** + badges. Badges: existing License +
   Python, **plus a CI-status badge** for `ci.yml` (a real green signal). No
   other badges.
2. **What it is** — 2–3 sentences: AI agents ↔ security platforms, for
   SOC/security-engineer/hunter/CISO, rendered per audience.
3. **The differentiator (short)** — privacy-first, small **local** models,
   read-only-by-default. One paragraph.
4. **What works today** — a table of the **6 live-validated servers** with tool
   counts and a one-line capability summary each. This is the "it's real"
   moment and must appear above the fold.

   | Server | Status | Tools | What it reads |
   |---|---|---|---|
   | `f0-defender-mcp` | ✅ live-validated | 6 (4 read + 2 gated) | secure score, incidents, alerts, hunting (KQL); gated `isolate_host` / `release_host` |
   | `f0-entra-mcp` | ✅ live-validated | 4 | risky users, risk detections, conditional access, privileged roles |
   | `f0-limacharlie-mcp` | ✅ live-validated | 6 | org overview, sensors, sensor detail, D&R rules, detections, LCQL telemetry |
   | `f0-projectachilles-mcp` | ✅ live-validated | 6 | defense score, weak techniques, test executions, risk acceptances, agents, fleet health |
   | `f0-intune-mcp` | ✅ live-validated | 6 | managed devices, compliance, stale devices, policies, config profiles |
   | `f0-tenable-mcp` | ✅ live-validated | 6 | vuln summary, top vulns, assets, per-asset vulns, plugin info, scans |

   Total **34 registered tools** (matches the scorecard's composition column).
   Defender is the only server with gated writes — the concrete example of the
   safety model. Counts verified against each server's `list_tools` test.
5. **Track 1 — For security teams (practitioner):** the safety model
   (read-only default; gated writes need flag + single-use human token +
   audit); the four personas; link to the User Guide.
6. **Track 2 — For local-AI builders (the differentiator):** the small-model
   eval story. Lead line grounded in the scorecard: *every tested model scores
   100%/100% per-server across all six platforms; the full 34-tool registry is
   driven at up to 100%.* Link `evals/SCORECARD.md` and
   `docs/runtime-performance.md`. Name the design rules that make it possible
   (flat args, short enums, ≤~8 tools/server, bounded output).
7. **Quickstart (≤ 60 seconds path)** — clone → `uv sync` → copy one
   `.env.<platform>.example` → run the server / run the eval. Real, runnable
   commands.
8. **Architecture (short)** — 2–3 sentences (shared core + thin servers) with
   the Mermaid diagram from D6 and a link to `docs/architecture.md`.
9. **Roadmap** — the *remaining* planned platforms, clearly labelled
   **planned**, visually separated from "what works today" so the two are never
   conflated again.
10. **Docs / Contributing / Security / License** links.

Constraints: every capability claim must trace to something real in the repo;
no aspirational feature described as present-tense. Keep the file skimmable
(headings + one table), target well under the current sprawl.

#### D2. Doc-drift sweep

Fix stale claims found across the tree:
- `docs/user-guide/README.md:15` — "Today: Microsoft **Defender** and **Entra
  ID**." → reflect all 6 servers (or drop the "today" enumeration and point at
  the support matrix just below it).
- `docs/user-guide/workflows.md:164` — "pivots across all four servers" → the
  accurate count/wording for the cross-platform skill.
- `CONTRIBUTING.md` — de-emphasise the Wazuh-as-first-server framing where it
  reads as current state; keep the "add a platform" recipe generic.
- `CLAUDE.md:200` — "start with Wazuh as the reference implementation": reconcile
  the wording so it does not imply Wazuh is built (it is a planned target). Touch
  only that line's framing; do not restructure CLAUDE.md.
- Grep the whole tree once more for stale counts ("four", "4 servers") and fix
  any straggler.

#### D3. SECURITY.md contact

Add the private reporting channel to the existing "Reporting a vulnerability"
section: email **security@fortika.io**. Keep the rest of the file intact.

#### D4. Community-health files

- `.github/ISSUE_TEMPLATE/bug_report.md` — standard bug template (repro, env,
  which server, expected/actual). Reminds reporters **not** to paste secrets or
  raw platform data.
- `.github/ISSUE_TEMPLATE/new_platform_request.md` — tuned to this repo: which
  platform, auth model, read capabilities wanted, any gated writes, links to
  API docs. Mirrors the "Adding a New Platform Server" recipe shape.
- `.github/ISSUE_TEMPLATE/config.yml` — disable blank issues; link the User
  Guide + Security policy.
- `.github/PULL_REQUEST_TEMPLATE.md` — checklist mirroring the Critical Rules:
  read-only (or gated via `core/gating/` with flag+token+audit); returns the
  findings schema; redaction at the boundary incl. error paths; eval task added
  for new tools; flat args/short enums; no `.env`/secrets staged; tests + ruff
  + mypy green.
- `CODE_OF_CONDUCT.md` — Contributor Covenant 2.1 verbatim, contact
  `security@fortika.io`.

#### D5. `examples/mcp` content

The `examples/mcp/` directory is currently empty (dead end). Populate with:
- `examples/mcp/README.md` — what these are, the base-name vs runtime-prefix note.
- A Claude Code `mcp.json` snippet wiring one server (e.g. tenable) over stdio.
- A generic stdio MCP-client config example (runtime-agnostic).
No secrets; reference `.env.<platform>` by path only.

### PR-2 — Showcase

#### D6. Architecture diagram (`docs/architecture.md` + README embed)

A Mermaid diagram: local model (vLLM/llama.cpp) → agent runtime (Hermes /
Claude Code) → MCP servers (the 6) → each platform API, with `core/` (schema,
redaction, auth, gating, renderers) as the shared layer every server imports.
`docs/architecture.md` holds the diagram + a short narrative of the
shared-core/thin-server rule; the README embeds the same diagram. Mermaid
renders natively on GitHub — no image asset to maintain.

#### D7. Demo asset (mock/eval-based)

A recorded terminal walkthrough that needs **neither a live platform nor a
GPU**, so any visitor can reproduce it:
- **Primary choice:** record a **scorecard/eval run** (or a mock-backed tool
  sequence) that shows a model selecting the right tools and the server
  returning real findings JSON.
- Format: `asciinema` → committed **SVG** (via `svg-term` or `agg`) so it
  renders inline in the README with no external host / no autoplay video
  dependency. If SVG tooling is unavailable, fall back to an annotated
  fenced-code transcript in the README (still zero-dependency).
- The exact recording target and tool are finalised in the plan; the invariant
  is: reproducible, no live platform, no GPU, renders on GitHub, embedded near
  the top of Track 2 or the Quickstart.

#### D8. CHANGELOG.md

`CHANGELOG.md` at repo root, Keep-a-Changelog format, with a `## [0.1.0]`
section summarising the initial public release (6 servers, core, skills,
personas, eval harness, Hermes integration, CI). Doubles as the GitHub release
notes draft. No date-locked "Unreleased" cruft beyond the 0.1.0 entry.

### Out-of-band (user performs)

- Confirm `security@fortika.io` routes (confirmed).
- Enable/verify any GitHub repo settings needed (e.g. if advisories are wanted
  later — not required for v0.1.0).
- Create the `v0.1.0` tag and flip the repo public. Claude prepares the release
  notes (D8) and hands over these switches; Claude does not perform them.

---

## Verification

- **Every capability/status claim in the README traces to a real artifact**
  (a server test, a skill, a scorecard cell). No present-tense aspirational
  claims.
- Tool counts in D1's table match each server's `list_tools` test.
- `grep` for stale counts ("four servers", "Today: … Defender and Entra")
  returns nothing after D2.
- `skills/test_skills_valid.py` and the full `pytest` suite still pass (docs-only
  changes must not break anything); `ruff` clean.
- Markdown links resolve (the `links` workflow / a local lychee pass).
- No `.env` or secret staged in either PR (`git ls-files | grep .env` shows only
  `.example`).
- Mermaid diagram renders (GitHub preview or a mermaid linter).
- Demo asset renders inline on GitHub and was produced with no live-platform /
  no-GPU path.

## Risks & mitigations

- **Over-claiming in the README** → every claim cross-checked against a repo
  artifact during D1; the verification gate above is explicit about it.
- **Demo scope creep** (chasing a live/GPU recording) → decision locked to
  mock/eval; a plain transcript is an acceptable fallback, so PR-2 never blocks
  on tooling.
- **CLAUDE.md churn** → D2 touches only the one misleading line's framing; no
  restructuring of the house-rules doc.
- **Docs drifting again later** → the User Guide already has a "living guide"
  contract; the README's "what works today" table becomes the second
  update-on-change surface (noted in the roadmap section).
