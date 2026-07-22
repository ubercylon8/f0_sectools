# Design history

*Every significant piece of f0_sectools was planned and specced before it was
built. The dated documents under [`docs/superpowers/`](../superpowers/) are the
project's de-facto ADR log — this page is their index. Plans describe the
step-by-step execution; specs capture the design and its rationale. They are
historical records: accurate as of their date, never retro-edited.*

## Plans

- **2026-06-28** — [core-and-microsoft-servers](../superpowers/plans/2026-06-28-core-and-microsoft-servers.md): Stand up the workspace, shared `core/` (schema, redaction, gating, Graph client), and read-only Defender/Entra MCP servers. *(no spec — predates the plan/spec split)*
- **2026-07-10** — [defender-gated-isolate-host](../superpowers/plans/2026-07-10-defender-gated-isolate-host.md): Ship first gated writes — Defender isolate/release host via flag + single-use token + audit, proving no autonomous isolation.
- **2026-07-11** — [cicd-github-actions](../superpowers/plans/2026-07-11-cicd-github-actions.md): Add GitHub Actions CI — test/lint gate, secret scan, SAST, dependency audit, link check, Claude PR review — before going public.
- **2026-07-11** — [cross-platform-correlation-skills](../superpowers/plans/2026-07-11-cross-platform-correlation-skills.md): Two portable SKILL.md playbooks pivoting across all four servers: cross-platform incident triage and offensive↔defensive coverage loop.
- **2026-07-11** — [eval-scorecard-and-multiserver](../superpowers/plans/2026-07-11-eval-scorecard-and-multiserver.md): Reproducible model-by-server scorecard matrix plus combined-registry eval, proving which local models drive all (then-)22 tools reliably.
- **2026-07-11** — [intune-mcp-server](../superpowers/plans/2026-07-11-intune-mcp-server.md): Read-only Intune server (#5) exposing six device-management/compliance tools over Microsoft Graph, reusing `core/` unchanged.
- **2026-07-11** — [persona-renderers](../superpowers/plans/2026-07-11-persona-renderers.md): Build `core/renderers/` — a deterministic library turning a Finding into audience-shaped Markdown for five personas.
- **2026-07-12** — [agentic-skill-eval](../superpowers/plans/2026-07-12-agentic-skill-eval.md): Multi-step eval harness measuring whether a small local model can drive a whole SKILL.md procedure end-to-end.
- **2026-07-12** — [intune-skills](../superpowers/plans/2026-07-12-intune-skills.md): Three portable SKILL.md playbooks for the live-validated Intune server, plus docs marking the server complete.
- **2026-07-13** — [public-release-prep](../superpowers/plans/2026-07-13-public-release-prep.md): Documentation, community-health, and showcase polish readying the repo for its v0.1.0 public debut; no code-behaviour changes.
- **2026-07-13** — [tenable-mcp-server](../superpowers/plans/2026-07-13-tenable-mcp-server.md): Sixth platform server — thin read-only MCP over the Tenable VM Workbenches API, six flat tools plus three skills.
- **2026-07-14** — [bounded-output-and-tenable-plugin-assets](../superpowers/plans/2026-07-14-bounded-output-and-tenable-plugin-assets.md): Add Tenable plugin-to-hosts tool and fix the unbounded `get_all` pattern in defender/entra; clamp limits — surfaced by a pi live-run.
- **2026-07-14** — [defender-guided-hunt](../superpowers/plans/2026-07-14-defender-guided-hunt.md): Guided `hunt` tool building vetted KQL server-side so small models stop guessing field names; custom-KQL tool disambiguated.
- **2026-07-14** — [projectachilles-catalog](../superpowers/plans/2026-07-14-projectachilles-catalog.md): Two small-model-safe read tools (`find_tests`, `get_test`) to explore the ProjectAchilles test catalog by technique/actor/tactic/tag/keyword.
- **2026-07-14** — [runtime-walkthroughs-hermes-pi](../superpowers/plans/2026-07-14-runtime-walkthroughs-hermes-pi.md): Full runnable Hermes and pi runtime walkthroughs, fixing the Profiles-vs-personas bug and shipping `integrations/pi/` wiring.
- **2026-07-18** — [gating-approvals](../superpowers/plans/2026-07-18-gating-approvals.md): One-keypress watcher-terminal approval for gated writes instead of token copy-paste, keeping flag/single-use/target-bound/TTL/audit guarantees.
- **2026-07-18** — [pa-actions-server](../superpowers/plans/2026-07-18-pa-actions-server.md): Second PA server (`f0-pa-actions`) that runs/schedules/pauses/cancels validation tests behind the core gating flag+token+audit gate.
- **2026-07-19** — [gating-chat-confirm](../superpowers/plans/2026-07-19-gating-chat-confirm.md): Opt-in per-platform chat-confirm mode — supervised operator types "approved" in chat — with the token/watcher path unchanged and default.
- **2026-07-19** — [pa-bundle-results](../superpowers/plans/2026-07-19-pa-bundle-results.md): Make `get_task_status` return bundle-rollup outcomes, reword findings to fire-and-report instead of polling, roll up execution listings.
- **2026-07-19** — [pa-fleet-status-cancel](../superpowers/plans/2026-07-19-pa-fleet-status-cancel.md): Give fleet runs first-class identity after launch: run-scoped results (kills the phantom host), one-call lifecycle sweep, bulk gated cancel.
- **2026-07-19** — [pa-fleet-tag-runs](../superpowers/plans/2026-07-19-pa-fleet-tag-runs.md): Let `run_test`/`schedule_test` target a fleet by tag in one gated action, confirmation bound to blast radius forcing re-approval.
- **2026-07-19** — [small-model-safety-hardening](../superpowers/plans/2026-07-19-small-model-safety-hardening.md): Tighten three cross-cutting Rule-5 gaps — string-advertised enums, unbounded read limits, asymmetric read/write validation — without behavioural regression.
- **2026-07-20** — [hermes-profile-distribution](../superpowers/plans/2026-07-20-hermes-profile-distribution.md): Ship `integrations/hermes/distribution/` — a git-installable Hermes profile standing up the validated f0sectools agent via `hermes profile install`.
- **2026-07-21** — [opencode-runtime](../superpowers/plans/2026-07-21-opencode-runtime.md): Wire opencode (≥1.18) as a runtime: root `opencode.json`, skill symlinks, persona agents, drift-guard tests, docs.
- **2026-07-21** — [purview-mcp](../superpowers/plans/2026-07-21-purview-mcp.md): Build server #8 — read-only Microsoft Purview data-risk tools over Microsoft Graph, per the approved design spec.

## Specs

- **2026-07-10** — [defender-gated-isolate-host](../superpowers/specs/2026-07-10-defender-gated-isolate-host-design.md): Design for the first gated write action — Defender isolate/release host through flag, single-use token, and audit machinery.
- **2026-07-11** — [cicd-github-actions](../superpowers/specs/2026-07-11-cicd-github-actions-design.md): Design of the GitHub Actions CI/CD workflow suite — the automated gates required before the repo goes public.
- **2026-07-11** — [cross-platform-correlation-skills](../superpowers/specs/2026-07-11-cross-platform-correlation-skills-design.md): Design of two cross-platform correlation skills (incident triage, offensive↔defensive coverage loop) spanning all four servers.
- **2026-07-11** — [eval-scorecard-and-multiserver](../superpowers/specs/2026-07-11-eval-scorecard-and-multiserver-design.md): Design of the model×server eval scorecard matrix and the combined-registry multi-server eval.
- **2026-07-11** — [intune-mcp-server](../superpowers/specs/2026-07-11-intune-mcp-server-design.md): Design for the read-only Microsoft Intune MCP server (server #5) over Microsoft Graph.
- **2026-07-11** — [persona-renderers](../superpowers/specs/2026-07-11-persona-renderers-design.md): Design of `core/renderers/` — the deterministic five-persona Finding presentation layer.
- **2026-07-11** — [tool-description-disambiguation](../superpowers/specs/2026-07-11-tool-description-disambiguation-design.md): Reword five colliding tool descriptions (hunting pair, overview trio) that caused cross-server mis-selection in the combined eval.
- **2026-07-12** — [agentic-skill-eval](../superpowers/specs/2026-07-12-agentic-skill-eval-design.md): Design of the multi-step agentic eval measuring whether a small model can drive a whole SKILL.md procedure.
- **2026-07-12** — [intune-skills](../superpowers/specs/2026-07-12-intune-skills-design.md): Design of the three portable Intune SKILL.md playbooks under `skills/intune/`.
- **2026-07-13** — [public-release-prep](../superpowers/specs/2026-07-13-public-release-prep-design.md): Design of v0.1.0 public-release preparation — docs, community health, and showcase polish with no shipped-code changes.
- **2026-07-13** — [tenable-mcp-server](../superpowers/specs/2026-07-13-tenable-mcp-server-design.md): Design for tenable-mcp, platform server #6, over the Tenable Vulnerability Management Workbenches API.
- **2026-07-14** — [bounded-output-and-tenable-plugin-assets](../superpowers/specs/2026-07-14-bounded-output-and-tenable-plugin-assets-design.md): Design for shared `core/paging` output-bounding fixes and the new Tenable plugin-to-affected-hosts tool.
- **2026-07-14** — [defender-guided-hunt](../superpowers/specs/2026-07-14-defender-guided-hunt-design.md): Design for the guided Defender `hunt` tool building vetted KQL server-side, disambiguated from custom-KQL `run_hunting_query`.
- **2026-07-14** — [projectachilles-catalog](../superpowers/specs/2026-07-14-projectachilles-catalog-design.md): Design of the `find_tests`/`get_test` read tools for exploring the ProjectAchilles test catalog.
- **2026-07-14** — [runtime-walkthroughs-hermes-pi](../superpowers/specs/2026-07-14-runtime-walkthroughs-hermes-pi-design.md): Design for Hermes and pi runtime walkthroughs plus `integrations/pi/` wiring — docs-only, every claim primary-source-verified.
- **2026-07-18** — [gating-approvals](../superpowers/specs/2026-07-18-gating-approvals-design.md): Design of the approval watcher — low-friction one-keypress gated-write confirmation, because token copy-paste is high-friction.
- **2026-07-18** — [projectachilles-actions](../superpowers/specs/2026-07-18-projectachilles-actions-design.md): Design of the gated-writes ProjectAchilles actions server running/scheduling/pausing/cancelling validation tests.
- **2026-07-19** — [gating-chat-confirm](../superpowers/specs/2026-07-19-gating-chat-confirm-design.md): Design of the opt-in chat-confirm gating mode for supervised reversible actions, since the watcher flow still adds friction.
- **2026-07-19** — [pa-bundle-results](../superpowers/specs/2026-07-19-pa-bundle-results-design.md): Design fixing two live-testing read/UX defects — bundle-result rollups and no-poll fire-and-report status wording.
- **2026-07-19** — [pa-fleet-status-cancel](../superpowers/specs/2026-07-19-pa-fleet-status-cancel-design.md): Design giving fleet runs first-class post-launch identity — run-scoped results, lifecycle sweep, bulk cancel.
- **2026-07-19** — [pa-fleet-tag-runs](../superpowers/specs/2026-07-19-pa-fleet-tag-runs-design.md): Design for fleet-wide test runs by tag in one gated action, with confirmation bound to the blast radius.
- **2026-07-19** — [small-model-safety-hardening](../superpowers/specs/2026-07-19-small-model-safety-hardening-design.md): Design closing three cross-cutting Rule-5 gaps in one pass, measurable via the eval scorecard's argument-fill accuracy.
- **2026-07-20** — [hermes-profile-distribution](../superpowers/specs/2026-07-20-hermes-profile-distribution-design.md): Design (Phase B) packaging the live-validated f0sectools Hermes profile as a git-installable distribution.
- **2026-07-20** — [hermes-runtime-integration](../superpowers/specs/2026-07-20-hermes-runtime-integration-design.md): Design to live-validate f0_sectools under Hermes Agent (Phase A) then ship a profile distribution without disturbing existing installs.
- **2026-07-21** — [opencode-runtime](../superpowers/specs/2026-07-21-opencode-runtime-design.md): Design adding opencode (≥1.18, native MCP and SKILL.md) as a runtime with in-repo wiring.
- **2026-07-21** — [purview-mcp](../superpowers/specs/2026-07-21-purview-mcp-design.md): Design for server #8 — read-only Microsoft Purview data-risk server (DLP, insider risk, audit posture, classification).

## Reading paths

- **"Why is gating built this way?"** → [isolate-host](../superpowers/specs/2026-07-10-defender-gated-isolate-host-design.md) → [watcher approvals](../superpowers/specs/2026-07-18-gating-approvals-design.md) → [chat-confirm](../superpowers/specs/2026-07-19-gating-chat-confirm-design.md) — the full evolution of the write gate, friction-driven at each step.
- **"How do you prove small models can drive this?"** → [eval scorecard](../superpowers/specs/2026-07-11-eval-scorecard-and-multiserver-design.md) → [description disambiguation](../superpowers/specs/2026-07-11-tool-description-disambiguation-design.md) → [agentic skill eval](../superpowers/specs/2026-07-12-agentic-skill-eval-design.md) → [safety hardening](../superpowers/specs/2026-07-19-small-model-safety-hardening-design.md) — measurement finding design defects, and the fixes.
- **"What does adding a platform look like, end to end?"** → [tenable plan](../superpowers/plans/2026-07-13-tenable-mcp-server.md) + [spec](../superpowers/specs/2026-07-13-tenable-mcp-server-design.md) — the cleanest single-server example of the recipe.
