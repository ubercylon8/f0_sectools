# Changelog

All notable changes to f0_sectools are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Hermes profile distribution** (`integrations/hermes/distribution/`) — a
  git-installable Hermes Agent profile: `hermes profile install
  ./integrations/hermes/distribution` stands up the f0_sectools security agent
  (7 MCP servers + 22 skills + 4 personas + SOUL) from a checkout, with servers
  and skills resolved at runtime from `${F0_SECTOOLS_DIR}` and secrets kept in
  the per-platform `.env` files. Live-validated end to end (fresh install →
  7 servers, 22 skills, a human-approved fleet-by-tag gated write).

- **LimaCharlie tag view & user-focused queries** — `list_sensors` gains a
  `tag` filter ("which hosts carry lc:sleeper / prueba"), and `query_telemetry`
  gains a fifth `user_activity` hunt preset (USER_OBSERVED, with the host each
  user was seen on) plus a `username` filter for process/PowerShell activity by
  the acting user — boundary-anchored (`DOMAIN\user`-aware), so lookalike names
  never match. Still 6 tools.
- **LimaCharlie sleeper visibility** — sensor tags are now surfaced:
  `get_sensor` lists them (flagging dormant `lc:sleeper` sensors, which collect
  no telemetry by design), a zero-event `query_telemetry` result diagnoses the
  host's state (dormant / offline / online-but-quiet) instead of returning a
  bare count, and `get_org_overview` reports a dormant-sleeper census (on the
  validation fleet: 1,173 of 1,247 sensors).

### Fixed

- **LimaCharlie hostname scoping selected zero sensors** — `query_telemetry`
  exact-matched the caller's hostname while sensors register FQDNs, so a short
  name ("sbl8042") silently returned 0 events on a host with ~1,000 real events
  in the window. Hostnames are now resolved (prefix lookup, accepted at a dot
  boundary) to the stored hostname before scoping; an unmatched or ambiguous
  name returns an explicit finding instead of a silent empty result.
- **ProjectAchilles fleet-by-tag routing** — sharpened `run_test`/`schedule_test`
  tool descriptions so a small model runs a whole tag by passing `tag=…` instead
  of trying to enumerate the hosts first (surfaced by the Hermes live run).
- **Entra `list_privileged_role_assignments` output bounding** — returns one
  bounded page (default 25) plus a "more available" note instead of ~100 findings
  that overflowed a small model's runtime output cap; critical roles still first.

### Security

- The distribution ships the gated-write `f0-pa-actions` server
  **`enabled: false`** (explicit opt-in), and both it and `config.example.yaml`
  document that under Hermes v0.18.2 the model retains shell access — so the
  gated-write confirmation is **not forge-resistant**; keep
  `PROJECTACHILLES_ALLOW_WRITE=false` unless that risk is accepted.

## [0.2.0] — 2026-07-20

Adds the **ProjectAchilles actions server** (the platform's first full gated-write
integration beyond Defender), a low-friction gated-write confirmation layer,
**fleet-wide** validation runs, and a **small-model-safety** hardening pass —
growing the platform to **45 registered tools across seven live-validated servers**.

### Added

- **`projectachilles-actions-mcp` — seventh server (gated writes).** Runs the
  write side of the validation loop: gated `run_test`, `schedule_test`,
  `set_schedule_status`, `cancel_tasks`, plus reads `list_schedules`,
  `get_task_status`, `list_tasks`. Second consumer of `core/gating` after Defender.
- **Fleet-wide validation runs by tag.** `run_test`/`schedule_test` target a single
  host **or a whole tag/fleet** (every agent carrying the tag, fanned out in one
  gated action); the confirmation is bound to the matched host **count** (a >200-host
  tag is refused, and a changed count auto-refuses a stale confirmation).
- **Fleet status & cancel.** `list_tasks` sweeps a run's per-host task states in one
  call; `cancel_tasks` cancels one task or bulk-cancels by `status`/`search`
  (count-bound); `list_test_executions` gained `test`/`tag`/`hostname` scoping so
  results scope to one run instead of a tenant-wide time window.
- **ProjectAchilles test catalog.** `find_tests` (search by technique/actor/tactic/
  category/tag/keyword) and `get_test` (full detail for one test).
- **Bundle-aware results.** `get_task_status` and `list_test_executions` roll a
  multi-control bundle run up into one COMPLIANT / NON-COMPLIANT finding per host.
- **Low-friction gated-write confirmation.** An approval **watcher**
  (`confirm_action.py --watch` — one keypress, no token through model context) and
  an opt-in **chat-confirm** mode, alongside the existing single-use token.
- **Tenable `list_vulnerability_assets`** — the hosts affected by a given
  plugin/vulnerability (plugin→hosts).
- **Defender `hunt`** — guided advanced-hunting tool (category + indicator →
  server-built KQL) so small models stop guessing field names; `run_hunting_query`
  remains for custom KQL.
- **Claude Code GitHub App** — automated per-PR security review + `@claude` responder.

### Changed

- **Small-model-safe schemas.** Closed-enum params (`severity_min`, `hunt` category,
  `find_tests` `by`, `list_managed_devices` compliance, …) now advertise a `Literal`
  enum in the MCP schema so a small model picks from it; read-tool `limit`s are
  clamped to ≤100 across all servers; read-search inputs are length/control-char
  bounded. Measured on the eval scorecard (e.g. `find_tests` argument-fill 0% → 100%
  on Qwen3.5-9B).
- **Sharper tool-routing descriptions** for the ProjectAchilles catalog-vs-results
  tools (took the projectachilles eval 92% → 100% on Qwen3.5-9B).
- **Shared input validators** (scope/search predicates) hoisted into
  `core/smallmodel` so validation lives in `core` once (Critical Rule 6).
- **Bounded output** — Defender `list_incidents`/`list_alerts` and Entra
  `list_risky_users`/`list_risk_detections` return a single bounded page with a
  "more available" note instead of paginating the whole tenant.

### Fixed

- **ProjectAchilles cyber-hygiene mislabeling** — read the enriched executions
  endpoint so control checks render "passed / not passed", not "NOT blocked".
- **LimaCharlie** — `get_sensor` shape, telemetry sub-hour windows + nested
  projections, result-stream metadata junk inflating counts, and boundary-anchored
  (not substring) domain matching.
- **ProjectAchilles `org_id`** on the actions server; **pi** runtime lifecycle +
  tool-name prefixes; assorted tool-output clarity fixes.

### Security

- Every gated write (Defender host isolate/release; the ProjectAchilles actions
  server) routes through `core/gating` — config flag **and** per-action human
  confirmation **and** a local audit trail. Fleet and bulk actions are count-bound
  so a changed target auto-refuses a stale confirmation, and a mid-batch failure is
  still audited.

## [0.1.0] — 2026-07-14

Initial public release.

### Added

- **Shared `core/`** — findings schema, redaction (applied to all output incl.
  error paths), per-platform `.env` auth, pagination, gated-write machinery +
  audit trail, and persona renderers.
- **Six live-validated MCP servers** — 34 registered tools (32 read + Defender's
  2 gated writes): `defender`, `entra`, `limacharlie`, `projectachilles`,
  `intune`, `tenable`.
- **20 portable [agentskills.io](https://agentskills.io) skills** across the six
  platforms plus cross-platform correlation playbooks.
- **Four role personas** (CISO, threat hunter, detection engineer, security
  engineer) and a **Hermes** integration.
- **Small-model tool-calling eval harness + scorecard** — measures tool-selection
  and argument-filling accuracy per server and across the combined 34-tool
  registry.
- **CI** — tests, ruff, mypy (strict, scoped to shipped source), secret scan
  (gitleaks), and Semgrep as hard gates.
- User guide, runtime-performance guide, and architecture doc.

### Security

- Read-only by default; state-changing actions gated behind a config flag **and**
  a single-use human confirmation token, and audited.
- Credentials never logged, never returned to the model, never leave the host.

[Unreleased]: https://github.com/ubercylon8/f0_sectools/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ubercylon8/f0_sectools/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ubercylon8/f0_sectools/releases/tag/v0.1.0
