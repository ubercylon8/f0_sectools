# Changelog

All notable changes to f0_sectools are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`sentinel-mcp` — ninth server** (Microsoft Sentinel, SIEM pillar).
  Read-only: KQL telemetry over the Log Analytics workspace (guided
  `hunt_firewall` and `hunt_dns_web` plus a custom `run_kql` escape hatch),
  fast M365 audit search (`search_office_activity`, seconds instead of
  Purview's 5-15 minute asynchronous search), the Sentinel SOC incident queue
  (`list_sentinel_incidents`, with MITRE tactics, status and owner), analytics-
  rule detection coverage (`get_detection_coverage`), and `list_data_sources`
  to discover what a given workspace actually ingests before hunting it.
  Two-way routing docstrings point operators at the right server: Sentinel vs.
  Defender for incidents and for KQL (different table universes), Sentinel vs.
  Purview for M365 audit.

### Fixed

- **`run_kql`'s control-command guard now rejects a dot-command on any line**,
  not just the first — a Kusto control command (`.drop`, `.create`, …) smuggled
  onto a second line previously reached the client unrejected.
- **Every server's `_render` now redacts through `redact_finding`**, not the
  weaker `redact_obj`. `redact_obj` only ever sees the literal `key`/`value`
  keys of a flat evidence entry; `redact_finding`'s extra evidence-key pass
  blanks a value sitting under a secret-hinting key name (e.g.
  `client_secret`), which previously only the generated-report path did.

## [0.2.1] — 2026-07-25

Twenty-seven merged PRs since 0.2.0. Two themes: **persona posture reports** as a
shareable deliverable, and a **read-tool audit** that found several tools were
presenting already-handled records as current.

**Read the Changed section before upgrading** — several tools now return
materially different results by default. That is the point of the release, but it
will change what your agents report.

### Added

- **Persona posture reports** — `scripts/gen_report.py` + the
  `generate-report` skill turn gathered findings into a shareable deliverable:
  **Markdown and a standalone, self-contained HTML page always**, plus an optional
  **PDF** (`--pdf`, needs the `[reports]` extra), in **English or Spanish**.
  Four personas, each with its own title and its own gathered data — Executive
  Risk Briefing (CISO), Detection Coverage Report, Threat Hunting Report,
  Security Hardening Report. Every report opens with a "Posture at a glance"
  tile grid, ends with **open questions for the operator**, and states coverage
  explicitly: a dark platform degrades to "not assessed" and the report still
  generates.

  The narrative (executive summary, risk framing, open questions) is authored by
  the agent; **every number is re-gathered by the engine itself**, fresh and
  redacted, so no figure is ever transcribed by a model. The deterministic
  engine lives in `core/f0_sectools_core/reports/` and is platform-free and
  model-free; all platform wiring is in `scripts/report_gather.py`.
- **`purview-mcp` — eighth server** (Microsoft Purview, data-risk pillar).
  Read-only: DLP alert rollup + list, insider-risk alerts (both via the GA
  `security/alerts_v2` Graph endpoint), sensitivity-label inventory (Graph
  beta), and a guided **async two-phase** unified-audit search
  (`search_audit_log` polls briefly, hands back an `audit_query_id` for
  `get_audit_results` when the tenant's query runs long). Explicit non-goal:
  the Compliance Manager score (no public API).
- **opencode runtime** — [opencode](https://opencode.ai) (≥1.18) is wired as an
  in-repo project config: run `opencode` from the checkout and the MCP servers,
  all skills (via opencode's **native** SKILL.md loader — committed symlinks, no
  forks), and the four role personas auto-load. The gated-write server ships
  `enabled: false`.
- **Hermes profile distribution** (`integrations/hermes/distribution/`) — a
  git-installable Hermes Agent profile: `hermes profile install
  ./integrations/hermes/distribution` stands up the security agent from a
  checkout, with servers and skills resolved at runtime from
  `${F0_SECTOOLS_DIR}` and secrets kept in the per-platform `.env` files.
- **CISO risk-rollup skill** (`skills/cross-platform/ciso-risk-rollup`) — one
  executive playbook pulling a headline posture number from each of the six
  platforms, ranking top risks by actual severity, and reporting a partial
  rollup gracefully when a platform is dark.
- **LimaCharlie tag view & user-focused queries** — `list_sensors` gains a `tag`
  filter, and `query_telemetry` gains a `user_activity` hunt preset plus a
  `username` filter, boundary-anchored (`DOMAIN\user`-aware) so lookalike names
  never match.
- **LimaCharlie sleeper visibility** — sensor tags are surfaced: `get_sensor`
  lists them (flagging dormant `lc:sleeper` sensors, which collect no telemetry
  by design), a zero-event `query_telemetry` result diagnoses the host's state
  (dormant / offline / online-but-quiet), and `get_org_overview` reports a
  dormant-sleeper census.
- **Truncation disclosure** — `core/paging.truncation_finding`, now used across
  Intune, Tenable, LimaCharlie, ProjectAchilles and Purview so a bounded page
  says how much it withheld instead of reading as the whole set.
- **Documentation overhaul** — new `docs/explanation/` layer
  ([architecture](docs/explanation/architecture.md),
  [security model](docs/explanation/security-model.md),
  [findings schema](docs/explanation/findings-schema.md),
  [small-model design](docs/explanation/small-model-design.md), design-history
  index), a **generated reference with a CI drift guard**
  (`scripts/gen_docs.py` harvests the live FastMCP registries; a test fails CI
  when the output is stale), per-server sample findings validated in CI,
  annotated transcripts including the full gated-write lifecycle, a
  [gated-actions how-to](docs/user-guide/gated-actions.md),
  [FAQ](docs/user-guide/faq.md), [glossary](docs/reference/glossary.md) and a
  [docs hub](docs/README.md). The add-a-platform recipe moved to
  [CONTRIBUTING.md](CONTRIBUTING.md).

### Changed

These change what tools return by default. Each keeps the previous behaviour
available behind an explicit argument.

- **Defender `list_incidents` / `list_alerts` return only unresolved items**,
  newest first, filtered server-side. Previously an arbitrary page was fetched
  and then filtered in Python, so a severity floor could not reach rows the page
  bound had already excluded. Pass `state="all"` for history.
- **Entra `list_risky_users` / `list_risk_detections` return only users and
  detections still at risk**, newest first. Entra retains dismissed and
  remediated entries indefinitely. Pass `state="all"` for risk history.
- **Purview `get_dlp_summary` / `list_dlp_alerts` /
  `list_insider_risk_alerts` return only unresolved alerts.** The DLP headline
  counts open alerts rather than every alert in the window. Pass `state="all"`
  to include resolved ones.
- **Defender `severity_min` now behaves as documented.** `info` and `critical`
  were absent from the lookup table and both silently resolved to `medium`, so
  `critical` returned medium and high items and `info` dropped the low and info
  ones it asked for. Enum arguments also fold case, and an unrecognized value is
  reported rather than reinterpreted.
- **LimaCharlie `get_org_overview` scores fleet dormancy** instead of always
  reporting `info`, and its headline reports the share of the fleet with
  telemetry enabled rather than the online count, which overstates coverage when
  most sensors are dormant. Scored on dormancy alone — offline is transient.
- **Report tiles: an `info` pillar renders `clear` (muted), not `strong`
  (green).** `low` means assessed and judged fine; `info` carries no risk
  judgment, and painting it green asserted good news the data never established.

### Fixed

- **Defender incidents never expanded their correlated alerts** —
  `/security/incidents` omits the `alerts` collection unless `$expand` is
  requested, so the count was always 0 and the "high severity + several
  correlated alerts → critical" escalation could never fire.
- **Silent truncation across twelve tools** (Intune, Tenable, LimaCharlie,
  ProjectAchilles, Purview) — a bounded page read as the complete set.
- **Tenable `list_scans` returned scans in arbitrary order** despite
  `last_modification_date` being available; now newest first, with undated scans
  sorted last rather than dropped.
- **LimaCharlie hostname scoping selected zero sensors** — `query_telemetry`
  exact-matched the caller's hostname while sensors register FQDNs, so a short
  name silently returned 0 events on a host with ~1,000 real events in the
  window. Hostnames now resolve at a dot boundary; an unmatched or ambiguous
  name returns an explicit finding instead of a silent empty result.
- **Purview audit-search resubmit storm** — identical searches within a TTL
  reuse the in-flight query, and `get_audit_results` block-polls like
  `search_audit_log` so a model stops hammering it every few seconds. Tenant
  audit queries genuinely take 5–15 minutes; the guidance now says so.
- **ProjectAchilles fleet-by-tag routing** — sharpened `run_test` /
  `schedule_test` descriptions so a small model runs a whole tag by passing
  `tag=…` instead of enumerating hosts first.
- **Entra `list_privileged_role_assignments` output bounding** — one bounded
  page plus a "more available" note instead of ~100 findings that overflowed a
  small model's runtime output cap; critical roles still first.
- **Report generation**: the parsed `## Risk Framing` narrative was never
  rendered; finding rows lost evidence and MITRE references; metric tiles
  rendered whole titles at headline size; operational personas received the
  CISO's pillar data in an operational layout; a group that ran clean and
  returned nothing reported as "Not assessed"; Spanish reports rendered tile and
  coverage chrome in English.
- **Doc drift**: README server/tool/skill counts, a broken user-guide platform
  table row, `servers/README.md` listing built servers as "planned", a missing
  Tenable tool, and a CLAUDE.md schema example that had drifted from the code.
  The report how-to never explained the required `--narrative` file, and the
  README described reports as "Markdown + PDF" after HTML became a first-class
  always-written output.

### Security

- **Reports pass through the redaction layer.** `core/redaction.redact_finding`
  adds evidence-**key**-aware blanking: `redact_obj` alone cannot see a secret
  sitting under a secret-hinting evidence key, because evidence is a flat
  `{key, value}` list. Applied at both the gather and emit boundaries, and the
  headline split now happens after redaction so a secret spanning the boundary
  cannot escape.
- **opencode gated-write path** — the project config pre-arms opencode's `"ask"`
  permission on the four ProjectAchilles write tools: when an operator opts in,
  every write call requires an interactive TUI approval the model cannot forge,
  layered on the core gate; non-interactive runs auto-reject writes. The server
  still ships `enabled: false`.
- **Hermes distribution** ships the gated-write `f0-pa-actions` server
  `enabled: false` (explicit opt-in), and documents that under Hermes v0.18.2
  the model retains shell access — so the gated-write confirmation is **not
  forge-resistant**; keep `PROJECTACHILLES_ALLOW_WRITE=false` unless that risk
  is accepted.
- **gitleaks allowlist scoping** — the allowlist is scoped to the
  `generic-api-key` rule so it cannot blind whole paths to every other rule.

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

[Unreleased]: https://github.com/ubercylon8/f0_sectools/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/ubercylon8/f0_sectools/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/ubercylon8/f0_sectools/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ubercylon8/f0_sectools/releases/tag/v0.1.0
