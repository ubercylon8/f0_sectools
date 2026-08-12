# sentinel-mcp — Microsoft Sentinel / Log Analytics Server Design

**Date:** 2026-08-11 · **Status:** approved-pending-review · **Server #9**

Read-only MCP server over **Microsoft Sentinel** — both of its API surfaces:
the **Log Analytics query API** (KQL over ingested telemetry) and the
**Sentinel management API** (incidents, analytics rules, watchlists). Follows
the CLAUDE.md add-a-platform recipe; the ninth thin server over the shared
`core/`.

## Positioning: complement, not supersede

f0_sectools already has four Microsoft servers (`defender`, `entra`, `intune`,
`purview`). The tempting pitch for a Sentinel server is "one server to query
any Microsoft data, superseding the rest." **That pitch is wrong, and the
validation tenant proves it.**

Log Analytics contains only what a connector *ships into it*. Resource state —
Intune compliance, Secure Score, sensitivity-label inventory, device
configuration posture — is Graph-only and appears in no table at any price.
Worse, on the validation tenant the Defender XDR **device tables are not
streaming at all** (`DeviceProcessEvents`, `DeviceNetworkEvents`,
`DeviceLogonEvents`, `DeviceFileEvents`, `DeviceInfo`, `EmailEvents`,
`IdentityLogonEvents`, `CloudAppEvents` — all empty over 7d). A
"Sentinel replaces Defender" topology would have silently lost every device
hunt.

So `f0-sentinel` owns what **only** it can reach:

1. **Non-Microsoft infrastructure telemetry** — firewalls, DNS/web security,
   syslog. f0_sectools has no eyes on any of this today. This is the largest
   coverage gap the repo has.
2. **The Sentinel-native object model** — the SOC incident queue with MITRE
   tactics, and the analytics-rule inventory (i.e. *what do we actually
   detect?*), which nothing in the repo answers.
3. **Fast O365 activity search** — the same data as
   `f0-purview.search_audit_log`, minus that tool's 5–15 minute async round
   trip.

## Discovery: what the validation tenant actually contains

Design decisions below are grounded in a read-only recon of a live Sentinel
workspace (2026-08-11), not in the connector catalog. The catalog lists ~400
tables; the tenant had **26 tables with data**. Tenant identifiers are
deliberately omitted.

| Surface | Rows / 7d | Covered elsewhere in f0_sectools? | Decision |
|---|---:|---|---|
| `CommonSecurityLog` — Check Point VPN-1/FireWall-1 (+ Identity Awareness, SmartDefense, Anti-Malware, URL Filtering), some Fortinet FortiGate | ~112M | ❌ nothing | **Build** |
| `Cisco_Umbrella_firewall_CL` / `_dns_CL` / `_proxy_CL` / `_ravpnlogs_CL` | ~17M | ❌ nothing | **Build** |
| `OfficeActivity` (SharePoint, OneDrive, Exchange, Teams) | ~5.6M | ⚠️ `f0-purview.search_audit_log`, 5–15 min async | **Build** |
| `OracleDB_*_CL` (4 custom business-app tables) | ~2.7M | ❌ nothing | Defer — bespoke per tenant |
| `Syslog` | ~743K | ❌ nothing | Defer — 99.7% one facility/severity |
| `SigninLogs` | ~306K | ✅ `f0-entra` | Skip — see non-goals |
| `BehaviorAnalytics`, `UserPeerAnalytics` (UEBA) | ~462K | ❌ nothing | **Skip — see non-goals** |
| `ThreatIntelIndicators` | ~80K | ❌ nothing | Defer |
| `SecurityIncident` | ~290 | ✅ `f0-defender.list_incidents` | **Build** as SOC queue |
| `SecurityAlert` | ~514 | ✅ `f0-defender` + `f0-purview` | Skip |
| `AADRiskyUsers`, `Anomalies` | <20 | ✅ `f0-entra` | Skip |

Management API: 5 analytics rules (4 Scheduled + 1 Fusion, all enabled),
2 watchlists, 2 automation rules, 0 bookmarks, TI indicators present.

**Retention is 30 days** on the validation tenant, confirmed both by the
workspace resource (`retentionInDays`) and by an empty `ago(90d)` probe.

### Findings that changed the design

These are the reason recon preceded design, and each one killed a tool that
looked obviously correct on paper:

1. **UEBA ingests ~462K rows and scores nothing.** Every `BehaviorAnalytics`
   row carries `InvestigationPriority = 0`; the `Anomalies` table held 3 rows.
   A "UEBA anomalies" tool would return an empty list forever. *Verify the
   shape, not the row count.*
2. **The `dataConnectors` management API under-reports by 6×.** It listed a
   single connector (`Office365`) while at least six sources were actively
   ingesting — AMA/DCR and codeless connectors never register there. **The
   capability probe must be built on the `Usage` table, not on
   `dataConnectors`.** A `list_connectors` tool would systematically lie about
   coverage.
3. **`Classification` is unused.** Closed incidents were 100%
   `Undetermined`; new incidents blank. A classification-breakdown tool would
   report one meaningless bucket.
4. **The firewall carries no URLs, users, or hostnames.** Over ~824K rows in
   one hour: `SourceIP` 99.8%, `DestinationIP` 98.7%, `DestinationPort` 96.6%
   — but `RequestURL` **0.08%**, `SourceUserName` 0.28%,
   `DestinationHostName` 0.57%. Firewall hunting is **IP/port only**; domain
   hunting belongs to the Umbrella tools. Designing from the CEF schema rather
   than the data would have shipped a tool that always returns nothing.
5. **Connector hygiene defect (tenant-side, but the server must tolerate
   it).** The Umbrella connectors ingest their CSV header rows as data:
   `Action_s == "Action"`, `Verdict_s == "Action"`,
   `AMP_Disposition_s == "AMP Disposition"`. Every query and aggregate must
   filter these out or a phantom bucket appears in every answer.

## Explicit non-goals

Documented so nobody hunts for them or "helpfully" adds them later:

- **No device-telemetry hunt tool.** Defender device tables are not streaming;
  `f0-defender.hunt` / `run_hunting_query` own that surface. Adding a
  duplicate would recreate the `hunt`-vs-`list_alerts` misroute already
  documented in the eval findings.
- **No UEBA tool** — ingested but unscored (finding 1).
- **No incident-classification tool** — field unused (finding 3).
- **No `list_connectors` tool** — the API under-reports (finding 2);
  `list_data_sources` replaces it using `Usage`.
- **No sign-in tool.** `SigninLogs` is real and rich, but `f0-entra` owns
  identity and a second sign-in surface is pure routing collision for no new
  capability.
- **No writes in v1.** Incident close/classify/assign is a plausible future
  gated write through `core/gating/`, but the recipe is read-tools-first and
  the tenant does not currently use classification at all.

## Architecture

`servers/sentinel-mcp/`, the standard thin-server pattern. **No `core/`
changes** — `GraphClient` already accepts `base_url` and `scope` in its
constructor and exposes `.post(path, json_body)`
(`core/f0_sectools_core/auth/graph.py`), so it drives both Azure endpoints
with plain client-credentials. This is the fourth auth model added without
touching core.

One `SentinelClient` composing two `GraphClient` instances, because the halves
differ in host, token audience, and RBAC:

| Half | `base_url` | `scope` | Azure role |
|---|---|---|---|
| Logs (KQL) | `https://api.loganalytics.azure.com/v1` | `https://api.loganalytics.io/.default` | Log Analytics Reader |
| Objects (ARM) | `https://management.azure.com` | `https://management.azure.com/.default` | Microsoft Sentinel Reader |

Query: `POST /workspaces/{workspace_id}/query` with `{query, timespan}`.
ARM: `GET /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{name}/providers/Microsoft.SecurityInsights/{resource}?api-version=2024-09-01`.

> `hunts` rejects `api-version=2024-09-01` in some regions and needs an older
> version. Not used in v1; noted so it is not rediscovered.

### Config

`SentinelConfig` in `core/auth/config.py` + a test in
`core/tests/test_config.py`, following the existing dataclass/`from_env`
convention. Loaded from `.env.sentinel`:

| Var | Required | Purpose |
|---|---|---|
| `SENTINEL_TENANT_ID` / `_CLIENT_ID` / `_CLIENT_SECRET` | yes | client-credentials |
| `SENTINEL_WORKSPACE_ID` | yes | workspace GUID, KQL half |
| `SENTINEL_SUBSCRIPTION_ID` / `_RESOURCE_GROUP` / `_WORKSPACE_NAME` | no | ARM half |
| `SENTINEL_RETENTION_DAYS` | no (default `30`) | upper bound for every `hours` argument |

The ARM three are **optional by design**: when absent,
`get_detection_coverage` returns a `posture` finding explaining which config
is missing rather than failing, and every other tool works normally. Per
Critical Rule 7 this is its own `.env` even if the operator reuses an existing
app registration — credential isolation is a property of the loader, not of
the tenant.

**Single-workspace by design.** The validation tenant had exactly one
workspace in one subscription. `workspace` is therefore **config-only and
never a tool argument** — a workspace/subscription parameter is precisely the
opaque-identifier argument small models fill wrong. Multi-workspace or
Lighthouse support is a future spec, not a v1 parameter.

## Tools (7)

All arguments are flat scalars with short closed enums. Every enum value below
was verified against live data.

```
list_data_sources()
hunt_firewall(action, indicator, hours, limit)
hunt_dns_web(surface, action, indicator, hours, limit)
search_office_activity(workload, operation, user, hours, limit)
list_sentinel_incidents(severity_min, status, hours, limit)
get_detection_coverage()
run_kql(kql)
```

Shared enums:

- `action`: `allowed | blocked | detected | any`
- `surface`: `dns | web | vpn`
- `workload`: `sharepoint | onedrive | exchange | teams | any`
- `severity_min`: `informational | low | medium | high`
- `status`: `new | active | closed | any`

### 1. `list_data_sources()`

What telemetry this workspace actually has, from `Usage` over 30d: table name,
rounded volume, and a one-word family (`firewall`, `dns_web`, `office`,
`identity`, `incident`, `custom`). Also the public face of the capability
probe. Answers "can you even see our firewall?" — which, because every
deployment differs, is the question that makes this server self-describing
instead of tenant-hardcoded.

### 2. `hunt_firewall(action, indicator, hours, limit)`

`CommonSecurityLog`. `indicator` is an **IP address or port** — never a
domain or username (finding 4); the docstring says so explicitly and names
`hunt_dns_web` as the destination for domains.

### 3. `hunt_dns_web(surface, action, indicator, hours, limit)`

Cisco Umbrella. `surface` selects the table: `dns` → `Cisco_Umbrella_dns_CL`
(`Domain_s`, `Categories_s`), `web` → `Cisco_Umbrella_proxy_CL` (`URL_s`,
`Verdict_s`, file/AMP fields), `vpn` → `Cisco_Umbrella_ravpnlogs_CL` (remote
access sessions). `indicator` matches domain / URL / IP as appropriate to the
surface.

`Categories_s` is a **JSON array serialized into a string**, so category
matching uses `has`, never `==`.

### 4. `search_office_activity(workload, operation, user, hours, limit)`

`OfficeActivity`. `operation` is an exact O365 operation name
(`FileDownloaded`, `MailItemsAccessed`, `FileAccessed`, `ListItemViewed`…);
when unset, the tool returns **a breakdown of the top operations for the
window instead of event rows**, so the model discovers valid operation names
in one call rather than guessing them — the same self-describing intent
`f0-purview.search_audit_log` expresses in its docstring, but resolved in one
round trip instead of two.

### 5. `list_sentinel_incidents(severity_min, status, hours, limit)`

`SecurityIncident`, surfacing what the Defender view does not: **MITRE
tactics**, SOC status, and owner. Not an alert list —
`f0-defender.list_alerts` owns alerts.

### 6. `get_detection_coverage()`

ARM `alertRules`: rule count, enabled/disabled split, kind breakdown
(`Scheduled`, `Fusion`, `NRT`, `MicrosoftSecurityIncidentCreation`), and
**MITRE tactic coverage with the uncovered tactics named**. On the validation
tenant this reports 5 rules against ~391 incidents/30d sourced entirely from
Microsoft XDR — i.e. *this Sentinel is a log lake plus an XDR mirror, not a
detection engine*. That gap is invisible from the incident queue and is the
detection-engineer persona's highest-value answer.

### 7. `run_kql(kql)`

Escape hatch for what the guided tools do not cover. Validated for read-only
shape and force-bounded (below). The docstring routes explicitly: this is
**Sentinel workspace KQL**, not Defender advanced hunting — for device
telemetry use `f0-defender.run_hunting_query`.

## The normalization layer

The server's real product is collapsing three vendors' inconsistent fields
into one vocabulary the model can hit reliably. Raw `DeviceAction` has 15+
mixed-case, mixed-semantic values (`Accept`, `blocked`, `Drop`, `Detect`,
`detected`, `Bypass`, `Failed Log In`, `crash`, `RADIUS-auth-failure`,
`negotiate`, `DHCP-no-response`, …) — exposing it is exactly the "40-value
enum the model picks wrong from" that CLAUDE.md forbids.

| Semantic | Check Point `DeviceAction` | Umbrella DNS `Action_s` | Proxy `Verdict_s` | FW `verdict_s` |
|---|---|---|---|---|
| `allowed` | `Accept`, `Bypass` | `Allowed` | `ALLOWED` | `ALLOW` |
| `blocked` | `Drop`, `blocked`, `Reject` | `Blocked` | `BLOCKED` | `BLOCK` |
| `detected` | `Detect`, `detected` | — | — | — |
| `any` | no filter | no filter | no filter | no filter |

Note the same concept carries three field *names* and three *casings* across
the Umbrella tables. Mapping lives in one module (`normalize.py`) with a
contract test per vendor, so a new vendor is a table addition, not a tool
rewrite.

**Header-row hygiene filter** (finding 5) is applied unconditionally to every
query and aggregate.

## Capability probe and portability

Each telemetry tool resolves its table at call time against a
process-cached probe of `Usage` (30d, cached for the process lifetime — reads
are idempotent and the set of ingesting tables does not change intra-session).

If the table is absent, the tool returns a `posture` finding — *"no CEF
firewall data in this workspace"* — **not** an exception and not an empty
list, because an empty list reads as "no matching traffic" and is a materially
different answer from "this workspace has no firewall feed."

This is what lets one server run unmodified on a Palo Alto or Zscaler tenant.
It is built on `Usage` rather than `dataConnectors` for the reason in
finding 2.

## Bounding, cost, and context safety

At ~112M rows/7d in one table, bounding is a correctness and billing concern,
not a nicety:

- `hours` clamped to `SENTINEL_RETENTION_DAYS × 24` (**720** with the default
  30-day retention). Beyond retention is silently empty, so the clamp prevents
  a confidently wrong "no activity found." The clamp is config-driven, not
  hardcoded, because retention is a per-deployment property.
- The `TimeGenerated` predicate is **emitted first in every generated query**,
  always.
- **No indicator → aggregate-only.** `hunt_firewall()` and `hunt_dns_web()`
  without an `indicator` return a summary (counts by action, top talkers /
  top domains) and never raw rows. Only an indicator unlocks sampled rows.
  This mirrors `f0-defender.hunt`, where `indicator` is required for
  network/process.
- `limit` through `core.paging.clamp_limit`; `truncation_finding` when capped.
- `run_kql` is validated read-only (rejects `.set`/`.create`/`.drop`/ingest
  control commands) and force-bounded with an appended `take` when the query
  carries no bound of its own.
- Per-request server timeout so a runaway scan fails as a finding rather than
  hanging the agent.

## Overlap routing (two-way)

Names are chosen not to collide: `list_sentinel_incidents` (not
`list_incidents`), `run_kql` (not `run_hunting_query`).

| New tool | Points at | Reciprocal edit |
|---|---|---|
| `search_office_activity` | — | `f0-purview.search_audit_log`: "for O365 file/mail activity when a Sentinel workspace is configured, prefer `search_office_activity` — it answers in under a second vs. this tool's 5–15 minute async query" |
| `list_sentinel_incidents` | `f0-defender.list_incidents` for the XDR-native view | `f0-defender.list_incidents` gains a pointer to the SOC-queue/tactics view |
| `run_kql` | `f0-defender.run_hunting_query` for device telemetry | reciprocal "that is Defender advanced hunting, not Sentinel workspace KQL" |

Both reciprocal edits touch **live-validated servers**, so they require
`uv run python scripts/gen_docs.py` plus the `integrations/` drift-guard
update, and eval tasks proving the routing holds on **two** models — one model
is not a control (`f0sectools-eval-findings`).

## Errors

`errors.py` → `map_sentinel_error(...)`, every failure a finding, never an
exception:

| Condition | Finding |
|---|---|
| token failure / 401 | `posture` — auth not configured |
| 403 | `Finding.permission_missing` — names the missing Azure role (Log Analytics Reader vs Microsoft Sentinel Reader), since the two halves fail independently |
| 429 | `Finding.rate_limited` |
| 502/503/504 | `Finding.api_unavailable` |
| KQL `BadArgumentError` / `SemanticError` | `posture` — query rejected, with the sanitized reason (recon hit two of these; the model needs the reason to self-correct) |
| query timeout | `posture` — narrow the window or add an indicator |

Redaction at the boundary (`redact_obj(f.model_dump())`), error paths
included.

## Testing

**Layer A (mandatory, offline):** contract tests against a fake client —
finding shape per tool; normalization mapping per vendor; header-row filter;
capability probe returning `posture` on a missing table; the config-driven
`hours` clamp (default 720);
aggregate-only when `indicator` is empty; `run_kql` rejecting control
commands; redaction on success *and* error paths; ARM-config-absent
degradation. TDD each, contract test before implementation.

**Layer B (local, not CI):** `evals/sentinel/tasks.yaml`, ≥1 task per tool,
plus **dedicated routing tasks** for the three collisions in the overlap table
(firewall-vs-DNS indicator routing, Sentinel-vs-Defender incidents,
`run_kql`-vs-`run_hunting_query`). Register in `evals/test_eval_coverage.py`
and `evals/run.py`. Routing tasks run on two models.

**Step 9 live-test:** `scripts/live_smoke_sentinel.py`. The recon scripts from
the design phase seed it. Expect 1–3 field-name mismatches; the recon already
absorbed several that would otherwise land here.

## Skills

Three `SKILL.md` under `skills/sentinel/`, agentskills.io format, tools by
base name:

1. **`data-source-coverage`** — what telemetry exists, what's missing, what's
   ingesting but unusable. Default focus for this server.
2. **`network-investigation`** — firewall + DNS/web hunting for an indicator;
   the offensive↔defensive complement to the endpoint-side LimaCharlie skill.
3. **`detection-coverage`** — analytics-rule inventory and MITRE gaps, for the
   detection-engineer persona.

## Delivery

CONTRIBUTING recipe steps 1–12 in order, TDD each code step. Step 9 needs
network access and explicit user confirmation. Step 11 updates the Platform
Integrations table and Architecture tree in CLAUDE.md, the README status, the
user-guide support matrix, and the `integrations/` templates (Hermes, pi,
opencode `opencode.json` + `.opencode/skills` symlinks). Step 12 verifies
`pytest` / `ruff` / `mypy`, confirms no real `.env` is staged, commits
conventionally — **and does not push**.

## Risks

| Risk | Mitigation |
|---|---|
| Tool count 51 → 58 degrades selection accuracy repo-wide | Distinct names + two-way routing + dedicated eval routing tasks on two models; scorecard re-run before merge, as with the Tenable addition |
| Tools are shaped by one tenant's vendors (Check Point, Umbrella) | Capability probe degrades to `posture` on absent tables; `normalize.py` is table-driven so a new vendor is data, not code |
| A single unbounded query is genuinely expensive at ~250 GB/30d ingest | Time-predicate-first, aggregate-only without indicator, retention clamp, forced `take`, server timeout |
| Reciprocal docstring edits regress live-validated servers | Description-only changes, no behaviour change; drift guard + full eval re-run |
| Retention/vendors differ per deployment | Retention read from config, not hardcoded; `list_data_sources` makes the surface discoverable at runtime |
