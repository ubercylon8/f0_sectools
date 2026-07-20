# Small-model-safety hardening — design

**Date:** 2026-07-19
**Servers:** defender, tenable, projectachilles, projectachilles-actions, intune, limacharlie (read tools)
**Motive:** Rule 5 (small-model-safe tools) is the repo's reason to exist. Three cross-cutting gaps — enum params advertised as free strings, read tools with unbounded `limit`, and asymmetric input validation — are tightened in one pass. Measurable on the eval scorecard (argument-fill accuracy).

## Scope

Three items (A + B + C), all additive, no behavioural regression:

- **A — Literal-enum promotion.** Closed-enum `str` params (enum lives only in the docstring today) become `Literal[...]` in the **server wrapper**, so FastMCP advertises a constrained `enum` the model picks from. The **tools-layer keeps its existing tolerant/graceful handling** (belt + suspenders): the Literal is a hint for the model + schema-enforcing clients; the code stays the floor for lenient clients. No path newly hard-fails.
- **B — `limit` ceiling sweep.** Apply the existing `core/paging.clamp_limit` (default preserved per-tool, **max 100**) to model-facing `limit` params in the servers that skip it.
- **C — read-search input bound.** Give read-side `search`/`value` params a bounded-length + no-control-char guard (returning the existing graceful `guidance` finding), so read and write inputs are both validated.

### Explicitly out of scope (verified open/passthrough — NOT promoted)

`find_tests`-style catalog reads showed three candidates that are **open passthrough filters, not closed enums** — promoting them would wrongly reject legitimate values:

- `projectachilles.list_agents(status)` — passed unvalidated straight to the agents API; closed set unconfirmed.
- `limacharlie.list_detections(category)` — user-defined D&R rule categories.
- `limacharlie.list_dr_rules(namespace)` — arbitrary namespace string.

These stay `str`. (This "verify closed vs open before promoting" check is the point — a Literal on an open filter is a regression.)

---

## Item A — Literal-enum promotion

Confirmed-closed params (each has an explicit closed set in code — a validation set, an ordering map, or a filter map). Promote the **server-wrapper** parameter type only; tools-layer signatures and bodies are unchanged.

| Server · tool | Param | `Literal[...]` values | Default | Belt+suspenders (tools-layer today) |
|---|---|---|---|---|
| defender · `list_incidents` | `severity_min` | `info,low,medium,high,critical` | `"medium"` | `_meets()`; unknown→info (kept) |
| defender · `list_alerts` | `severity_min` | `info,low,medium,high,critical` | `"high"` | same |
| defender · `hunt` | `category` | `network,process,logon,email` | (required) | maps to vetted KQL; unknown→graceful 400 finding (kept) |
| tenable · `list_top_vulnerabilities` | `severity_min` | `low,medium,high,critical` | `"high"` | severity map; unknown→info (kept) |
| tenable · `get_asset_vulnerabilities` | `severity_min` | `low,medium,high,critical` | `"high"` | same |
| projectachilles · `list_risk_acceptances` | `status` | `active,revoked` | `"active"` | passed to API; kept |
| projectachilles · `find_tests` | `by` | `technique,actor,tactic,category,tag,keyword` | (required) | `if by not in _FIND_BY: guidance` (kept — this is the graceful floor) |
| intune · `list_managed_devices` | `compliance` | `all,compliant,noncompliant,ingraceperiod,unknown` | `"all"` | `_COMPLIANCE_FILTER.get(...)`; unmatched→no filter=all (kept) |

**Sentinel / default rules:**
- Params with a "select-all" default keep it inside the Literal: `compliance` includes `all`; a param that means "any" via `""` keeps `""` in the Literal (as `list_tasks` already does).
- Required params (`hunt.category`, `find_tests.by`) have no default — the Literal has no `""`/`None` member.
- The tools-layer signature stays `str` (it receives whatever the wrapper passes). Only the **wrapper** annotation changes. This keeps the graceful fallback reachable when a lenient client bypasses schema validation.

**Why belt + suspenders:** a schema-enforcing client (and the model, seeing the enum) is steered to valid values — the win. A lenient client that ignores the schema still hits the tools-layer's existing tolerant handling, so nothing newly crashes or hard-rejects — consistent with Critical Rule 4 ("every failure → finding") and the "no regression" constraint.

---

## Item B — `limit` ceiling sweep

`core/paging.clamp_limit(limit, default=DEFAULT_LIMIT, maximum=MAX_LIMIT)` already exists (`DEFAULT_LIMIT=25`, `MAX_LIMIT=100`) and is used in defender/entra/tenable. Extend it to the **model-facing `limit`** of read tools in the four servers that skip it:

- **projectachilles:** `get_weak_techniques`, `list_test_executions`, `list_risk_acceptances`, `list_agents`, `find_tests`
- **projectachilles-actions:** `list_tasks`
- **limacharlie:** `list_dr_rules`, `list_detections`, `query_telemetry`
- **intune:** `list_managed_devices`

Pattern: `limit = clamp_limit(limit)` at the top of each tools-layer function (the bare call matches the existing defender/tenable pattern) — bounds oversized inputs to 100 and floors sub-1 values to 1. `limit` is typed `int`, so the framework coerces it before the tool runs and `clamp_limit`'s `default` branch is unreachable in practice; the bare call is therefore sufficient, and each tool's own signature default still applies when the arg is omitted. The existing "N more available" / bounded-output messaging is unchanged.

> Implementation note (2026-07-20): also swept limacharlie `list_sensors` for uniformity (a review-flagged omission from the original 12-site list; its output was already hard-capped at 50).

**Do NOT clamp internal, non-model-facing limits** — e.g. `cancel_tasks`'s hardcoded enumeration `limit=201` (that's the 200-cap machinery, not a model input). Only clamp parameters the model supplies.

---

## Item C — read-search input bound (symmetric validation)

Write-side bulk `cancel_tasks(search)` is charset-guarded; read searches are not. Add a **permissive** bound to the read searches so both sides validate, **without** the strict write-side charset (which would reject legitimate keyword/name searches):

- `projectachilles-actions.list_tasks(search)`
- `projectachilles.find_tests(value)`

Guard: reject only **oversized (> 128 chars)** or **control-character-containing** values → return the existing graceful `guidance` finding, pre-request. Legit searches (spaces, dots, `T1110`, `APT29`, `CVE-2020-1472`, multi-word keywords) pass unchanged. This is length/hygiene bounding, not an injection defense (httpx encodes params) — the goal is symmetry + protecting the context window from a giant search string, per Rule 5.

> Design note: reads stay **permissive** (length + control-char only) while gated writes stay **strict** (`_SCOPE_RE`) — deliberate asymmetry in *strictness*, but both now validate. Do not tighten the read guard to the write charset; it would reject valid searches.

---

## Item D — testing & measurement

### Contract tests (Layer A — mandatory, offline)

- **A (schema):** for each promoted param, assert the MCP input schema exposes the exact closed `enum` (mirror the existing `test_*_enum_closed` / `test_status_enums_closed` tests). Assert the three open-passthrough params (`list_agents.status`, `list_detections.category`, `list_dr_rules.namespace`) stay **free strings** (no `enum` key) — locks in the "don't promote open filters" decision.
- **A (graceful floor):** assert a tools-layer call with an out-of-enum value still degrades gracefully (unknown `severity_min`→ current behaviour; bad `find_tests.by`→ guidance finding) — proves belt+suspenders, no regression.
- **B (clamp):** for each swept tool, assert an oversized `limit` (e.g. 5000) is capped at 100 and a valid one passes through; assert the internal `cancel_tasks` `limit=201` is untouched.
- **C (search bound):** assert a > 128-char or control-char `search`/`value` returns a guidance finding pre-request (no HTTP call); assert a normal multi-word search passes.
- Full suite + `ruff` + strict `mypy` stay green. Update any per-server registration/enum tests to include the newly-closed enums.

### Measurement (Layer B — non-gating, run by me)

After merge, run `evals/run.py` against the local OpenAI-compatible endpoint, A/B on argument-fill accuracy for the promoted tools (severity_min / category / status / by / compliance).

⚠️ **Honest caveat:** the endpoint currently reachable (Ollama :11434) is serving **MiniCPM5-1B**, which tool-calls poorly on Ollama (prior finding: ~0% on Ollama, needs an XML parser via SGLang/vLLM). For a representative number the box needs a capable tool-caller pulled (Gemma 4 / Qwen3 / GPT-OSS-20b). I'll report whatever the available model yields and flag clearly if it isn't representative. Measurement never gates the merge — the schema hardening is correct Rule-5 work on its own.

---

## Out of scope (YAGNI)

- No changes to `core/paging` (the helper already exists) or `core/` at all.
- No promotion of open passthrough filters (see Scope).
- No new tools, no behavioural changes to what any tool returns.
- No tightening of the read-search guard to the strict write charset.
