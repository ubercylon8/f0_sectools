# ProjectAchilles Test Catalog (read) — Design

**Status:** Approved for planning
**Date:** 2026-07-14
**Branch:** `feat/projectachilles-catalog`
**Scope:** Sub-project **A** of the two planned ProjectAchilles additions. Sub-project **B** (gated writes: schedule / unschedule / execute) is explicitly **deferred to its own later spec/plan/PR** and is out of scope here.

---

## Goal

Give an operator (via a small local model) a read-only way to explore the **ProjectAchilles test library / catalog** — the available security tests and cyber-hygiene control checks and their metadata — so they can ask, e.g.:

- "How many tests do we have for technique T1110?"
- "Do we have any tests for threat actor APT29?"
- "List the tests in the cyber-hygiene category" / "…tagged `persistence`" / "…for the `credential-access` tactic"
- "What does test *X* cover?" (description, OS/target, techniques, tactics, complexity)

This is distinct from the existing `list_test_executions` (run **history**). The catalog is the **library of what *can* be run**.

## Non-goals (YAGNI)

- No raw test **file** bodies (attack-flow YAML, kill-chain, README, binaries). Those live behind heavier `/api/browser/tests/:uuid/{files,description,attack-flow,kill-chain}` endpoints and are not small-model-safe payloads.
- No write / schedule / execute actions (sub-project B).
- No new server, no new `.env`, no new auth mechanism.
- No `severity` dimension in `find_tests` (can be added later if asked; kept out to hold the enum short).

---

## Architecture

Extend the **existing** `servers/projectachilles-mcp` — no second server. `core/` is unchanged (reuses `Finding`, `redact_obj`, `map_pa_error`, the paging/bounding helpers).

- **Client:** the existing `ProjectAchillesClient.get(path, params)` already issues `GET {base_url}/api{path}` with the static `pa_` Bearer. The catalog endpoints are reached with:
  - list: `pa.get("/browser/tests", params=...)`
  - detail: `pa.get(f"/browser/tests/{uuid}")`
  No client changes beyond possibly a `404`-aware error path (see Errors).
- **Tools:** two new async functions in `f0_projectachilles_mcp/tools.py` returning `list[Finding]`; two `@mcp.tool()` wrappers in `server.py`, each rendered through `redact_obj(f.model_dump())` at the boundary.
- **Tool budget:** PA server goes **6 → 8** tools — at the ≤~8 small-model ceiling, not over it.

### Auth (the one live-validation risk)

PA applies `acceptApiKey` **globally** (`app.use` before all route mounts); it accepts `Authorization: Bearer pa_…` and synthesises `req.auth` for every route. The `/api/browser/tests` GET handlers carry **no** `requirePermission(...)` gate — they only need an identity — so the static `pa_` key should reach them exactly as it already reaches `/api/analytics/*`. This is the primary thing the live smoke test must confirm first.

- **If reachability holds:** done, no new auth.
- **Fallback if PA later gates browser routes:** the PA CLI's Clerk device-code → JWT flow (`/api/cli/auth/*`, 1h access + refresh token) is the alternative; a stored refresh token in `.env.projectachilles` would be the non-interactive adapter. Documented as fallback only — **not built now** (YAGNI).

Because `map_pa_error` already turns `401/403` into a graceful posture finding, a wrong auth assumption degrades **loudly but safely** (a clear finding), never a crash or a secret leak.

---

## Data source & field mapping

`GET /api/browser/tests` returns a bounded per-test metadata list (no file bodies). Server-side query filters: `?search=`, `?technique=`, `?category=`, `?severity=`. Per-test fields (from `TestMetadata`/`TestDetails` in the PA backend):

| Finding field (ours) | PA field | Notes |
|---|---|---|
| `os` (evidence) | `target: string[]` | e.g. `windows-endpoint`, `linux-server`, `entra-id`. The user's "OS". |
| `techniques` / references | `techniques: string[]` | MITRE `T####`; also emitted as `Reference(type="mitre")`. |
| `tactics` | `tactics?: string[]` | MITRE `TA00xx`. |
| `threat_actor` | `threatActor?: string` | |
| `severity` | `severity?: string` | critical/high/medium/low. |
| `complexity` | `complexity?: string` | low/medium/high. |
| `category` | `category` | intel-driven / mitre-top10 / cyber-hygiene / phase-aligned. |
| `subcategory` | `subcategory?: string` | |
| `tags` | `tags?: string[]` | |
| `description` | `description?: string` | one line in list findings; full in `get_test`. |
| `uuid` (evidence) | `uuid` | enables `find_tests` → `get_test` chaining. |
| `stage_count` | `stageCount` / `stages.length` | `get_test` only. |

> Real field names/shapes are authoritative only after live validation (recipe step 9 — "mocks encode assumptions; the live API is truth"). Contract tests assert our mapping against a fake client; the smoke script confirms the wire shape.

---

## Tool contracts

### Tool 1 — `find_tests(by: str, value: str, limit: int = 25) -> list[Finding]`

Find catalog tests by one dimension.

- **`by`** — closed enum: `technique | actor | tactic | category | tag | keyword`.
- **`value`** — the term to match (e.g. `T1110`, `APT29`, `cyber-hygiene`, `persistence`).
- **`limit`** — max per-test findings returned (default 25; bounded).

**Routing:**
- `technique` → `?technique={value}` (server-side)
- `category` → `?category={value}` (server-side)
- `keyword` → `?search={value}` (server-side)
- `actor` → fetch list, client-side filter on `threatActor` (case-insensitive contains)
- `tactic` → fetch list, client-side filter on `tactics[]`
- `tag` → fetch list, client-side filter on `tags[]`

**Returns** (a `list[Finding]`):
1. A **leading summary finding** (`finding_type=posture`, entity kind `tenant`): title `"{N} tests match {by}={value}"`, evidence `total_matches={N}`, `returned={min(N, limit)}`. This makes "how many…?" **exact even when the per-test list is truncated** — bounded output must never misreport a count.
2. Up to `limit` per-test findings (`finding_type=posture`, entity kind `rule`, `id=uuid`, `name=test name`): title `"Test: {name} ({category})"`, evidence `techniques`, `threat_actor`, `os`, `severity`, `complexity`, `description` (one line), `uuid`; `references` = MITRE techniques.

If `N == 0`: return only the summary finding (`"0 tests match {by}={value}"`) — a clean empty result, not an error.

**Invalid `by`** (not in the enum): return a single posture finding naming the allowed values — never raise.

### Tool 2 — `get_test(test_id: str) -> list[Finding]`

Full detail for one catalog test.

- **`test_id`** — a **UUID or a test name**. A small model usually holds a name from a prior `find_tests` result, not a UUID.
  - If `test_id` matches the UUID regex → `pa.get(f"/browser/tests/{uuid}")` directly.
  - Else → resolve by name via `?search={test_id}`: exact (case-insensitive) name match wins; if exactly one fuzzy match, use it; if multiple, return a `"Multiple tests match '{test_id}' — specify by uuid"` finding listing the candidates (name + uuid); if none, a `"No test found for '{test_id}'"` finding.
- **Returns** one finding (`finding_type=posture`, entity kind `rule`): title `"Test: {name}"`, evidence `description` (full), `os`, `complexity`, `category`, `subcategory`, `severity`, `tactics`, `tags`, `stage_count`; `references` = MITRE techniques.
- **`404`** from the UUID path → graceful `"Test {test_id} not found"` posture finding (not an exception).

---

## Errors

Reuse `map_pa_error(e, capability)` — every failure becomes a finding:
- auth (`401`) → posture finding ("authentication …")
- `403` → `Finding.permission_missing`
- `429` → `Finding.rate_limited`
- `502/503/504` → "API unavailable" posture finding
- **New:** `404` (single-test fetch) → a clean "not found" posture finding, handled in the tool (caught before `map_pa_error` re-raises) so it reads as a normal negative result.

Redaction (`redact_obj`) runs at the server boundary on every finding, including error findings — unchanged from the existing tools.

---

## Testing

### Contract tests (`servers/projectachilles-mcp/tests/test_tools.py`, fake client — TDD each)

- `find_tests` **server-side routing**: `by=technique` sends `?technique=`, `by=category` sends `?category=`, `by=keyword` sends `?search=` (assert on `FakeClient.calls`).
- `find_tests` **client-side routing**: `by=actor|tactic|tag` filters the returned list correctly (matching + non-matching rows in the fixture).
- `find_tests` **summary finding + count**: leading finding carries exact `total_matches`; with a fixture of `> limit` matches, `returned == limit` but `total_matches == N` (truncation never lies).
- `find_tests` **empty**: `N=0` → single summary finding, `finding_type=posture`, no per-test findings.
- `find_tests` **invalid `by`**: returns the allowed-values finding, no raise.
- `find_tests` **field mapping**: `os` comes from `target[]`; MITRE `references` populated from `techniques`.
- `get_test` **by uuid**: hits `/browser/tests/{uuid}`, maps full detail incl. `stage_count`.
- `get_test` **by name**: exact match resolves; multiple matches → "specify by uuid" finding; none → "no test found" finding.
- `get_test` **404** → graceful not-found finding.
- **Degradation**: `401` / `403` / `5xx` on `/browser/tests` → posture/permission/unavailable findings (reuse existing patterns).

### Evals (`evals/projectachilles/tasks.yaml`)

Add ≥1 task per new tool:
- "How many tests do we have for T1110?" → `find_tests(by=technique, value=T1110)`
- "Do we have tests for APT29?" → `find_tests(by=actor, value=APT29)`
- "What does test *<name>* cover?" → `get_test`

PA is already in `SERVERS` (`evals/test_eval_coverage.py`) and `SERVER_MODULES` (`evals/run.py`) — no registration change.

### Live smoke (`scripts/live_smoke_projectachilles.py`)

Extend with `find_tests` (one server-side dim + one client-side dim) and `get_test`. **First assertion: auth reachability** of `/browser/tests` with the `pa_` key. Operator drives this on the tenant (pi); fix-forward field/shape mismatches (recipe step 9).

---

## Skill

New light skill `skills/projectachilles/explore-test-catalog/SKILL.md` (agentskills.io, ≤60-char description) — "find which tests cover a technique / actor / tactic, and what a test does." References `find_tests` / `get_test` by base name. Procedure: pick the `by` dimension → `find_tests` → drill into a specific test with `get_test`. Pitfalls: this is the **library** (what can be run), not `list_test_executions` (what *was* run); don't conflate a catalog entry with a result. Passes `skills/test_skills_valid.py`.

---

## Docs

- `CLAUDE.md` — PA tool count 6 → 8 (Architecture tree note); no structural change.
- `README.md` — status line + tool table total 34 → 36; PA row 6 → 8 (read-only).
- User-guide — one PA workflow line for catalog lookup.

---

## Delivery order (mirrors the add-a-platform recipe)

1. (Client) `404`-aware path if needed → 2. Errors (404 handling) → 3. `find_tests` (TDD) → 4. `get_test` (TDD) → 5. Server wiring + boundary redaction → 6. Evals → 7. Smoke script → 8. **Live-validate on tenant (user-driven, fix-forward)** → 9. Skill → 10. Docs → 11. `uv run pytest` + `ruff` + `mypy` + skills test → 12. Commit (conventional, Co-Authored-By/session trailers), **push only on explicit instruction**, open PR.

## Verification (definition of done)

- All new contract tests green; full suite + `ruff` + `mypy` clean.
- Live smoke confirms auth reachability and real field shapes; any mismatch fixed forward.
- `find_tests` answers the four example asks; counts exact under truncation.
- PA server at 8 tools; no `core/` change; no new secret path; redaction on every return.
- Sub-project B (gated writes) remains explicitly deferred and captured on the roadmap.
