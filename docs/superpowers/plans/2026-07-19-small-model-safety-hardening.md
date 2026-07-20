# Small-model-safety hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Tighten three cross-cutting Rule-5 gaps — enum params advertised as free strings, unbounded read `limit`, asymmetric read/write input validation — with no behavioural regression.

**Architecture:** Promote confirmed-closed str params to `Literal[...]` in the **server wrapper only** (tools-layer keeps its graceful fallback = belt+suspenders); apply the existing `core/paging.clamp_limit` to model-facing read `limit`s in the servers that skip it; add a permissive length/control-char bound to two read-search params.

**Tech Stack:** Python 3.11+, FastMCP, `core/paging.clamp_limit` (already exists), `pytest`, `ruff`, strict `mypy`.

**Spec:** `docs/superpowers/specs/2026-07-19-small-model-safety-hardening-design.md` (commit `74e3f21`).

## Global Constraints

- **Belt + suspenders:** promote only the **wrapper** param annotation to `Literal`. Tools-layer signatures stay `str` and keep their existing tolerant/graceful handling. No path newly hard-fails (Critical Rule 4: every failure → finding).
- **Only promote confirmed-closed enums.** Leave these OPEN passthrough filters as `str` (a Literal on them is a regression): `projectachilles.list_agents(status)`, `limacharlie.list_detections(category)`, `limacharlie.list_dr_rules(namespace)`.
- **`clamp_limit` pattern:** bare `limit = clamp_limit(limit)` at the top of each tools-layer read function (bounds to [1,100]; matches the tenable/defender pattern). Import `from f0_sectools_core.paging import clamp_limit`. **Do NOT clamp** internal, non-model-facing limits — specifically `cancel_tasks`'s hardcoded enumeration `limit=201`.
- **Read-search guard is permissive:** reject only `len > 128` or a control char (`ord(c) < 0x20`) → the server's existing graceful guidance finding. Do NOT use the strict write-side `_SCOPE_RE` charset (it would reject valid keyword searches).
- Full suite + `ruff check .` + `mypy core servers` stay green.
- **Commit trailers** on every commit:
  ```
  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01Va1ncSUtqQJyetofn2mJem
  ```
- **Do not push.** Commit locally; surface hashes; wait for explicit push.

---

## File Structure

| File | Change | Task |
|---|---|---|
| `servers/defender-mcp/f0_defender_mcp/server.py` | Literal on `list_incidents.severity_min`, `list_alerts.severity_min`, `hunt.category` | 1 |
| `servers/tenable-mcp/f0_tenable_mcp/server.py` | Literal on `list_top_vulnerabilities.severity_min`, `get_asset_vulnerabilities.severity_min` | 1 |
| `servers/projectachilles-mcp/f0_projectachilles_mcp/server.py` | Literal on `list_risk_acceptances.status`, `find_tests.by` | 1 |
| `servers/intune-mcp/f0_intune_mcp/server.py` | Literal on `list_managed_devices.compliance` | 1 |
| `servers/{defender,tenable,intune}-mcp/tests/test_tools.py`, `servers/projectachilles-mcp/tests/test_server_registration.py`, `servers/limacharlie-mcp/tests/test_tools.py` | schema-enum tests + open-stays-str tests + graceful-fallback tests | 1 |
| `servers/projectachilles-mcp/f0_projectachilles_mcp/tools.py` | `clamp_limit` on 5 reads (T2); `find_tests` value guard (T3) | 2,3 |
| `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py` | `clamp_limit` on `list_tasks` (T2); `list_tasks` search guard (T3) | 2,3 |
| `servers/limacharlie-mcp/f0_limacharlie_mcp/tools.py` | `clamp_limit` on `list_dr_rules`, `list_detections`, `query_telemetry` | 2 |
| `servers/intune-mcp/f0_intune_mcp/tools.py` | `clamp_limit` on `list_managed_devices`, `list_stale_devices`, `list_compliance_policies`, `list_configuration_profiles` | 2 |
| the four servers' `tests/test_tools.py` | clamp tests | 2 |

---

## Task 1: Item A — Literal-enum promotion (wrappers only)

**Files:**
- Modify: `servers/defender-mcp/f0_defender_mcp/server.py`, `servers/tenable-mcp/f0_tenable_mcp/server.py`, `servers/projectachilles-mcp/f0_projectachilles_mcp/server.py`, `servers/intune-mcp/f0_intune_mcp/server.py`
- Test: `servers/defender-mcp/tests/test_tools.py`, `servers/tenable-mcp/tests/test_tools.py`, `servers/intune-mcp/tests/test_tools.py`, `servers/projectachilles-mcp/tests/test_server_registration.py`, `servers/limacharlie-mcp/tests/test_tools.py`

**Interfaces:**
- Produces: unchanged tool names/behaviour; only the MCP input schema's `enum` for the promoted params. Tools-layer signatures untouched.

**The promotion table (wrapper annotation only; keep the default):**

| server.py wrapper | param: current → new |
|---|---|
| defender `list_incidents` | `severity_min: str = "medium"` → `severity_min: Literal["info", "low", "medium", "high", "critical"] = "medium"` |
| defender `list_alerts` | `severity_min: str = "high"` → `severity_min: Literal["info", "low", "medium", "high", "critical"] = "high"` |
| defender `hunt` | `category: str` → `category: Literal["network", "process", "logon", "email"]` |
| tenable `list_top_vulnerabilities` | `severity_min: str = "high"` → `severity_min: Literal["low", "medium", "high", "critical"] = "high"` |
| tenable `get_asset_vulnerabilities` | `severity_min: str = "high"` → `severity_min: Literal["low", "medium", "high", "critical"] = "high"` |
| projectachilles `list_risk_acceptances` | `status: str = "active"` → `status: Literal["active", "revoked"] = "active"` |
| projectachilles `find_tests` | `by: str` → `by: Literal["technique", "actor", "tactic", "category", "tag", "keyword"]` |
| intune `list_managed_devices` | `compliance: str = "all"` → `compliance: Literal["all", "compliant", "noncompliant", "ingraceperiod", "unknown"] = "all"` |

Each of the four server.py files needs `Literal` imported: change `from typing import Any` → `from typing import Any, Literal`.

**DO NOT touch** (leave as `str`/`str | None`): projectachilles `list_agents(status)`, limacharlie `list_detections(category)`, limacharlie `list_dr_rules(namespace)`. The tools-layer functions everywhere stay `str` (belt+suspenders).

- [ ] **Step 1: Write the failing schema tests**

Add to `servers/defender-mcp/tests/test_tools.py` (import `pytest` and `server` if not already; mirror the existing `list_tools()` pattern used in tenable's tests):

```python
@pytest.mark.asyncio
async def test_severity_and_category_enums_closed():
    from f0_defender_mcp import server
    tools = {t.name: t for t in await server.mcp.list_tools()}
    for name in ("list_incidents", "list_alerts"):
        enum = tools[name].inputSchema["properties"]["severity_min"]["enum"]
        assert set(enum) == {"info", "low", "medium", "high", "critical"}
    assert set(tools["hunt"].inputSchema["properties"]["category"]["enum"]) == {
        "network", "process", "logon", "email"}
```

Add the analogous enum tests to `tenable/tests/test_tools.py` (`severity_min` on `list_top_vulnerabilities`/`get_asset_vulnerabilities` → `{"low","medium","high","critical"}`), `intune/tests/test_tools.py` (`list_managed_devices.compliance` → `{"all","compliant","noncompliant","ingraceperiod","unknown"}`), and `projectachilles/tests/test_server_registration.py` (`list_risk_acceptances.status` → `{"active","revoked"}`; `find_tests.by` → the 6-value set).

Add the **open-stays-str** guard tests — `projectachilles/tests/test_server_registration.py`:

```python
@pytest.mark.asyncio
async def test_open_passthrough_params_stay_free_strings():
    from f0_projectachilles_mcp import server
    tools = {t.name: t for t in await server.mcp.list_tools()}
    # list_agents.status is an unvalidated passthrough filter — must NOT be a closed enum.
    assert "enum" not in tools["list_agents"].inputSchema["properties"]["status"]
```

and `limacharlie/tests/test_tools.py`:

```python
@pytest.mark.asyncio
async def test_open_passthrough_params_stay_free_strings():
    from f0_limacharlie_mcp import server
    tools = {t.name: t for t in await server.mcp.list_tools()}
    assert "enum" not in tools["list_detections"].inputSchema["properties"]["category"]
    assert "enum" not in tools["list_dr_rules"].inputSchema["properties"]["namespace"]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd servers/defender-mcp && uv run pytest tests/test_tools.py -k enum -v`
Expected: FAIL — `KeyError: 'enum'` (param is still a free string).

- [ ] **Step 3: Implement the promotions**

Apply the promotion table to each server.py wrapper (annotation only; body/default unchanged), adding `Literal` to each file's `typing` import. Example (defender):

```python
from typing import Any, Literal
...
@mcp.tool()
async def list_incidents(
    severity_min: Literal["info", "low", "medium", "high", "critical"] = "medium",
    limit: int = 25,
) -> list[dict[str, Any]]:
    """List Defender XDR incidents (correlated alert groups).

    severity_min: one of info|low|medium|high|critical. limit: max incidents.
    """
    cfg = PlatformConfig.from_env("DEFENDER")
    async with GraphClient(cfg) as gc:
        return _render(await tools.list_incidents(gc, severity_min, limit))
```

- [ ] **Step 4: Add the graceful-fallback (belt+suspenders) tests**

These call the **tools layer** directly with an out-of-enum value (a lenient client bypassing the schema) and assert it still degrades gracefully, not crashes. Add to the relevant `test_tools.py`:

```python
@pytest.mark.asyncio
async def test_find_tests_unknown_by_is_graceful_finding():
    # tools-layer keeps its floor even though the wrapper now advertises an enum.
    from f0_projectachilles_mcp import tools
    class _Fake:
        async def get(self, path, params=None): return {}
    findings = await tools.find_tests(_Fake(), by="bogus", value="x")
    assert findings[0].finding_type.value == "posture"
    assert "Unknown search dimension" in findings[0].title
```

For `severity_min` tools (defender/tenable), add a test that a tools-layer call with `severity_min="bogus"` returns findings without raising (the existing unknown→info behaviour). Use each server's existing FakeClient/respx fixture.

- [ ] **Step 5: Run all Task-1 tests + full suites for touched servers**

Run:
```bash
for s in defender tenable projectachilles intune limacharlie; do
  (cd servers/$s-mcp && uv run pytest -q) || break
done
```
Expected: all PASS (new enum + open-stays-str + graceful tests pass; nothing regressed).

- [ ] **Step 6: Commit**

```bash
git add servers/defender-mcp servers/tenable-mcp servers/projectachilles-mcp \
        servers/intune-mcp servers/limacharlie-mcp/tests
git commit -F - <<'EOF'
feat(servers): promote confirmed-closed enum params to Literal (small-model-safe schemas)

severity_min (defender x2, tenable x2), hunt.category, list_risk_acceptances.status,
find_tests.by, list_managed_devices.compliance now advertise a closed enum in the MCP
schema so small models pick from it. Wrapper-only change; tools-layer keeps its
graceful fallback (belt+suspenders). Open passthrough filters (list_agents.status,
list_detections.category, list_dr_rules.namespace) verified open -> stay free strings,
locked by tests.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Va1ncSUtqQJyetofn2mJem
EOF
```

---

## Task 2: Item B — `limit` ceiling sweep

**Files:**
- Modify: `servers/projectachilles-mcp/f0_projectachilles_mcp/tools.py`, `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py`, `servers/limacharlie-mcp/f0_limacharlie_mcp/tools.py`, `servers/intune-mcp/f0_intune_mcp/tools.py`
- Test: each server's `tests/test_tools.py` (+ `projectachilles-actions-mcp/tests/test_list_tasks.py`)

**Interfaces:**
- Consumes: `from f0_sectools_core.paging import clamp_limit` (already used by defender/entra/tenable; signature `clamp_limit(limit) -> int`, bounds to [1,100]).
- Produces: model-facing `limit` on these reads capped at 100.

**Sites — add `limit = clamp_limit(limit)` as the FIRST line of each function body (after the docstring), and add the import to each file:**

- **projectachilles/tools.py:** `find_tests` (108), `get_weak_techniques` (361), `list_test_executions` (409), `list_risk_acceptances` (570), `list_agents` (597)
- **projectachilles-actions/tools.py:** `list_tasks` (701) — **NOT** `cancel_tasks`'s internal `limit=_MAX_CANCEL + 1`
- **limacharlie/tools.py:** `list_dr_rules` (114), `list_detections` (142), `query_telemetry` (227)
- **intune/tools.py:** `list_managed_devices` (75), `list_stale_devices` (126), `list_compliance_policies` (223), `list_configuration_profiles` (241)

- [ ] **Step 1: Write the failing clamp tests**

One representative test per server asserting an oversized `limit` is capped at 100. For `projectachilles` (FakeClient records outbound params — `list_test_executions` sends `pageSize=limit`):

```python
@pytest.mark.asyncio
async def test_list_test_executions_clamps_oversized_limit():
    pa = FakeClient(responses={"/analytics/executions/paginated": {"data": []}})
    await tools.list_test_executions(pa, limit=5000)
    _, params = pa.calls[0]
    assert params["pageSize"] == 100   # clamped from 5000
```

For `projectachilles-actions` `list_tasks` (respx — asserts the `limit` query param), add to `tests/test_list_tasks.py`:

```python
@pytest.mark.asyncio
async def test_list_tasks_clamps_oversized_limit():
    with respx.mock as router:
        route = router.get(f"{BASE}/api/agent/admin/tasks").mock(
            return_value=httpx.Response(200, json={"success": True, "data": {"tasks": [], "total": 0}}))
        async with ProjectAchillesClient(_cfg()) as pa:
            await list_tasks(pa, limit=5000)
    assert "limit=100" in str(route.calls[0].request.url)
```

Add analogous representative clamp tests for `intune` (`list_managed_devices`, oversized → outbound `$top`/slice capped at 100 per that tool's mechanism) and `limacharlie` (`list_detections`, oversized `limit` → the value passed to `lc.list_detections(..., limit=...)` is 100).

**Regression guard** — add to `projectachilles-actions-mcp/tests/test_cancel_tasks.py` (the internal 201 enumeration must be untouched):

```python
@pytest.mark.asyncio
async def test_cancel_tasks_enumeration_still_requests_201(tmp_path):
    with respx.mock(assert_all_called=False) as router:
        get = router.get(f"{BASE}/api/agent/admin/tasks").mock(return_value=_tasks(["t1"]))
        router.post(url__regex=rf"{BASE}/api/agent/admin/tasks/.+/cancel")
        async with ProjectAchillesClient(_cfg()) as pa:
            await cancel_tasks(pa, _gate(tmp_path), status="pending")
    assert "limit=201" in str(get.calls[0].request.url)  # NOT clamped to 100
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd servers/projectachilles-mcp && uv run pytest tests/test_tools.py -k clamp -v`
Expected: FAIL — `params["pageSize"] == 5000` (not yet clamped).

- [ ] **Step 3: Implement**

In each of the four `tools.py`, add the import (near the other `f0_sectools_core` imports):

```python
from f0_sectools_core.paging import clamp_limit
```

and make `limit = clamp_limit(limit)` the first statement of each listed function's body. Example (`list_test_executions`):

```python
async def list_test_executions(
    pa: Any, days: int = 7, limit: int = 25,
    test: str = "", tag: str = "", hostname: str = "",
) -> list[Finding]:
    limit = clamp_limit(limit)
    frm, to = _window(days)
    ...
```

Leave `cancel_tasks`'s `params = {"status": st, "limit": _MAX_CANCEL + 1}` exactly as-is.

- [ ] **Step 4: Run tests to verify they pass**

Run: `for s in projectachilles projectachilles-actions limacharlie intune; do (cd servers/$s-mcp && uv run pytest -q) || break; done`
Expected: PASS (clamp tests green; the 201-regression guard green; nothing else broke).

- [ ] **Step 5: Commit**

```bash
git add servers/projectachilles-mcp servers/projectachilles-actions-mcp \
        servers/limacharlie-mcp servers/intune-mcp
git commit -F - <<'EOF'
feat(servers): clamp model-facing read limits to 100 (Rule 5 bounded output)

Applies the existing core/paging.clamp_limit to the read tools in
projectachilles / pa-actions / limacharlie / intune that skipped it
(they now match defender/entra/tenable). Internal cancel_tasks
enumeration (limit=201) intentionally untouched.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Va1ncSUtqQJyetofn2mJem
EOF
```

---

## Task 3: Item C — read-search input bound + final verification

**Files:**
- Modify: `servers/projectachilles-mcp/f0_projectachilles_mcp/tools.py` (`find_tests` value guard), `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py` (`list_tasks` search guard)
- Test: `servers/projectachilles-mcp/tests/test_tools.py`, `servers/projectachilles-actions-mcp/tests/test_list_tasks.py`

**Interfaces:**
- Produces: a permissive `_search_ok(value: str) -> bool` module helper in each of the two `tools.py`; both reads reject oversized/control-char searches pre-request via the server's existing graceful finding.

**The helper (add near the top-of-module regexes in each file):**

```python
def _search_ok(value: str) -> bool:
    """Permissive bound for a read-side search term: reject only oversized or
    control-character values (context-window / hygiene, not injection — httpx
    encodes params). Legit multi-word / dotted / id searches pass."""
    return len(value) <= 128 and all(ord(c) >= 0x20 for c in value)
```

- [ ] **Step 1: Write the failing tests**

`projectachilles/tests/test_tools.py`:

```python
@pytest.mark.asyncio
async def test_find_tests_rejects_oversized_value():
    pa = FakeClient(responses={"/browser/tests": {"data": []}})
    findings = await tools.find_tests(pa, by="keyword", value="x" * 129)
    assert findings[0].finding_type.value == "posture"
    assert pa.calls == []  # rejected pre-request


@pytest.mark.asyncio
async def test_find_tests_allows_normal_multiword_value():
    pa = FakeClient(responses={"/browser/tests": {"data": []}})
    await tools.find_tests(pa, by="keyword", value="pass the hash (T1550.002)")
    assert pa.calls  # normal search reached the API
```

`projectachilles-actions/tests/test_list_tasks.py`:

```python
@pytest.mark.asyncio
async def test_list_tasks_rejects_control_char_search():
    with respx.mock(assert_all_called=False) as router:
        route = router.get(f"{BASE}/api/agent/admin/tasks")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await list_tasks(pa, search="bad\nsearch")
    assert route.called is False
    assert findings[0].finding_type.value == "posture"
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd servers/projectachilles-mcp && uv run pytest tests/test_tools.py -k "find_tests_rejects or find_tests_allows" -v`
Expected: FAIL — the oversized value currently reaches the API (`pa.calls` non-empty).

- [ ] **Step 3: Implement**

`projectachilles/tools.py` — in `find_tests`, after the `by` guard block and before building `param`/the request, add:

```python
    if value and not _search_ok(value):
        return [
            Finding(
                source="projectachilles",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title="Search value too long or contains control characters",
                recommended_action=RecommendedAction(
                    summary="Use a plain search term (<=128 chars, no control characters).",
                ),
            )
        ]
```

`projectachilles-actions/tools.py` — in `list_tasks`, before building `params`, add (this server has the `guidance` helper):

```python
    if search and not _search_ok(search):
        return [guidance(
            "search is too long or contains control characters",
            "Use a plain test-name or hostname substring (<=128 chars).",
        )]
```

Add the `_search_ok` helper to each file.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd servers/projectachilles-mcp && uv run pytest tests/test_tools.py -q && cd ../projectachilles-actions-mcp && uv run pytest -q`
Expected: PASS.

- [ ] **Step 5: Final verification + doc scan**

Run the whole gate:
```bash
cd /home/jimx/F0RT1KA/sec-tools
uv run pytest -q
uv run ruff check .
uv run mypy core servers
```
Expected: full suite PASS, ruff clean, mypy clean.

Doc scan — the promoted enums' values already appear in the tool docstrings, so no doc rewrite is expected, but verify nothing states a now-stale type:
```bash
grep -rn "severity_min\|compliance\|find_tests" CLAUDE.md README.md docs/user-guide/ | grep -i "str\|free" || echo "no stale type mentions"
```
If a doc explicitly calls one of these params a "free string", update it to note the closed enum. Otherwise no doc change.

- [ ] **Step 6: Commit**

```bash
git add servers/projectachilles-mcp servers/projectachilles-actions-mcp
git commit -F - <<'EOF'
feat(pa): bound read-search inputs (symmetric read/write validation)

find_tests(value) and list_tasks(search) now reject oversized (>128) or
control-character values with a graceful finding, matching that gated
writes already validate their search. Permissive by design (length +
control-char only, not the strict write charset) so legit keyword/name
searches pass. httpx encodes params — this is context-window hygiene,
not injection defense.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Va1ncSUtqQJyetofn2mJem
EOF
```

---

## Measurement (post-merge, run by controller — NOT a task)

After merge, run `evals/run.py --server <affected>` A/B (before baseline vs after) against the local OpenAI-compatible endpoint, comparing argument-fill accuracy on the promoted tools. ⚠️ The endpoint currently serves MiniCPM5-1B (tool-calls poorly on Ollama); for a representative number a capable tool-caller (Gemma 4 / Qwen3 / GPT-OSS-20b) must be served. Report the number and flag if not representative. Non-gating.

## Self-review notes

- **Spec coverage:** Item A → Task 1 (incl. open-stays-str + graceful-fallback tests); Item B → Task 2 (incl. 201-untouched guard); Item C → Task 3; Item D testing folded into 1–3, measurement noted above. All spec sections mapped.
- **Type consistency:** tools-layer signatures stay `str` in every task; only wrapper annotations become `Literal`. `clamp_limit` imported identically in all four Task-2 files. `_search_ok` defined in both Task-3 files (same signature).
- **No `cancel_tasks` clamp:** called out in Global Constraints, Task 2 site list, and a dedicated regression test.
