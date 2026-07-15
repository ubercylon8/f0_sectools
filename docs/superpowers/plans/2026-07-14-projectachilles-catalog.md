# ProjectAchilles Test Catalog (read) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add two small-model-safe read tools — `find_tests` and `get_test` — to the existing `projectachilles-mcp` server so an operator can explore the ProjectAchilles test catalog (library of runnable security tests and cyber-hygiene checks) by technique / actor / tactic / category / tag / keyword.

**Architecture:** Extend `servers/projectachilles-mcp` (no new server, no new `.env`, no `core/` change). Both tools call `/api/browser/tests` (list, with server-side `?technique/?category/?search` filters) and `/api/browser/tests/{uuid}` (detail) through the existing `ProjectAchillesClient.get(path, params)` — which issues `GET {base_url}/api{path}` with the static `pa_` Bearer. Server-side dimensions filter at the API; actor/tactic/tag filter client-side over the returned list. Every result is a `Finding`, redacted at the server boundary.

**Tech Stack:** Python 3.11+, `mcp` (FastMCP), `httpx` (already in the client), `pytest`/`pytest-asyncio`, `ruff`, `mypy`. Spec: `docs/superpowers/specs/2026-07-14-projectachilles-catalog-design.md` (committed `bcd1db4`).

## Global Constraints

- Read-only. No state-changing calls. (Gated writes are sub-project B, out of scope.)
- Every failure becomes a `Finding`, never a raised exception out of a tool. Reuse `map_pa_error`.
- Redaction happens at the server boundary via `redact_obj(f.model_dump())` — never bypass it.
- Small-model-safe: `find_tests` has exactly three args (`by` closed enum of 6 values, `value` str, `limit` int); no nested args; bounded output.
- `by` enum is exactly: `technique | actor | tactic | category | tag | keyword`. No `severity` dimension.
- Tool count: `projectachilles-mcp` goes 6 → 8. Do not exceed 8.
- Findings use `source="projectachilles"`; a catalog test is `EntityKind.rule`; the catalog summary is `EntityKind.tenant`.
- API paths passed to `pa.get(...)` omit the `/api` prefix (the client adds it): use `/browser/tests` and `/browser/tests/{uuid}`.
- Live-validation and `git push` are USER-GATED — do not run live smoke against the tenant or push without explicit instruction.
- Commit trailers on every commit:
  ```
  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01Va1ncSUtqQJyetofn2mJem
  ```

**Reference — existing `FakeClient`** (already in `servers/projectachilles-mcp/tests/test_tools.py`, do not redefine): async `get(path, params=None)` that records `(path, params)` in `.calls`, returns the first `responses` value whose key is a prefix of `path`, or raises the first `raise_on` error whose key is a prefix of `path`, else returns `{}`. When a test needs the detail path, register the key `"/browser/tests/"` (trailing slash) so it does not also swallow a bare `"/browser/tests"` list call.

---

### Task 1: `find_tests` tool + catalog helpers

**Files:**
- Modify: `servers/projectachilles-mcp/f0_projectachilles_mcp/tools.py` (add imports, module constants, helpers, and `find_tests`)
- Test: `servers/projectachilles-mcp/tests/test_tools.py` (append tests)

**Interfaces:**
- Consumes: `ProjectAchillesClient.get(path, params)`; `map_pa_error(e, capability)`; schema types `Finding, Entity, EntityKind, Evidence, Reference, RecommendedAction, FindingType, Severity` (already imported at the top of `tools.py`).
- Produces:
  - `_FIND_BY: set[str]` — the 6 allowed `by` values.
  - `_tests(resp: Any) -> list[dict[str, Any]]` — extracts `resp["tests"]` (browser list shape) or a bare list, else `[]`.
  - `_test_evidence(t: dict) -> list[Evidence]` — compact per-test evidence (techniques, threat_actor, os, severity, complexity, uuid).
  - `async find_tests(pa, by: str, value: str, limit: int = 25) -> list[Finding]`.

- [ ] **Step 1: Write the failing tests**

Append to `servers/projectachilles-mcp/tests/test_tools.py`:

```python
@pytest.mark.asyncio
async def test_find_tests_technique_uses_server_side_filter():
    pa = FakeClient(responses={"/browser/tests": {"count": 1, "tests": [
        {"uuid": "u1", "name": "Kerberoast", "category": "mitre-top10",
         "severity": "high", "techniques": ["T1558.003"], "target": ["windows-endpoint"],
         "threatActor": "APT29", "complexity": "medium", "description": "Roast SPNs."},
    ]}})
    findings = await tools.find_tests(pa, by="technique", value="T1558.003")
    # server-side filter param is sent
    path, params = pa.calls[0]
    assert path == "/browser/tests" and params == {"technique": "T1558.003"}
    # leading summary finding carries an exact count
    assert findings[0].finding_type.value == "posture"
    assert "1 tests match technique=T1558.003" in findings[0].title
    ev0 = {e.key: e.value for e in findings[0].evidence}
    assert ev0["total_matches"] == "1"
    # per-test finding maps os from target[] and emits a MITRE reference
    ev1 = {e.key: e.value for e in findings[1].evidence}
    assert ev1["os"] == "windows-endpoint"
    assert ev1["threat_actor"] == "APT29"
    assert findings[1].entity.kind.value == "rule"
    assert any(r.id == "T1558.003" for r in findings[1].references)


@pytest.mark.asyncio
async def test_find_tests_category_and_keyword_route_server_side():
    pa = FakeClient(responses={"/browser/tests": {"tests": []}})
    await tools.find_tests(pa, by="category", value="cyber-hygiene")
    await tools.find_tests(pa, by="keyword", value="mimikatz")
    assert pa.calls[0][1] == {"category": "cyber-hygiene"}
    assert pa.calls[1][1] == {"search": "mimikatz"}


@pytest.mark.asyncio
async def test_find_tests_actor_filters_client_side():
    # PA browser routes have no actor filter -> we fetch all and filter locally.
    pa = FakeClient(responses={"/browser/tests": {"tests": [
        {"uuid": "u1", "name": "A", "category": "intel-driven", "threatActor": "APT29"},
        {"uuid": "u2", "name": "B", "category": "intel-driven", "threatActor": "FIN7"},
    ]}})
    findings = await tools.find_tests(pa, by="actor", value="apt29")
    assert pa.calls[0][1] == {}  # no server-side param (FakeClient records `params or {}`)
    assert "1 tests match actor=apt29" in findings[0].title
    assert findings[1].entity.name == "A"


@pytest.mark.asyncio
async def test_find_tests_tag_and_tactic_filter_client_side():
    pa = FakeClient(responses={"/browser/tests": {"tests": [
        {"uuid": "u1", "name": "A", "category": "c", "tags": ["persistence"],
         "tactics": ["TA0003"]},
        {"uuid": "u2", "name": "B", "category": "c", "tags": ["exfil"], "tactics": ["TA0010"]},
    ]}})
    by_tag = await tools.find_tests(pa, by="tag", value="persistence")
    assert by_tag[0].title.startswith("1 tests match tag=persistence")
    by_tactic = await tools.find_tests(pa, by="tactic", value="TA0010")
    assert by_tactic[1].entity.name == "B"


@pytest.mark.asyncio
async def test_find_tests_bounds_output_but_counts_all():
    rows = [{"uuid": f"u{i}", "name": f"T{i}", "category": "c",
             "techniques": ["T1110"]} for i in range(30)]
    pa = FakeClient(responses={"/browser/tests": {"tests": rows}})
    findings = await tools.find_tests(pa, by="technique", value="T1110", limit=5)
    ev0 = {e.key: e.value for e in findings[0].evidence}
    assert ev0["total_matches"] == "30" and ev0["returned"] == "5"  # truncation never lies
    assert len(findings) == 1 + 5  # summary + 5 tests


@pytest.mark.asyncio
async def test_find_tests_empty_returns_only_summary():
    pa = FakeClient(responses={"/browser/tests": {"tests": []}})
    findings = await tools.find_tests(pa, by="technique", value="T9999")
    assert len(findings) == 1
    assert "0 tests match technique=T9999" in findings[0].title


@pytest.mark.asyncio
async def test_find_tests_invalid_by_returns_finding_not_raise():
    pa = FakeClient(responses={"/browser/tests": {"tests": []}})
    findings = await tools.find_tests(pa, by="planet", value="mars")
    assert len(findings) == 1
    assert "planet" in findings[0].title
    assert not pa.calls  # never hit the API


@pytest.mark.asyncio
async def test_find_tests_401_degrades():
    pa = FakeClient(raise_on={"/browser/tests": ProjectAchillesError(401, "unauthorized")})
    findings = await tools.find_tests(pa, by="technique", value="T1110")
    assert findings[0].finding_type.value == "posture"
    assert "authentication" in findings[0].title.lower()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest servers/projectachilles-mcp/tests/test_tools.py -k find_tests -q`
Expected: FAIL — `AttributeError: module 'f0_projectachilles_mcp.tools' has no attribute 'find_tests'`.

- [ ] **Step 3: Implement the helpers and `find_tests`**

In `servers/projectachilles-mcp/f0_projectachilles_mcp/tools.py`, add this block after the existing `_rows` helper (no new imports needed in this task — `re` is added in Task 2 where `_UUID_RE` uses it):

```python
_FIND_BY = {"technique", "actor", "tactic", "category", "tag", "keyword"}

# PA supports these filters server-side on GET /api/browser/tests; the rest
# (actor/tactic/tag) are filtered client-side over the returned list.
_SERVER_SIDE = {"technique": "technique", "category": "category", "keyword": "search"}


def _tests(resp: Any) -> list[dict[str, Any]]:
    """Browser /tests returns {success, count, tests: [...]}. Be defensive."""
    if isinstance(resp, dict):
        t = resp.get("tests")
        if isinstance(t, list):
            return t
    if isinstance(resp, list):
        return resp
    return []


def _test_evidence(t: dict[str, Any]) -> list[Evidence]:
    return [
        Evidence(key="techniques", value=", ".join(t.get("techniques") or []) or "none"),
        Evidence(key="threat_actor", value=str(t.get("threatActor") or "none")),
        Evidence(key="os", value=", ".join(t.get("target") or []) or "any"),
        Evidence(key="severity", value=str(t.get("severity") or "unspecified")),
        Evidence(key="complexity", value=str(t.get("complexity") or "unspecified")),
        Evidence(key="uuid", value=str(t.get("uuid", ""))),
    ]


async def find_tests(pa: Any, by: str, value: str, limit: int = 25) -> list[Finding]:
    by = by.strip().lower()
    if by not in _FIND_BY:
        return [
            Finding(
                source="projectachilles",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"Unknown search dimension '{by}'",
                recommended_action=RecommendedAction(
                    summary="Use by = technique | actor | tactic | category | tag | keyword.",
                ),
            )
        ]
    param = _SERVER_SIDE.get(by)
    try:
        resp = await pa.get("/browser/tests", params={param: value} if param else None)
    except Exception as e:
        finding = map_pa_error(e, "ProjectAchilles test catalog")
        if finding:
            return [finding]
        raise
    rows = _tests(resp)
    needle = value.lower()
    if by == "actor":
        rows = [r for r in rows if needle in str(r.get("threatActor") or "").lower()]
    elif by == "tactic":
        rows = [r for r in rows if any(needle in str(x).lower() for x in (r.get("tactics") or []))]
    elif by == "tag":
        rows = [r for r in rows if any(needle in str(x).lower() for x in (r.get("tags") or []))]
    total = len(rows)
    out: list[Finding] = [
        Finding(
            source="projectachilles",
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=f"{total} tests match {by}={value}",
            entity=Entity(kind=EntityKind.tenant, id="catalog"),
            evidence=[
                Evidence(key="total_matches", value=str(total)),
                Evidence(key="returned", value=str(min(total, limit))),
            ],
        )
    ]
    for t in rows[:limit]:
        name = str(t.get("name", "test"))
        cat = str(t.get("category", "?"))
        ev = _test_evidence(t)
        desc = str(t.get("description") or "").strip().replace("\n", " ")
        if desc:
            ev.append(
                Evidence(key="description", value=desc[:197] + "..." if len(desc) > 200 else desc)
            )
        out.append(
            Finding(
                source="projectachilles",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"Test: {name} ({cat})",
                entity=Entity(kind=EntityKind.rule, id=str(t.get("uuid", "")), name=name),
                evidence=ev,
                references=[Reference(type="mitre", id=x) for x in (t.get("techniques") or [])],
            )
        )
    return out
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest servers/projectachilles-mcp/tests/test_tools.py -k find_tests -q`
Expected: PASS (8 tests).

- [ ] **Step 5: Lint/type-check the changed file**

Run: `uv run ruff check servers/projectachilles-mcp && uv run mypy servers/projectachilles-mcp`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add servers/projectachilles-mcp/f0_projectachilles_mcp/tools.py servers/projectachilles-mcp/tests/test_tools.py
git commit -m "feat(projectachilles): add find_tests catalog search tool

Search the test catalog by technique|actor|tactic|category|tag|keyword.
Leading summary finding carries exact total_matches so bounded output never
misreports a count. Server-side filters where PA supports them; actor/tactic/tag
filtered client-side.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Va1ncSUtqQJyetofn2mJem"
```

---

### Task 2: `get_test` tool (uuid-or-name, 404-aware)

**Files:**
- Modify: `servers/projectachilles-mcp/f0_projectachilles_mcp/tools.py` (add `ProjectAchillesError` import, `_UUID_RE`, `_not_found`, `_test_detail_finding`, `get_test`)
- Test: `servers/projectachilles-mcp/tests/test_tools.py` (append tests)

**Interfaces:**
- Consumes: `_tests` (from Task 1); `ProjectAchillesError` (from `.client`); `map_pa_error`; schema types.
- Produces: `async get_test(pa, test_id: str) -> list[Finding]`.

- [ ] **Step 1: Write the failing tests**

Append to `servers/projectachilles-mcp/tests/test_tools.py`:

```python
_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


@pytest.mark.asyncio
async def test_get_test_by_uuid_maps_full_detail():
    pa = FakeClient(responses={"/browser/tests/": {"test": {
        "uuid": _UUID, "name": "Kerberoast", "category": "mitre-top10",
        "subcategory": "credential-access", "severity": "high", "complexity": "medium",
        "techniques": ["T1558.003"], "tactics": ["TA0006"], "target": ["windows-endpoint"],
        "tags": ["kerberos"], "description": "Request SPNs and crack offline.",
        "stageCount": 2}}})
    findings = await tools.get_test(pa, _UUID)
    assert pa.calls[0][0] == f"/browser/tests/{_UUID}"
    f = findings[0]
    assert f.title == "Test: Kerberoast" and f.entity.kind.value == "rule"
    ev = {e.key: e.value for e in f.evidence}
    assert ev["os"] == "windows-endpoint" and ev["stage_count"] == "2"
    assert ev["subcategory"] == "credential-access"
    assert any(r.id == "T1558.003" for r in f.references)


@pytest.mark.asyncio
async def test_get_test_by_uuid_404_is_graceful():
    pa = FakeClient(raise_on={"/browser/tests/": ProjectAchillesError(404, "not found")})
    findings = await tools.get_test(pa, _UUID)
    assert len(findings) == 1
    assert "no test found" in findings[0].title.lower()
    assert findings[0].finding_type.value == "posture"


@pytest.mark.asyncio
async def test_get_test_by_name_resolves_via_search():
    pa = FakeClient(responses={"/browser/tests": {"tests": [
        {"uuid": "u1", "name": "Kerberoast", "category": "mitre-top10",
         "description": "d", "techniques": []},
    ]}})
    findings = await tools.get_test(pa, "Kerberoast")
    assert pa.calls[0] == ("/browser/tests", {"search": "Kerberoast"})
    assert findings[0].title == "Test: Kerberoast"


@pytest.mark.asyncio
async def test_get_test_by_name_ambiguous_asks_for_uuid():
    pa = FakeClient(responses={"/browser/tests": {"tests": [
        {"uuid": "u1", "name": "Dump LSASS", "category": "c"},
        {"uuid": "u2", "name": "Dump LSASS via comsvcs", "category": "c"},
    ]}})
    findings = await tools.get_test(pa, "Dump")
    assert len(findings) == 1
    assert "specify by uuid" in findings[0].title.lower()
    ev = {e.key: e.value for e in findings[0].evidence}
    assert ev["Dump LSASS"] == "u1"  # candidates listed name->uuid


@pytest.mark.asyncio
async def test_get_test_by_name_not_found():
    pa = FakeClient(responses={"/browser/tests": {"tests": []}})
    findings = await tools.get_test(pa, "Nonexistent")
    assert "no test found" in findings[0].title.lower()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest servers/projectachilles-mcp/tests/test_tools.py -k get_test -q`
Expected: FAIL — `module 'f0_projectachilles_mcp.tools' has no attribute 'get_test'`.

- [ ] **Step 3: Implement `get_test` and helpers**

In `tools.py`, add `import re` under the existing stdlib imports (below `from datetime import ...`), and add `from .client import ProjectAchillesError` (next to `from .errors import map_pa_error`). Add `_UUID_RE` next to `_FIND_BY`:

```python
_UUID_RE = re.compile(
    r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", re.IGNORECASE
)
```

Then add these functions after `find_tests`:

```python
def _not_found(test_id: str) -> Finding:
    return Finding(
        source="projectachilles",
        finding_type=FindingType.posture,
        severity=Severity.info,
        title=f"No test found for '{test_id}'",
        recommended_action=RecommendedAction(
            summary="Use find_tests to browse the catalog, then get_test by uuid or exact name.",
        ),
    )


def _test_detail_finding(t: dict[str, Any]) -> Finding:
    name = str(t.get("name", "test"))
    ev = [
        Evidence(key="description", value=str(t.get("description") or "none").strip()),
        Evidence(key="os", value=", ".join(t.get("target") or []) or "any"),
        Evidence(key="complexity", value=str(t.get("complexity") or "unspecified")),
        Evidence(key="category", value=str(t.get("category", "?"))),
        Evidence(key="subcategory", value=str(t.get("subcategory") or "none")),
        Evidence(key="severity", value=str(t.get("severity") or "unspecified")),
        Evidence(key="tactics", value=", ".join(t.get("tactics") or []) or "none"),
        Evidence(key="tags", value=", ".join(t.get("tags") or []) or "none"),
        Evidence(key="threat_actor", value=str(t.get("threatActor") or "none")),
    ]
    stage_count = t.get("stageCount")
    if stage_count is None and isinstance(t.get("stages"), list):
        stage_count = len(t["stages"])
    if stage_count is not None:
        ev.append(Evidence(key="stage_count", value=str(stage_count)))
    return Finding(
        source="projectachilles",
        finding_type=FindingType.posture,
        severity=Severity.info,
        title=f"Test: {name}",
        entity=Entity(kind=EntityKind.rule, id=str(t.get("uuid", "")), name=name),
        evidence=ev,
        references=[Reference(type="mitre", id=x) for x in (t.get("techniques") or [])],
    )


async def get_test(pa: Any, test_id: str) -> list[Finding]:
    test_id = test_id.strip()
    if _UUID_RE.match(test_id):
        try:
            resp = await pa.get(f"/browser/tests/{test_id}")
        except ProjectAchillesError as e:
            if e.status == 404:
                return [_not_found(test_id)]
            finding = map_pa_error(e, "ProjectAchilles test detail")
            if finding:
                return [finding]
            raise
        t = resp.get("test") if isinstance(resp, dict) else None
        return [_test_detail_finding(t)] if t else [_not_found(test_id)]
    # Resolve by name via search.
    try:
        resp = await pa.get("/browser/tests", params={"search": test_id})
    except Exception as e:
        finding = map_pa_error(e, "ProjectAchilles test detail")
        if finding:
            return [finding]
        raise
    rows = _tests(resp)
    exact = [r for r in rows if str(r.get("name", "")).lower() == test_id.lower()]
    candidates = exact or rows
    if len(candidates) == 1:
        return [_test_detail_finding(candidates[0])]
    if len(candidates) > 1:
        return [
            Finding(
                source="projectachilles",
                finding_type=FindingType.posture,
                severity=Severity.info,
                title=f"Multiple tests match '{test_id}' — specify by uuid",
                evidence=[
                    Evidence(key=str(r.get("name", "?")), value=str(r.get("uuid", "")))
                    for r in candidates[:10]
                ],
            )
        ]
    return [_not_found(test_id)]
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest servers/projectachilles-mcp/tests/test_tools.py -k get_test -q`
Expected: PASS (5 tests).

- [ ] **Step 5: Lint/type-check**

Run: `uv run ruff check servers/projectachilles-mcp && uv run mypy servers/projectachilles-mcp`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add servers/projectachilles-mcp/f0_projectachilles_mcp/tools.py servers/projectachilles-mcp/tests/test_tools.py
git commit -m "feat(projectachilles): add get_test catalog-detail tool

Full detail for one test by uuid or exact name (name resolves via search;
ambiguous -> asks for uuid). 404 on the uuid path degrades to a graceful
not-found finding.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Va1ncSUtqQJyetofn2mJem"
```

---

### Task 3: Server wiring (register the two tools)

**Files:**
- Modify: `servers/projectachilles-mcp/f0_projectachilles_mcp/server.py` (add two `@mcp.tool()` wrappers)
- Test: `servers/projectachilles-mcp/tests/test_server_registration.py` (create)

**Interfaces:**
- Consumes: `tools.find_tests`, `tools.get_test` (Tasks 1–2); existing `_client()` and `_render()` in `server.py`.
- Produces: MCP tools `find_tests`, `get_test` registered on the `f0-projectachilles` server.

- [ ] **Step 1: Write the failing test**

Create `servers/projectachilles-mcp/tests/test_server_registration.py`:

```python
"""The catalog tools must be registered on the FastMCP server."""
import pytest
from f0_projectachilles_mcp import server


@pytest.mark.asyncio
async def test_catalog_tools_registered():
    names = {t.name for t in await server.mcp.list_tools()}
    assert {"find_tests", "get_test"} <= names
    # server stays within the small-model tool budget
    assert len(names) == 8
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest servers/projectachilles-mcp/tests/test_server_registration.py -q`
Expected: FAIL — `find_tests`/`get_test` not in the registered set (and count is 6).

- [ ] **Step 3: Add the tool wrappers**

In `servers/projectachilles-mcp/f0_projectachilles_mcp/server.py`, add these two tools after the existing `get_fleet_health` tool (before `def main()`):

```python
@mcp.tool()
async def find_tests(by: str, value: str, limit: int = 25) -> list[dict[str, Any]]:
    """Search the ProjectAchilles TEST CATALOG — the library of tests that CAN be run,
    not run history (use list_test_executions for history). by selects the dimension:
    technique|actor|tactic|category|tag|keyword. Returns a match count plus the matching
    tests (name, MITRE techniques, threat actor, OS, severity)."""
    async with _client() as pa:
        return _render(await tools.find_tests(pa, by, value, limit))


@mcp.tool()
async def get_test(test_id: str) -> list[dict[str, Any]]:
    """Full detail for ONE catalog test — description, OS/target, complexity, tactics,
    tags, MITRE techniques. test_id is a test uuid or an exact test name."""
    async with _client() as pa:
        return _render(await tools.get_test(pa, test_id))
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest servers/projectachilles-mcp/tests/test_server_registration.py -q`
Expected: PASS.

- [ ] **Step 5: Lint/type-check**

Run: `uv run ruff check servers/projectachilles-mcp && uv run mypy servers/projectachilles-mcp`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add servers/projectachilles-mcp/f0_projectachilles_mcp/server.py servers/projectachilles-mcp/tests/test_server_registration.py
git commit -m "feat(projectachilles): register find_tests + get_test (6->8 tools)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Va1ncSUtqQJyetofn2mJem"
```

---

### Task 4: Eval tasks

**Files:**
- Modify: `evals/projectachilles/tasks.yaml` (append tasks)

**Interfaces:**
- Consumes: the registered tool names `find_tests`, `get_test`.
- Produces: eval coverage for both new tools (enforced by `evals/test_eval_coverage.py`).

- [ ] **Step 1: Add the eval tasks**

Append to `evals/projectachilles/tasks.yaml`:

```yaml
- prompt: "How many ProjectAchilles tests do we have for technique T1110?"
  expect_tool: find_tests
  expect_args: { by: technique, value: T1110 }

- prompt: "Do we have any tests for threat actor APT29?"
  expect_tool: find_tests
  expect_args: { by: actor, value: APT29 }

- prompt: "List our cyber-hygiene control checks in the catalog."
  expect_tool: find_tests
  expect_args: { by: category, value: cyber-hygiene }

- prompt: "What does the Kerberoast test cover?"
  expect_tool: get_test
```

- [ ] **Step 2: Verify the coverage test passes**

Run: `uv run pytest evals/test_eval_coverage.py -q`
Expected: PASS (every PA tool, including the two new ones, has ≥1 task).

- [ ] **Step 3: Commit**

```bash
git add evals/projectachilles/tasks.yaml
git commit -m "test(evals): add catalog find_tests/get_test tasks for ProjectAchilles

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Va1ncSUtqQJyetofn2mJem"
```

---

### Task 5: Live smoke script extension

**Files:**
- Modify: `scripts/live_smoke_projectachilles.py` (add the two catalog calls)

**Interfaces:**
- Consumes: `tools.find_tests`, `tools.get_test`.
- Produces: live-reachability coverage for the catalog endpoints (run manually by the operator against the tenant — USER-GATED).

- [ ] **Step 1: Add the catalog calls to the smoke run**

In `scripts/live_smoke_projectachilles.py`, add these two entries to the `for label, coro in [ ... ]` list, after the `("get_fleet_health", tools.get_fleet_health(pa))` line:

```python
            # Catalog reads — the FIRST of these confirms /browser/tests auth
            # reachability with the pa_ key (the top live-validation risk).
            (
                "find_tests(technique=T1110)",
                tools.find_tests(pa, by="technique", value="T1110", limit=5),
            ),
            ("find_tests(actor=APT29)", tools.find_tests(pa, by="actor", value="APT29", limit=5)),
```

- [ ] **Step 2: Verify the script still parses/imports (offline)**

Run: `uv run python -c "import ast, pathlib; ast.parse(pathlib.Path('scripts/live_smoke_projectachilles.py').read_text())" && echo OK`
Expected: `OK`. (The live run itself is user-gated — do not execute against the tenant here.)

- [ ] **Step 3: Lint**

Run: `uv run ruff check scripts/live_smoke_projectachilles.py`
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add scripts/live_smoke_projectachilles.py
git commit -m "test(smoke): exercise find_tests catalog reads (auth reachability first)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Va1ncSUtqQJyetofn2mJem"
```

> **USER-GATED LIVE VALIDATION (not an executable task).** After Task 5, the operator runs `uv run python scripts/live_smoke_projectachilles.py` against the tenant (on pi) with a real `.env.projectachilles`. The first assertion to watch is `/browser/tests` **auth reachability** with the `pa_` key. If PA rejects it (401/403) or field names differ from `TestMetadata` (`target`, `threatActor`, `techniques`, `tactics`, `tags`, `stageCount`), fix forward — adjust `_tests`/`_test_evidence`/`_test_detail_finding` and re-run the contract tests. The offline tasks below (skill, docs) do not depend on live shapes and may proceed in parallel.

---

### Task 6: `explore-test-catalog` skill

**Files:**
- Create: `skills/projectachilles/explore-test-catalog/SKILL.md`
- Test: `skills/test_skills_valid.py` (existing — run it, do not edit)

**Interfaces:**
- Consumes: tool base names `find_tests`, `get_test`.
- Produces: a portable agentskills.io skill (valid frontmatter, ≤60-char description).

- [ ] **Step 1: Write the skill**

Create `skills/projectachilles/explore-test-catalog/SKILL.md`:

```markdown
---
name: explore-test-catalog
description: Explore the ProjectAchilles test catalog by technique/actor
version: 1.0.0
metadata:
  hermes:
    tags: [security, projectachilles, catalog, mitre, threat-intel]
    category: security
---

# Explore the ProjectAchilles Test Catalog

## When to Use

The user wants to know **what tests exist** — e.g. "how many tests do we have for
T1110", "do we have anything for APT29", "list our cyber-hygiene checks", "what
does the Kerberoast test do". Uses the **f0_sectools ProjectAchilles** MCP server
(read-only). This is the **library of what can be run** — not run history (that's
`list_test_executions`).

## Tools

Base tool names (runtime may prefix — see the ProjectAchilles server README):
`find_tests`, `get_test`. Read-only.

## Procedure

1. Pick the dimension the user is asking about and call `find_tests` with the
   matching `by`: `technique` (e.g. T1110), `actor` (e.g. APT29), `tactic`
   (e.g. TA0006), `category` (intel-driven / mitre-top10 / cyber-hygiene /
   phase-aligned), `tag`, or `keyword` for free text.
2. Read the **leading summary finding** for the exact match count — it is correct
   even when the per-test list is capped at `limit`. Report that count directly.
3. To explain a specific test, call `get_test` with its uuid (from a `find_tests`
   result) or its exact name — it returns the description, OS/target, complexity,
   tactics, tags, and MITRE techniques.

## Discipline (small local models)

- One tool at a time; report only the tests returned.
- Lead with the count from the summary finding; don't re-count the truncated list.
- Relay any `posture` finding (auth / permission / API unavailable) plainly.

## Pitfalls

- **Catalog ≠ history.** A `find_tests` result means the test *exists in the
  library*, not that it was ever run. For "what did we run / block", use
  `list_test_executions`.
- If `get_test` says "specify by uuid", the name was ambiguous — pick the uuid
  from the listed candidates and call again.
- Don't invent techniques, actors, or tests not present in a finding.

## Verification

Each reported test maps to a `find_tests` per-test finding (or a `get_test`
detail finding); the count comes from the summary finding's `total_matches`.
```

- [ ] **Step 2: Verify the skill validates**

Run: `uv run pytest skills/test_skills_valid.py -q`
Expected: PASS (valid frontmatter; description is 49 chars ≤ 60).

- [ ] **Step 3: Commit**

```bash
git add skills/projectachilles/explore-test-catalog/SKILL.md
git commit -m "feat(skills): add explore-test-catalog ProjectAchilles skill

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Va1ncSUtqQJyetofn2mJem"
```

---

### Task 7: Docs (tool counts + workflow)

**Files:**
- Modify: `README.md` (PA row 6→8; registered total 36→38; skills 20→21; scorecard pending-list)
- Modify: `CLAUDE.md` (PA skills list + adjust the 20→21 skills count if present)
- Modify: `docs/user-guide/workflows.md` (one PA catalog workflow section)

**Interfaces:**
- Consumes: nothing (documentation).
- Produces: accurate tool/skill counts and a discoverable catalog workflow.

> **Verified controller note (the numbers were checked against the live docs — use these exact values, do NOT re-derive from the spec's "34→36" which was wrong):** the current README says **36 registered tools** (line ~24) and the PA table row is **6** (line ~20). The two new catalog tools make registered = **38**. Separately, the scorecard sentence (line ~38) says "**34 tools registered at once**" — that 34 is the SCORECARD number and STAYS 34; `find_tests`/`get_test` are new and unevaluated, so they join the "pending their scorecard pass" parenthetical. Adding the skill takes the skills count **20 → 21**.

- [ ] **Step 1: Confirm the exact current strings**

Run:
```bash
grep -n "registered tools\|portable\|agentskills.io skills" README.md
grep -n "f0-projectachilles-mcp" README.md
grep -n "34 tools registered at once" README.md
grep -n "projectachilles/{defense-posture-review" CLAUDE.md
grep -rn "ProjectAchilles" docs/user-guide/README.md | head
```
Expected: README line ~20 PA row shows `| 6 |`; line ~24 shows `**36 registered tools.**` and `20 portable ... skills`; line ~38 shows `34 tools registered at once`; CLAUDE.md line ~169 has the PA skills set; user-guide has PA workflows but no catalog line.

- [ ] **Step 2: Update the README PA row + capabilities (line ~20)**

Change the `f0-projectachilles-mcp` table row from `| 6 |` to `| 8 |`, and extend its capability list to include the catalog reads. Example (match the existing column formatting exactly):
`| \`f0-projectachilles-mcp\` | ✅ live-validated | 8 | defense score, weak techniques, test executions, risk acceptances, agents, fleet health, test-catalog search, test detail |`

- [ ] **Step 3: Update the README totals (line ~24)**

Change `**36 registered tools.**` to `**38 registered tools.**`, and `20 portable [agentskills.io](https://agentskills.io) skills` to `21 portable [agentskills.io](https://agentskills.io) skills`. Change nothing else on that line.

- [ ] **Step 4: Update the README scorecard parenthetical (line ~38) — keep 34**

Do NOT change the number `34` in "all **34 tools registered at once**". Only extend the pending-tools parenthetical so the two new PA tools are listed as pending their scorecard pass. Change:
`(the new Tenable \`list_vulnerability_assets\` and Defender \`hunt\` tools are pending their scorecard pass)`
to:
`(the new Tenable \`list_vulnerability_assets\`, Defender \`hunt\`, and ProjectAchilles \`find_tests\`/\`get_test\` tools are pending their scorecard pass)`

- [ ] **Step 5: Update CLAUDE.md (line ~169)**

In the "Current skills" enumeration, change the ProjectAchilles set from `projectachilles/{defense-posture-review,coverage-gap-analysis,validation-fleet-review}` to `projectachilles/{defense-posture-review,coverage-gap-analysis,validation-fleet-review,explore-test-catalog}`. If CLAUDE.md states a total skills count of 20 anywhere, bump it to 21; if it names a PA read-tool count of 6, bump it to 8. Do not touch other servers' entries.

- [ ] **Step 6: Update the user guide**

The user-guide workflows live in `docs/user-guide/workflows.md` as `## Title (persona)` sections (a `> **Prompt:** "..."` line + a descriptive paragraph), NOT bullets. Insert a new section immediately AFTER the "ProjectAchilles validation fleet" section (i.e. after its paragraph ending "…the risks formally accepted.") and BEFORE "## Intune device compliance":

```markdown
## ProjectAchilles test catalog (detection engineer / threat hunter)

> **Prompt:** "How many ProjectAchilles tests do we have for T1110, and what does the Kerberoast test cover?"

The `explore-test-catalog` skill uses `find_tests` (by technique, actor, tactic,
category, tag, or keyword) to enumerate the available tests — the library of what
*can* be run, not run history — and `get_test` for one test's full detail
(description, OS/target, techniques, tactics). Lead with the exact match count
from the summary finding.
```

- [ ] **Step 7: Verify counts are consistent**

Run:
```bash
grep -n "38 registered tools\|21 portable" README.md
grep -n "34 tools registered at once" README.md   # must STILL be present (unchanged)
grep -n "explore-test-catalog" CLAUDE.md
uv run pytest skills/test_skills_valid.py -q
```
Expected: README shows `38 registered tools` and `21 portable`; the `34 tools registered at once` line is still present unchanged; CLAUDE.md lists `explore-test-catalog`; skills valid.

- [ ] **Step 8: Commit**

```bash
git add README.md CLAUDE.md docs/user-guide/workflows.md
git commit -m "docs: ProjectAchilles catalog tools (find_tests/get_test), 36->38 registered

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Va1ncSUtqQJyetofn2mJem"
```

---

## Final verification (before finishing the branch)

- [ ] Full suite green: `uv run pytest -q`
- [ ] Lint + types clean: `uv run ruff check . && uv run mypy core servers`
- [ ] No real `.env` staged: `git status --porcelain | grep -i "\.env" || echo "clean"`
- [ ] PA server at 8 tools (`test_server_registration.py`); no `core/` change in the diff (`git diff --stat main..HEAD -- core/` is empty).
- [ ] Roadmap intact: sub-project B (gated writes) still deferred; nothing in this branch changes state on a platform.
- [ ] Then use **superpowers:finishing-a-development-branch** (tests already verified) and present push/PR options — **push is USER-GATED**.

## Notes for the executor

- **Do not run the live smoke against the tenant** and **do not `git push`** — both are user-gated.
- If live validation reveals the `pa_` key cannot reach `/api/browser/*`, STOP and surface it — the fallback (CLI Clerk-JWT via stored refresh token) is a design change that needs the user, not a fix-forward.
- Keep `find_tests` at three flat args; if tempted to add filters (severity, multi-dimension), that is scope creep against the spec's small-model constraint — don't.
