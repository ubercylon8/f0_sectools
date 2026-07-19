# PA fleet status & cancel — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give a fleet (tagged) test run a first-class identity after launch: scope executions results to a run (kills the phantom host), sweep task lifecycle in one call, and bulk-cancel a run's tasks in one gated call.

**Architecture:** Three changes across the two existing PA servers. The read server's `list_test_executions` gains `test`/`tag`/`hostname` scoping (uses the backend's real `?tests=/?tags=/?hostnames=` filters). The actions server gains a read `list_tasks` (`GET /admin/tasks`) and renames+widens `cancel_task` → gated `cancel_tasks` (single `task_id` XOR a `status`/`search` filter; bulk cancel loops per-task inside the tool under one count-bound confirmation, since PA has no batch-cancel endpoint).

**Tech Stack:** Python 3.11+, `mcp` FastMCP, `httpx`, `respx` (actions tests) / hand-rolled `FakeClient` (read tests), `pytest`, `ruff`, strict `mypy`. Shared `core/` (findings schema, `redact_obj`, `map_pa_error`, `core/gating`).

**Spec:** `docs/superpowers/specs/2026-07-19-pa-fleet-status-cancel-design.md` (commit `ecc38ad`).

## Global Constraints

- **No new safety machinery** — route everything through existing `core/`: `map_pa_error(e, capability)` (every failure → finding, never exception), `_render` → `redact_obj(f.model_dump())` at the server boundary (incl. error paths), `core/gating` `GatedAction` for the write.
- **Actions server tool count 6 → 7**: add `list_tasks`, rename `cancel_task` → `cancel_tasks`; `get_task_status` stays. Under the ≤~8 ceiling.
- **`cancel_tasks` gated action name** = `projectachilles.cancel_tasks`.
- **Flat scalar args only**; `status` is a closed enum via `Literal`; `cancel_tasks` uses the `run_test` XOR pattern (single `task_id` xor filter → both/neither = pre-gate guidance, no token burned).
- **Count-bound confirmation** for bulk: target `f"cancel:{status}:{search or '*'}:{N}"`, whole-string compared (never split on `:`). Re-resolved on every call → drift auto-refused, **no `core/gating` change**.
- **200 hard cap** on bulk cancel; enumerate at `limit=201` and decide on response `total` (coerce to usable int, else `len(tasks) >= 200`) so a non-int `total` can't bypass it and `N` is never a truncated page.
- **Chat-confirm allowed** for `cancel_tasks` (count-bound); low-harm/reversible, not in the never-chat-confirm list.
- **`?tests=` name-vs-UUID is a live-validation checkpoint** — pass the caller's identifier through; do not hard-code a mapping. Pin live, document.
- **No regression**: empty scoping params on `list_test_executions` ⇒ payload byte-identical to today.
- **Commit trailers** on every commit:
  ```
  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01Va1ncSUtqQJyetofn2mJem
  ```
- **Do not push.** Commit locally; surface hashes; wait for explicit push instruction.

---

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `servers/projectachilles-mcp/f0_projectachilles_mcp/tools.py` | `list_test_executions` gains scoping params + charset guard | 1 |
| `servers/projectachilles-mcp/f0_projectachilles_mcp/server.py` | wrapper params + description | 1 |
| `servers/projectachilles-mcp/tests/test_tools.py` | scoping + phantom-host tests | 1 |
| `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py` | `list_tasks` (T2); `cancel_task`→`cancel_tasks` (T3) | 2,3 |
| `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/server.py` | `list_tasks` wrapper (T2); `cancel_tasks` wrapper (T3) | 2,3 |
| `servers/projectachilles-actions-mcp/tests/test_list_tasks.py` | `list_tasks` tests (new file) | 2 |
| `servers/projectachilles-actions-mcp/tests/test_cancel_tasks.py` | `cancel_tasks` tests (new file, replaces cancel half of `test_schedule_status_and_cancel.py`) | 3 |
| `servers/projectachilles-actions-mcp/tests/test_schedule_status_and_cancel.py` | drop cancel tests, keep set_schedule_status → rename to `test_schedule_status.py` | 3 |
| `servers/projectachilles-actions-mcp/tests/test_server_registration.py` | 6→7 tool set (T2 adds `list_tasks`; T3 renames) | 2,3 |
| `evals/projectachilles/tasks.yaml`, `evals/projectachilles-actions/tasks.yaml`, `evals/test_combined.py` | eval tasks + counts | 4 |
| `README.md`, `CLAUDE.md`, both server READMEs, `skills/.../run-validation-test/SKILL.md`, `docs/user-guide/README.md`, both smoke scripts | docs + smoke probes | 4 |

---

## Task 1: Read-side executions scoping (phantom-host fix)

**Files:**
- Modify: `servers/projectachilles-mcp/f0_projectachilles_mcp/tools.py` (`list_test_executions`, ~line 391; add `_SCOPE_RE` near the other module regexes ~line 72)
- Modify: `servers/projectachilles-mcp/f0_projectachilles_mcp/server.py` (`list_test_executions` wrapper ~line 54)
- Test: `servers/projectachilles-mcp/tests/test_tools.py`

**Interfaces:**
- Produces: `list_test_executions(pa, days=7, limit=25, test="", tag="", hostname="") -> list[Finding]`
- Consumes: existing `_rows`, `_window`, `guidance`-equivalent (read server uses inline `Finding` for guidance — see Step 3).

- [ ] **Step 1: Write failing tests**

Add to `servers/projectachilles-mcp/tests/test_tools.py` (FakeClient records `pa.calls`):

```python
@pytest.mark.asyncio
async def test_list_test_executions_scoping_params_passed_through():
    pa = FakeClient(responses={"/analytics/executions/paginated": {"data": []}})
    await tools.list_test_executions(pa, test="Kerberoast", tag="windows", hostname="dc-01")
    _, params = pa.calls[0]
    assert params.get("tests") == "Kerberoast"
    assert params.get("tags") == "windows"
    assert params.get("hostnames") == "dc-01"


@pytest.mark.asyncio
async def test_list_test_executions_no_scope_is_unchanged():
    pa = FakeClient(responses={"/analytics/executions/paginated": {"data": []}})
    await tools.list_test_executions(pa)
    _, params = pa.calls[0]
    for k in ("tests", "tags", "hostnames"):
        assert k not in params  # empty params omitted -> byte-identical to today


@pytest.mark.asyncio
async def test_list_test_executions_scope_excludes_other_hosts():
    # Phantom-host repro: caller scopes to test X; the endpoint (filtered) returns
    # only X's host. The tool must not invent or leak an unrelated host.
    pa = FakeClient(responses={"/analytics/executions/paginated": {"data": [
        {"test_name": "Kerberoast", "hostname": "dc-01", "is_protected": False,
         "severity": "high", "techniques": ["T1558.003"]},
    ], "pagination": {"totalItems": 1}}})
    findings = await tools.list_test_executions(pa, test="Kerberoast")
    hosts = {f.entity.name for f in findings if f.entity}
    assert hosts == {"dc-01"}


@pytest.mark.asyncio
async def test_list_test_executions_rejects_bad_scope_charset():
    pa = FakeClient(responses={"/analytics/executions/paginated": {"data": []}})
    findings = await tools.list_test_executions(pa, test="bad\nvalue")
    assert findings[0].finding_type.value == "posture"
    assert "scope" in findings[0].title.lower() or "character" in findings[0].title.lower()
    assert pa.calls == []  # rejected pre-request
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd servers/projectachilles-mcp && uv run pytest tests/test_tools.py -k scop -v`
Expected: FAIL (unexpected keyword `test`/`tag`/`hostname`).

- [ ] **Step 3: Implement**

In `tools.py`, add near the other regexes (after `_UUID_RE`, ~line 72):

```python
# Scoping values (test name/uuid, tag, hostname) — bounded, printable, no
# control chars. Permissive enough for test names with spaces; strict enough
# to reject newlines/garbage before they hit the query string.
_SCOPE_RE = re.compile(r"^[A-Za-z0-9 ._:@/\-]{1,128}$")


def _scope_guidance(field: str, value: str) -> Finding:
    return Finding(
        source="projectachilles",
        finding_type=FindingType.posture,
        severity=Severity.info,
        title=f"Invalid scope: {field} contains unsupported characters",
        evidence=[Evidence(key=field, value=value[:64])],
        recommended_action=RecommendedAction(
            summary=f"Pass a plain {field} (letters, digits, spaces, . _ - : @ /).",
        ),
    )
```

Change the signature and add the filters (replace the `async def list_test_executions(...)` header and the `params=` block):

```python
async def list_test_executions(
    pa: Any, days: int = 7, limit: int = 25,
    test: str = "", tag: str = "", hostname: str = "",
) -> list[Finding]:
    frm, to = _window(days)
    for field, value in (("test", test), ("tag", tag), ("hostname", hostname)):
        if value and not _SCOPE_RE.match(value):
            return [_scope_guidance(field, value)]
    params: dict[str, Any] = {
        "from": frm,
        "to": to,
        "pageSize": limit,
        "sortField": "routing.event_time",
        "sortOrder": "desc",
    }
    if test:
        params["tests"] = test          # ?tests= — name or UUID (live-validate)
    if tag:
        params["tags"] = tag
    if hostname:
        params["hostnames"] = hostname
    try:
        d = await pa.get("/analytics/executions/paginated", params=params)
    except Exception as e:
        finding = map_pa_error(e, "ProjectAchilles test executions")
        if finding:
            return [finding]
        raise
    # ... rest of the function is UNCHANGED (rows = _rows(d)[:limit] onward) ...
```

Leave everything from `rows = _rows(d)[:limit]` to the end exactly as it is.

In `server.py`, update the wrapper (~line 54):

```python
@mcp.tool()
async def list_test_executions(
    days: int = 7, limit: int = 25,
    test: str = "", tag: str = "", hostname: str = "",
) -> list[dict[str, Any]]:
    """Recent test executions per host. Two kinds (see the `check_kind` evidence):
    attack simulations — blocked vs NOT blocked; and cyber-hygiene control checks —
    passed vs not passed. Bundle runs roll up into one per-run COMPLIANT/NON-COMPLIANT
    finding (X/Y controls). Pass `test` (and/or `tag`/`hostname`) to scope results to
    ONE run instead of a raw time window (avoids unrelated hosts appearing)."""
    async with _client() as pa:
        return _render(await tools.list_test_executions(pa, days, limit, test, tag, hostname))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd servers/projectachilles-mcp && uv run pytest tests/test_tools.py -v`
Expected: PASS (all, including the pre-existing ones — no regression).

- [ ] **Step 5: Commit**

```bash
git add servers/projectachilles-mcp/f0_projectachilles_mcp/tools.py \
        servers/projectachilles-mcp/f0_projectachilles_mcp/server.py \
        servers/projectachilles-mcp/tests/test_tools.py
git commit -F - <<'EOF'
feat(projectachilles): scope list_test_executions by test/tag/hostname

Adds test/tag/hostname scoping params mapping to the backend's real
?tests=/?tags=/?hostnames= filters, so results can be scoped to one run
instead of a tenant-wide time window (fixes the phantom-host leak).
Empty params -> payload byte-identical to today. Scope values are
charset-guarded pre-request.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Va1ncSUtqQJyetofn2mJem
EOF
```

---

## Task 2: Actions read — `list_tasks`

**Files:**
- Modify: `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py` (add `list_tasks` + `_TASK_STATUS` constant)
- Modify: `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/server.py` (add `@mcp.tool` wrapper)
- Modify: `servers/projectachilles-actions-mcp/tests/test_server_registration.py` (add `list_tasks` to the set; keep `cancel_task` for now)
- Test: `servers/projectachilles-actions-mcp/tests/test_list_tasks.py` (new)

**Interfaces:**
- Produces: `list_tasks(pa, status="", search="", limit=25) -> list[Finding]`; module constant `_TASK_STATUS = {"pending","assigned","running","completed","failed","expired"}`.
- Consumes: existing `_as_dict` (tools.py ~line 579), `map_pa_error`, `guidance`.

- [ ] **Step 1: Write failing tests**

Create `servers/projectachilles-actions-mcp/tests/test_list_tasks.py`:

```python
"""list_tasks read-tool tests."""
from __future__ import annotations

import json

import httpx
import pytest
import respx
from f0_pa_actions_mcp.client import ProjectAchillesClient
from f0_pa_actions_mcp.tools import list_tasks
from f0_sectools_core.auth.config import ProjectAchillesConfig

BASE = "https://org.agent.example.com"


def _cfg() -> ProjectAchillesConfig:
    return ProjectAchillesConfig(base_url=BASE, api_key="pa_test", allow_write=True)


def _tasks_response(tasks, total):
    return httpx.Response(200, json={"success": True, "data": {"tasks": tasks, "total": total}})


@pytest.mark.asyncio
async def test_list_tasks_returns_summary_and_per_task():
    tasks = [
        {"id": "t1", "status": "pending", "agent_hostname": "web-01",
         "payload": {"test_name": "Kerberoast"}, "created_at": "2026-07-19T10:00:00Z"},
        {"id": "t2", "status": "running", "agent_hostname": "web-02",
         "payload": {"test_name": "Kerberoast"}, "created_at": "2026-07-19T10:00:01Z"},
    ]
    with respx.mock as router:
        route = router.get(f"{BASE}/api/agent/admin/tasks").mock(
            return_value=_tasks_response(tasks, 2))
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await list_tasks(pa, status="", search="", limit=25)
    assert route.called
    # First finding is the summary; then one per task.
    assert "2" in findings[0].title
    titles = [f.title for f in findings[1:]]
    assert "Kerberoast on web-01: pending" in titles
    assert "Kerberoast on web-02: running" in titles


@pytest.mark.asyncio
async def test_list_tasks_passes_status_and_search():
    with respx.mock as router:
        route = router.get(f"{BASE}/api/agent/admin/tasks").mock(
            return_value=_tasks_response([], 0))
        async with ProjectAchillesClient(_cfg()) as pa:
            await list_tasks(pa, status="pending", search="web-01", limit=10)
    sent = route.calls[0].request.url
    assert "status=pending" in str(sent)
    assert "search=web-01" in str(sent)
    assert "limit=10" in str(sent)


@pytest.mark.asyncio
async def test_list_tasks_empty_is_clean():
    with respx.mock as router:
        router.get(f"{BASE}/api/agent/admin/tasks").mock(
            return_value=_tasks_response([], 0))
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await list_tasks(pa)
    assert len(findings) == 1  # summary only, no error
    assert findings[0].finding_type.value == "posture"


@pytest.mark.asyncio
async def test_list_tasks_permission_error_is_finding():
    with respx.mock as router:
        router.get(f"{BASE}/api/agent/admin/tasks").mock(
            return_value=httpx.Response(403, json={"error": "forbidden"}))
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await list_tasks(pa)
    assert findings[0].finding_type.value in ("posture", "misconfig")
    assert "permission" in (findings[0].title + findings[0].recommended_action.summary).lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd servers/projectachilles-actions-mcp && uv run pytest tests/test_list_tasks.py -v`
Expected: FAIL (`cannot import name 'list_tasks'`).

- [ ] **Step 3: Implement**

In `tools.py`, add the status set near `_ID_RE` (~line 37):

```python
_TASK_STATUS = {"pending", "assigned", "running", "completed", "failed", "expired"}
```

Add the tool (place it near the other admin reads, after `list_schedules`):

```python
async def list_tasks(
    pa: Any, status: str = "", search: str = "", limit: int = 25
) -> list[Finding]:
    """List admin tasks with their lifecycle status (read). One call, N per-host
    rows — the fleet-aware alternative to N get_task_status calls."""
    if status and status not in _TASK_STATUS:
        return [guidance(
            f"status '{status}' is not a task state",
            "Use one of: " + ", ".join(sorted(_TASK_STATUS)) + " (or omit for all).",
        )]
    params: dict[str, Any] = {"limit": limit}
    if status:
        params["status"] = status
    if search:
        params["search"] = search
    try:
        resp = await pa.get("/agent/admin/tasks", params=params)
    except ProjectAchillesError as e:
        finding = map_pa_error(e, "ProjectAchilles tasks")
        if finding:
            return [finding]
        raise
    data = _as_dict(resp.get("data") if isinstance(resp, dict) else None)
    tasks = data.get("tasks") or []
    total = data.get("total")
    total_str = str(total if isinstance(total, int) and not isinstance(total, bool) else len(tasks))

    counts: dict[str, int] = {}
    for t in tasks:
        if isinstance(t, dict):
            s = str(t.get("status", "unknown"))
            counts[s] = counts.get(s, 0) + 1
    breakdown = ", ".join(f"{v} {k}" for k, v in sorted(counts.items())) or "none"

    out: list[Finding] = [Finding(
        source=_SOURCE,
        finding_type=FindingType.posture,
        severity=Severity.info,
        title=f"Tasks: {total_str} match ({breakdown} shown)",
        evidence=[
            Evidence(key="total", value=total_str),
            Evidence(key="shown", value=str(len(tasks))),
        ],
    )]
    for t in tasks[:limit]:
        if not isinstance(t, dict):
            continue
        host = str(t.get("agent_hostname") or "")
        name = str(_as_dict(t.get("payload")).get("test_name") or "test")
        st = str(t.get("status") or "unknown")
        ent = Entity(kind=EntityKind.host, id=host, name=host) if host else None
        out.append(Finding(
            source=_SOURCE,
            finding_type=FindingType.posture,
            severity=Severity.info,
            title=f"{name} on {host}: {st}",
            entity=ent,
            evidence=[
                Evidence(key="task_id", value=str(t.get("id", ""))),
                Evidence(key="status", value=st),
                Evidence(key="hostname", value=host),
                Evidence(key="created_at", value=str(t.get("created_at") or "")),
            ],
        ))
    return out
```

In `server.py`, add near `get_task_status` (import `Literal` if not already imported at top):

```python
@mcp.tool()
async def list_tasks(
    status: Literal["", "pending", "assigned", "running", "completed", "failed", "expired"] = "",
    search: str = "",
    limit: int = 25,
) -> list[dict[str, Any]]:
    """List ProjectAchilles test tasks and their lifecycle status (read).

    status filters by task state; search matches test name or hostname. One call
    returns all matching tasks (N per-host rows) — use instead of calling
    get_task_status once per task."""
    cfg = ProjectAchillesConfig.from_env()
    async with ProjectAchillesClient(cfg) as pa:
        return _render(await tools.list_tasks(pa, status, search, limit))
```

- [ ] **Step 4: Update registration test**

In `tests/test_server_registration.py`, change the expected set (still 7-with-`cancel_task`, `list_tasks` added):

```python
async def test_exactly_seven_tools_registered():
    tools = await server.mcp.list_tools()
    assert {t.name for t in tools} == {
        "run_test", "schedule_test", "set_schedule_status",
        "cancel_task", "list_schedules", "get_task_status", "list_tasks",
    }
```

(Rename the function from `test_exactly_six_tools_registered`.) Add an enum check:

```python
@pytest.mark.asyncio
async def test_list_tasks_status_enum_closed():
    tools = {t.name: t for t in await server.mcp.list_tools()}
    props = tools["list_tasks"].inputSchema["properties"]
    assert set(props["status"]["enum"]) == {
        "", "pending", "assigned", "running", "completed", "failed", "expired",
    }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd servers/projectachilles-actions-mcp && uv run pytest tests/test_list_tasks.py tests/test_server_registration.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py \
        servers/projectachilles-actions-mcp/f0_pa_actions_mcp/server.py \
        servers/projectachilles-actions-mcp/tests/test_list_tasks.py \
        servers/projectachilles-actions-mcp/tests/test_server_registration.py
git commit -F - <<'EOF'
feat(pa-actions): add list_tasks read tool (fleet task-status sweep)

GET /admin/tasks with status/search filters -> one info finding per task
plus a summary count, bounded at limit. Replaces N get_task_status calls
for a multi-host run. Tool count 6 -> 7.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Va1ncSUtqQJyetofn2mJem
EOF
```

---

## Task 3: Actions gated — `cancel_task` → `cancel_tasks` (single XOR filter, bulk)

**Files:**
- Modify: `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py` (rename `cancel_task`→`cancel_tasks`, new logic; add `_SCOPE_RE`, `_MAX_CANCEL`)
- Modify: `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/server.py` (wrapper rename + new params + gate name `projectachilles.cancel_tasks`)
- Modify: `servers/projectachilles-actions-mcp/tests/test_server_registration.py` (`cancel_task`→`cancel_tasks`)
- Modify: `servers/projectachilles-actions-mcp/tests/test_schedule_status_and_cancel.py` → rename to `test_schedule_status.py`, drop the cancel tests (moved to new file)
- Test: `servers/projectachilles-actions-mcp/tests/test_cancel_tasks.py` (new)

**Interfaces:**
- Produces: `cancel_tasks(pa, gate, task_id="", status="pending", search="", confirmation_token="", actor="mcp-operator") -> list[Finding]`; constants `_MAX_CANCEL = 200`, `_SCOPE_RE`.
- Consumes: `_TASK_STATUS` (defined in Task 2), `_as_dict` (tools.py); `GatedAction` (`has_approval`, `record_request`, `execute_async`, `.name`, `.confirm_mode`), `_intent`, `_refusal`, `_after_gate_error`, `guidance`, `_ID_RE`, `map_pa_error`, `ProjectAchillesError` (has `.status`).

- [ ] **Step 1: Write failing tests**

Create `servers/projectachilles-actions-mcp/tests/test_cancel_tasks.py`:

```python
"""cancel_tasks: single (task_id) + bulk (status/search) gated cancel."""
from __future__ import annotations

import httpx
import pytest
import respx
from f0_pa_actions_mcp.client import ProjectAchillesClient
from f0_pa_actions_mcp.tools import cancel_tasks
from f0_sectools_core.auth.config import ProjectAchillesConfig
from f0_sectools_core.gating.actions import ApprovalStore, AuditLog, GatedAction, TokenStore

BASE = "https://org.agent.example.com"


def _cfg() -> ProjectAchillesConfig:
    return ProjectAchillesConfig(base_url=BASE, api_key="pa_test", allow_write=True)


def _gate(tmp_path, enabled: bool = True, confirm_mode: str = "token") -> GatedAction:
    return GatedAction(
        "projectachilles.cancel_tasks",
        enabled=enabled,
        audit=AuditLog(str(tmp_path / "audit.log")),
        token_store=TokenStore(str(tmp_path / "pending")),
        approvals=ApprovalStore(str(tmp_path / "gating")),
        confirm_mode=confirm_mode,
    )


def _tasks(ids, status="pending"):
    return httpx.Response(200, json={"success": True, "data": {
        "tasks": [{"id": i, "status": status, "agent_hostname": f"h-{i}",
                   "payload": {"test_name": "X"}} for i in ids],
        "total": len(ids)}})


# --- single mode --------------------------------------------------------------

@pytest.mark.asyncio
async def test_single_no_token_returns_intent_no_call(tmp_path):
    with respx.mock(assert_all_called=False) as router:
        cancel = router.post(f"{BASE}/api/agent/admin/tasks/t1/cancel")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await cancel_tasks(pa, _gate(tmp_path), task_id="t1")
    assert cancel.called is False
    assert "Pending action" in findings[0].title
    assert "t1" in findings[0].recommended_action.summary


@pytest.mark.asyncio
async def test_single_with_token_cancels(tmp_path):
    gate = _gate(tmp_path)
    store = TokenStore(str(tmp_path / "pending"))
    token = store.issue("projectachilles.cancel_tasks", "t1")
    with respx.mock as router:
        cancel = router.post(f"{BASE}/api/agent/admin/tasks/t1/cancel").mock(
            return_value=httpx.Response(200, json={"success": True, "data": {"status": "expired"}}))
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await cancel_tasks(pa, gate, task_id="t1", confirmation_token=token)
    assert cancel.called
    assert "completed" in findings[0].title.lower()


# --- XOR validation -----------------------------------------------------------

@pytest.mark.asyncio
async def test_both_task_id_and_search_is_guidance(tmp_path):
    async with ProjectAchillesClient(_cfg()) as pa:
        findings = await cancel_tasks(pa, _gate(tmp_path), task_id="t1", search="web")
    assert "task_id" in findings[0].title.lower() or "either" in findings[0].recommended_action.summary.lower()


# --- bulk mode ----------------------------------------------------------------

@pytest.mark.asyncio
async def test_bulk_no_token_intent_counts_matches(tmp_path):
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/api/agent/admin/tasks").mock(return_value=_tasks(["t1", "t2", "t3"]))
        cancel = router.post(url__regex=rf"{BASE}/api/agent/admin/tasks/.+/cancel")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await cancel_tasks(pa, _gate(tmp_path), status="pending")
    assert cancel.called is False
    assert "cancel:pending:*:3" in findings[0].recommended_action.summary


@pytest.mark.asyncio
async def test_bulk_drift_refuses_stale_token(tmp_path):
    # Token issued for N=3; fleet shrinks to N=2 before execute -> target mismatch.
    gate = _gate(tmp_path)
    store = TokenStore(str(tmp_path / "pending"))
    token = store.issue("projectachilles.cancel_tasks", "cancel:pending:*:3")
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/api/agent/admin/tasks").mock(return_value=_tasks(["t1", "t2"]))
        cancel = router.post(url__regex=rf"{BASE}/api/agent/admin/tasks/.+/cancel")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await cancel_tasks(pa, gate, status="pending", confirmation_token=token)
    assert cancel.called is False           # stale token refused
    assert "not taken" in findings[0].title.lower()
    # The mismatched attempt BURNS the token file (consume unlinks by token hash
    # before checking the target), so re-consuming for its original target fails.
    assert store.consume("projectachilles.cancel_tasks", "cancel:pending:*:3", token) is False


@pytest.mark.asyncio
async def test_bulk_over_cap_refuses(tmp_path):
    over = httpx.Response(200, json={"success": True, "data": {
        "tasks": [{"id": f"t{i}", "status": "pending"} for i in range(201)], "total": 201}})
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/api/agent/admin/tasks").mock(return_value=over)
        cancel = router.post(url__regex=rf"{BASE}/api/agent/admin/tasks/.+/cancel")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await cancel_tasks(pa, _gate(tmp_path), status="pending")
    assert cancel.called is False
    assert "200" in (findings[0].title + findings[0].recommended_action.summary)


@pytest.mark.asyncio
async def test_bulk_over_cap_non_int_total(tmp_path):
    # Non-int total must NOT bypass the cap: fall back to len>=200.
    over = httpx.Response(200, json={"success": True, "data": {
        "tasks": [{"id": f"t{i}", "status": "pending"} for i in range(200)], "total": "lots"}})
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/api/agent/admin/tasks").mock(return_value=over)
        cancel = router.post(url__regex=rf"{BASE}/api/agent/admin/tasks/.+/cancel")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await cancel_tasks(pa, _gate(tmp_path), status="pending")
    assert cancel.called is False


@pytest.mark.asyncio
async def test_bulk_execute_cancels_all_and_tallies(tmp_path):
    gate = _gate(tmp_path)
    store = TokenStore(str(tmp_path / "pending"))
    token = store.issue("projectachilles.cancel_tasks", "cancel:pending:*:3")
    with respx.mock as router:
        router.get(f"{BASE}/api/agent/admin/tasks").mock(return_value=_tasks(["t1", "t2", "t3"]))
        c1 = router.post(f"{BASE}/api/agent/admin/tasks/t1/cancel").mock(
            return_value=httpx.Response(200, json={"success": True, "data": {}}))
        c2 = router.post(f"{BASE}/api/agent/admin/tasks/t2/cancel").mock(
            return_value=httpx.Response(200, json={"success": True, "data": {}}))
        # t3 already terminal -> 409, must not abort the batch
        c3 = router.post(f"{BASE}/api/agent/admin/tasks/t3/cancel").mock(
            return_value=httpx.Response(409, json={"error": "terminal"}))
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await cancel_tasks(pa, gate, status="pending", confirmation_token=token)
    assert c1.called and c2.called and c3.called
    title = findings[0].title
    assert "2" in title  # cancelled 2 of 3


@pytest.mark.asyncio
async def test_bulk_no_undercount_beyond_default_page(tmp_path):
    # 60 matches must all be enumerated (limit=201), not truncated to a 50-page.
    ids = [f"t{i}" for i in range(60)]
    gate = _gate(tmp_path)
    store = TokenStore(str(tmp_path / "pending"))
    token = store.issue("projectachilles.cancel_tasks", "cancel:pending:*:60")
    with respx.mock(assert_all_called=False) as router:
        get = router.get(f"{BASE}/api/agent/admin/tasks").mock(return_value=_tasks(ids))
        router.post(url__regex=rf"{BASE}/api/agent/admin/tasks/.+/cancel").mock(
            return_value=httpx.Response(200, json={"success": True, "data": {}}))
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await cancel_tasks(pa, gate, status="pending", confirmation_token=token)
    assert "limit=201" in str(get.calls[0].request.url)
    assert "60" in findings[0].title


@pytest.mark.asyncio
async def test_disabled_gate_refuses(tmp_path):
    async with ProjectAchillesClient(_cfg()) as pa:
        findings = await cancel_tasks(
            pa, _gate(tmp_path, enabled=False), task_id="t1", confirmation_token="x")
    assert "not taken" in findings[0].title.lower() or "disabled" in (
        findings[0].title + findings[0].recommended_action.summary).lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd servers/projectachilles-actions-mcp && uv run pytest tests/test_cancel_tasks.py -v`
Expected: FAIL (`cannot import name 'cancel_tasks'`).

- [ ] **Step 3: Implement**

In `tools.py`, add constants near `_ID_RE`:

```python
_SCOPE_RE = re.compile(r"^[A-Za-z0-9 ._:@/\-]{1,128}$")
_MAX_CANCEL = 200
```

Replace `cancel_task` (the whole `async def cancel_task(...)` block) with:

```python
async def cancel_tasks(
    pa: Any,
    gate: GatedAction,
    task_id: str = "",
    status: str = "pending",
    search: str = "",
    confirmation_token: str = "",
    actor: str = "mcp-operator",
) -> list[Finding]:
    """Cancel a validation task (gated). Pass EITHER task_id (one task) OR a
    status/search filter (bulk). No token -> intent only."""
    tid = task_id.strip()
    srch = search.strip()

    if tid:
        # --- single mode ---
        if srch:
            return [guidance(
                "pass either task_id or a status/search filter, not both",
                "Give task_id for one task, or status/search for a bulk cancel.",
            )]
        if not _ID_RE.match(tid):
            return [guidance(
                f"task_id '{tid}' contains unsupported characters",
                "Use the id exactly as shown by run_test, list_tasks, or get_task_status.",
            )]
        ids = [tid]
        target = tid
        label = f"task {tid}"
        entity: Entity | None = Entity(kind=EntityKind.rule, id=tid)
    else:
        # --- bulk mode ---
        st = (status or "pending").strip()
        if st not in _TASK_STATUS:
            return [guidance(
                f"status '{st}' is not a task state",
                "Use one of: " + ", ".join(sorted(_TASK_STATUS)) + ".",
            )]
        if srch and not _SCOPE_RE.match(srch):
            return [guidance(
                "search contains unsupported characters",
                "Pass a plain test-name or hostname substring.",
            )]
        params: dict[str, Any] = {"status": st, "limit": _MAX_CANCEL + 1}
        if srch:
            params["search"] = srch
        try:
            resp = await pa.get("/agent/admin/tasks", params=params)
        except ProjectAchillesError as e:
            finding = map_pa_error(e, "ProjectAchilles tasks")
            if finding:
                return [finding]
            raise
        data = _as_dict(resp.get("data") if isinstance(resp, dict) else None)
        rows = [t for t in (data.get("tasks") or []) if isinstance(t, dict) and t.get("id")]
        total = data.get("total")
        usable_total = total if isinstance(total, int) and not isinstance(total, bool) else None
        if (usable_total is not None and usable_total > _MAX_CANCEL) or (
            usable_total is None and len(rows) >= _MAX_CANCEL
        ):
            return [guidance(
                f"filter matches more than {_MAX_CANCEL} tasks",
                "Narrow with search=<test name or hostname>.",
            )]
        ids = [str(t["id"]) for t in rows]
        n = usable_total if usable_total is not None else len(ids)
        target = f"cancel:{st}:{srch or '*'}:{n}"
        label = f"{n} {st} task(s)" + (f" matching '{srch}'" if srch else "")
        entity = Entity(kind=EntityKind.rule, id=target)

    evidence = [
        Evidence(key="scope", value=label),
        Evidence(key="match_count", value=str(len(ids))),
    ]
    for i, x in enumerate(ids[:15]):
        evidence.append(Evidence(key=f"task_{i + 1}", value=x))
    if len(ids) > 15:
        evidence.append(Evidence(key="tasks_more", value=f"{len(ids) - 15} more not shown"))

    if not confirmation_token and not gate.has_approval(target):
        gate.record_request(target)
        return [_intent(
            gate.name, target, f"cancel {label}", entity, evidence,
            confirm_mode=gate.confirm_mode,
        )]

    async def _run() -> dict[str, int]:
        cancelled = terminal = failed = 0
        for x in ids:
            try:
                await pa.post(f"/agent/admin/tasks/{x}/cancel")
                cancelled += 1
            except ProjectAchillesError as e:
                if e.status in (401, 403):
                    raise  # systemic auth failure -> surface as permission finding
                if e.status in (400, 404, 409, 422):
                    terminal += 1  # already-terminal / gone -> skip, don't fail batch
                else:
                    failed += 1
        return {"cancelled": cancelled, "terminal": terminal, "failed": failed}

    try:
        tally = await gate.execute_async(
            target=target, actor=actor, token=confirmation_token, run=_run,
        )
    except GateDenied as e:
        return [_refusal(gate.name, target, e)]
    except ProjectAchillesError as e:
        return _after_gate_error(e, gate.name, target, "cancel tasks")

    return [Finding(
        source=_SOURCE,
        finding_type=FindingType.action,
        severity=Severity.info,
        title=(
            f"Action completed: cancelled {tally['cancelled']} of {len(ids)} task(s) "
            f"({tally['terminal']} already finished, {tally['failed']} failed)"
        ),
        entity=entity,
        evidence=[
            Evidence(key="cancelled", value=str(tally["cancelled"])),
            Evidence(key="already_finished", value=str(tally["terminal"])),
            Evidence(key="failed", value=str(tally["failed"])),
            *[Evidence(key=f"task_{i + 1}", value=x) for i, x in enumerate(ids[:15])],
        ],
        recommended_action=RecommendedAction(
            summary="Confirm remaining state with list_tasks.",
            gated_action=gate.name,
            confidence="high",
        ),
    )]
```

In `server.py`, replace the `cancel_task` wrapper with:

```python
@mcp.tool()
async def cancel_tasks(
    task_id: str = "",
    status: Literal["pending", "assigned", "running", "completed", "failed", "expired"] = "pending",
    search: str = "",
    confirmation_token: str = "",
) -> list[dict[str, Any]]:
    """Cancel ProjectAchilles test tasks (GATED WRITE). Pass EITHER task_id (one
    task) OR a status/search filter to bulk-cancel a run's tasks in one action
    (e.g. status=pending cancels all pending). Bulk confirmation is bound to the
    matched task COUNT; >200 matches is refused. Same two-step confirmation as
    run_test."""
    cfg = ProjectAchillesConfig.from_env()
    async with ProjectAchillesClient(cfg) as pa:
        return _render(
            await tools.cancel_tasks(
                pa, _gate("projectachilles.cancel_tasks", cfg),
                task_id, status, search, confirmation_token, _ACTOR,
            )
        )
```

- [ ] **Step 4: Update the split test file + registration**

Rename `tests/test_schedule_status_and_cancel.py` → `tests/test_schedule_status.py` and **remove every `cancel_task` test and the `cancel_task` import** from it (leaving only the `set_schedule_status` tests). The cancel coverage now lives in `test_cancel_tasks.py`.

```bash
git mv servers/projectachilles-actions-mcp/tests/test_schedule_status_and_cancel.py \
       servers/projectachilles-actions-mcp/tests/test_schedule_status.py
```

Then edit the file: change the import line `from f0_pa_actions_mcp.tools import cancel_task, set_schedule_status` → `from f0_pa_actions_mcp.tools import set_schedule_status`, and delete the `async def test_cancel_*` functions.

In `tests/test_server_registration.py`, change `cancel_task` → `cancel_tasks` in the expected set and add:

```python
@pytest.mark.asyncio
async def test_cancel_tasks_exposes_task_id_and_filter():
    tools = {t.name: t for t in await server.mcp.list_tools()}
    props = tools["cancel_tasks"].inputSchema["properties"]
    assert "task_id" in props and "status" in props and "search" in props
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd servers/projectachilles-actions-mcp && uv run pytest -v`
Expected: PASS (whole actions suite, incl. the moved schedule tests and the registration set of 7 with `cancel_tasks`).

- [ ] **Step 6: Commit**

```bash
git add servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py \
        servers/projectachilles-actions-mcp/f0_pa_actions_mcp/server.py \
        servers/projectachilles-actions-mcp/tests/test_cancel_tasks.py \
        servers/projectachilles-actions-mcp/tests/test_schedule_status.py \
        servers/projectachilles-actions-mcp/tests/test_server_registration.py
git commit -F - <<'EOF'
feat(pa-actions): cancel_task -> gated cancel_tasks (single or bulk)

Renames and widens the cancel tool: pass task_id for one task, or a
status/search filter to bulk-cancel a run's tasks in one gated action.
No batch-cancel endpoint exists, so the fan-out loops per-task inside
the tool under ONE count-bound confirmation (target cancel:<status>:
<search>:<N>) — drift auto-refused, no core/gating change. Enumerates at
limit=201 with a 200 hard cap (non-int total can't bypass). Per-task
cancel errors are tallied (cancelled/already-finished/failed), never
aborting the batch; a first-call 401/403 surfaces as a permission finding.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Va1ncSUtqQJyetofn2mJem
EOF
```

---

## Task 4: Evals, docs, skills, smoke probes

**Files:**
- Modify: `evals/projectachilles/tasks.yaml` (+1 scoped executions task), `evals/projectachilles-actions/tasks.yaml` (`cancel_task`→`cancel_tasks` prompt, +1 `list_tasks` task), `evals/test_combined.py` (counts 74→76)
- Modify: `README.md`, `CLAUDE.md`, `servers/projectachilles-actions-mcp/README.md`, `servers/projectachilles-mcp/README.md`, `skills/projectachilles/run-validation-test/SKILL.md`, `docs/user-guide/README.md`
- Modify: `scripts/live_smoke_projectachilles.py`, `scripts/live_smoke_projectachilles_actions.py` (read-only probes for the new surfaces)

**Interfaces:** none (docs/config only).

- [ ] **Step 1: Update eval task sets**

In `evals/projectachilles-actions/tasks.yaml`: change any `expect_tool: cancel_task` → `cancel_tasks`, and add:

```yaml
- prompt: "show me what's still pending for the acme ransomware run"
  expect_tool: list_tasks
  origin: projectachilles-actions
- prompt: "cancel all the pending tests"
  expect_tool: cancel_tasks
  origin: projectachilles-actions
```

In `evals/projectachilles/tasks.yaml`, add:

```yaml
- prompt: "show the results for the Kerberoast test on the windows fleet"
  expect_tool: list_test_executions
  origin: projectachilles
```

- [ ] **Step 2: Update the combined count test**

In `evals/test_combined.py`, update the comment and assertion:
- comment `... 12 projectachilles ... 11 projectachilles-actions = 74` → `13 projectachilles ... 13 projectachilles-actions = 76`
- `assert len(per_server) == 74` → `assert len(per_server) == 76`

(projectachilles read: 12→13 via the scoped-executions task; projectachilles-actions: 11→13 via the `list_tasks` task **and** the new `cancel_tasks` bulk task — the existing `cancel_task` task is renamed in place, so net +2. Verify the exact per-file counts after editing; adjust the number to the real total if it differs, and match the comment to it.)

- [ ] **Step 3: Run the eval count test**

Run: `uv run pytest evals/test_combined.py -v`
Expected: PASS. If it fails on the count, set the assertion to the actual `len(per_server)` printed and align the comment — the number must equal the real task count, not a guess.

- [ ] **Step 4: Update docs**

- `CLAUDE.md` — the Platform Integrations / actions-server description: "6 tools (4 gated writes — `run_test`, `schedule_test`, `set_schedule_status`, `cancel_task` — + 2 reads — `list_schedules`, `get_task_status`)" → "7 tools (4 gated writes — `run_test`, `schedule_test`, `set_schedule_status`, `cancel_tasks` — + 3 reads — `list_schedules`, `get_task_status`, `list_tasks`)". Note `cancel_tasks` does single **or** bulk (count-bound, 200 cap).
- `servers/projectachilles-actions-mcp/README.md` — tool table: `cancel_task(task_id)` → `cancel_tasks(task_id \| status/search)`; add `list_tasks(status, search)` read row; add a paragraph: bulk cancel is count-bound (`cancel:<status>:<search>:<N>`), >200 refused, same-size-swap not caught (deliberate), chat-confirm allowed (not single-use / no TTL caveat carries over).
- `servers/projectachilles-mcp/README.md` — `list_test_executions` now takes `test`/`tag`/`hostname` to scope to one run.
- `skills/projectachilles/run-validation-test/SKILL.md` — add a "Checking & cancelling a run" section: scope results with `list_test_executions(test=…, tag=…)`; sweep lifecycle with `list_tasks(status="pending")`; bulk-cancel with `cancel_tasks(status="pending")` (same confirm flow, count-bound).
- `README.md` (root) and `docs/user-guide/README.md` — replace `cancel_task` mentions with `cancel_tasks`; note `list_tasks`.

- [ ] **Step 5: Add read-only smoke probes**

In `scripts/live_smoke_projectachilles.py`, add a scoped-executions probe (call `list_test_executions` with a `test=` arg the operator can set) so live-validation can confirm `?tests=` semantics. In `scripts/live_smoke_projectachilles_actions.py`, add a `list_tasks(status="pending")` read probe and a **dry-run** `cancel_tasks(status="pending")` intent probe (no token — prints the count-bound target only, never executes). Keep both read-only / intent-only; the `--execute` cancel path stays gated behind an explicit token as with the other write smokes.

- [ ] **Step 6: Validate skills + integrations + full suite**

Run:
```bash
uv run pytest skills/test_skills_valid.py integrations/test_integrations_valid.py -v
uv run pytest
uv run ruff check .
uv run mypy core servers
```
Expected: all PASS (integrations templates unchanged — no server added/removed; skills frontmatter still valid; full suite green; ruff + strict mypy clean).

- [ ] **Step 7: Commit**

```bash
git add evals/ README.md CLAUDE.md \
        servers/projectachilles-actions-mcp/README.md servers/projectachilles-mcp/README.md \
        skills/projectachilles/run-validation-test/SKILL.md docs/user-guide/README.md \
        scripts/live_smoke_projectachilles.py scripts/live_smoke_projectachilles_actions.py
git commit -F - <<'EOF'
docs(pa): wire fleet status/cancel — evals, docs, skills, smoke probes

Eval tasks for list_tasks / cancel_tasks / scoped list_test_executions
(+ combined count). CLAUDE.md actions server 6->7 tools; READMEs, the
run-validation-test skill, and user guide updated for cancel_tasks
(single|bulk, count-bound, 200 cap, chat-confirm) and list_tasks.
Read-only/intent smoke probes for live validation of ?tests= semantics
and the count-bound cancel preview.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Va1ncSUtqQJyetofn2mJem
EOF
```

---

## Live-validation checklist (USER-GATED — on pi, not part of this branch)

Per the recipe's step 9 ("live API is truth"):
1. `?tests=` — matches `test_name` or `test_uuid`? Pin + document in the read server README.
2. `list_tasks` per-host rows for a real fleet run — hostnames all populated?
3. Bulk `cancel_tasks(status=pending)` on a real fleet → count-bound preview, N cancels, drift re-approval when a task finishes mid-flight.
4. Scoped `list_test_executions(test=…, tag=…)` → phantom host gone.

## Self-review notes

- **Spec coverage:** Component 1 → Task 1; Component 2 → Task 2; Component 3 → Task 3; Safety/testing/docs → folded into each task + Task 4. Every spec section maps to a task.
- **Caller safety (fleet lesson):** the `cancel_task`→`cancel_tasks` signature change ships with its only two callers (tools def + server wrapper) in the SAME task (Task 3); no smoke script calls the function positionally (verified).
- **Test-file split:** Task 3 moves cancel tests out of `test_schedule_status_and_cancel.py` (renamed) into `test_cancel_tasks.py` so no task leaves a dangling `cancel_task` import.
- **Eval count:** Step 2/3 of Task 4 verify the real `len(per_server)` rather than trusting the arithmetic — the assertion must equal the actual count.
