# Fleet-Wide Test Runs by Tag Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `run_test` / `schedule_test` target either one `hostname` (unchanged) or a fleet by `tag`, in one gated action, with the confirmation bound to `test@tag:<tag>:<N>` so a changed blast radius forces re-approval — reusing the existing gate with no `core/` change.

**Architecture:** A shared `resolve_selection(pa, hostname, tag)` in `resolve.py` returns a normalized selection (`agent_ids`, `hostnames`, `org_id`, `target_key`, `label`, `count`, `is_fleet`); both gated tools route host-or-tag through it, build `target = <uuid>@<target_key>`, and set `body["agent_ids"]` to the resolved list. The backend fans out. Bounded, one-finding output.

**Tech Stack:** Python 3.11+, pytest + respx.

**Spec:** `docs/superpowers/specs/2026-07-19-pa-fleet-tag-runs-design.md` (committed e2a5a25). Branch: `feat/pa-fleet-tag-runs` (checked out).

## Global Constraints

- **No new tools, no `core/gating` change** (read server 8, actions 6). The drift-catch reuses the existing `(action, target)` binding: N is baked into the target string.
- **Exactly one of `{hostname, tag}`** must be set on `run_test`/`schedule_test`; both or neither → pre-gate guidance finding, gate never consulted, no token burned.
- **Single-host path is byte-unchanged and backward compatible:** target stays `<uuid>@<hostname>`; existing single-host tests stay green with unchanged assertions.
- **Fleet target = `<uuid>@tag:<tag>:<N>`** (N = resolved agent count). Re-resolve the tag on BOTH intent and execute; a changed N ⇒ changed target ⇒ the gate refuses a stale token/approval/echo automatically.
- **>200 agents for a tag → HARD REFUSAL** (never silently run on a capped subset). The admin agents envelope is `{"data": {"agents": [...], "total": N}}` — refuse when `data.total > 200` (or defensively when the returned list length ≥ 200 and total is unknown).
- **org_id** for a fleet is fetched **once** from the first agent's detail endpoint (the admin list strips org_id — known).
- **Bounded output:** intent + result findings cap host evidence at 15 with a "…K more" note; the result is ONE summary finding (first ~10 task_ids + count), never N flat findings.
- Tag charset guard `^[A-Za-z0-9._:@-]{1,64}$`. Every failure → finding, never an exception. NO `tests/__init__.py`. Verification per task: named pytest scope + `uv run ruff check .` + `uv run mypy .`. Commits conventional, no backticks in `-m`, specific files staged, never push.

---

### Task 1: `resolve_agents_by_tag` + `resolve_selection` (resolve.py)

**Files:**
- Modify: `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/resolve.py`
- Test: `servers/projectachilles-actions-mcp/tests/test_resolve.py` (append)

**Interfaces:**
- Consumes: existing `resolve_agent`, `guidance`, `ResolveFailed`, `_mapped`.
- Produces:
  - `async resolve_agents_by_tag(pa, tag: str) -> dict[str, Any]` → `{"agent_ids": [...], "hostnames": [...], "org_id": str}`.
  - `async resolve_selection(pa, hostname: str, tag: str) -> dict[str, Any]` → `{"agent_ids": list[str], "hostnames": list[str], "org_id": str, "target_key": str, "label": str, "count": int, "is_fleet": bool}`. Used by Tasks 2–3.

- [ ] **Step 1: Write the failing tests** — append to `tests/test_resolve.py`:

```python
from f0_pa_actions_mcp.resolve import resolve_agents_by_tag, resolve_selection

TAGGED = {"data": {"agents": [
    {"id": "ag-1", "hostname": "web-01", "status": "active"},
    {"id": "ag-2", "hostname": "web-02", "status": "active"},
], "total": 2}}
DETAIL = {"data": {"id": "ag-1", "org_id": "default", "hostname": "web-01"}}


@pytest.mark.asyncio
async def test_resolve_agents_by_tag_returns_ids_hosts_org():
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/agents").mock(
            return_value=httpx.Response(200, json=TAGGED)
        )
        router.get(f"{BASE}/api/agent/admin/agents/ag-1").mock(
            return_value=httpx.Response(200, json=DETAIL)
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            r = await resolve_agents_by_tag(pa, "web")
    assert r["agent_ids"] == ["ag-1", "ag-2"]
    assert r["hostnames"] == ["web-01", "web-02"]
    assert r["org_id"] == "default"          # fetched once from detail


@pytest.mark.asyncio
async def test_resolve_agents_by_tag_zero_matches_guides():
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/agents").mock(
            return_value=httpx.Response(200, json={"data": {"agents": [], "total": 0}})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            with pytest.raises(ResolveFailed) as ei:
                await resolve_agents_by_tag(pa, "nope")
    assert "no agents" in ei.value.finding.title.lower()
    assert "nope" in ei.value.finding.title


@pytest.mark.asyncio
async def test_resolve_agents_by_tag_over_200_hard_refusal():
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/agents").mock(
            return_value=httpx.Response(200, json={"data": {
                "agents": [{"id": f"a{i}", "hostname": f"h{i}"} for i in range(200)],
                "total": 512,
            }})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            with pytest.raises(ResolveFailed) as ei:
                await resolve_agents_by_tag(pa, "everything")
    assert "narrow" in ei.value.finding.title.lower() or "narrow" in \
        ei.value.finding.recommended_action.summary.lower()


@pytest.mark.asyncio
async def test_resolve_agents_by_tag_bad_charset_guides():
    async with ProjectAchillesClient(_cfg()) as pa:
        with pytest.raises(ResolveFailed):
            await resolve_agents_by_tag(pa, "bad tag!")


@pytest.mark.asyncio
async def test_resolve_selection_requires_exactly_one():
    async with ProjectAchillesClient(_cfg()) as pa:
        with pytest.raises(ResolveFailed):        # neither
            await resolve_selection(pa, "", "")
        with pytest.raises(ResolveFailed):        # both
            await resolve_selection(pa, "web-01", "web")


@pytest.mark.asyncio
async def test_resolve_selection_host_is_single_backward_compatible():
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/agents").mock(
            return_value=httpx.Response(200, json={"data": {"agents": [
                {"id": "ag-1", "org_id": "default", "hostname": "web-01"},
            ]}})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            sel = await resolve_selection(pa, "web-01", "")
    assert sel["is_fleet"] is False
    assert sel["agent_ids"] == ["ag-1"]
    assert sel["target_key"] == "web-01"       # target stays uuid@hostname
    assert sel["count"] == 1


@pytest.mark.asyncio
async def test_resolve_selection_tag_is_fleet_target_encodes_count():
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/agents").mock(
            return_value=httpx.Response(200, json=TAGGED)
        )
        router.get(f"{BASE}/api/agent/admin/agents/ag-1").mock(
            return_value=httpx.Response(200, json=DETAIL)
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            sel = await resolve_selection(pa, "", "web")
    assert sel["is_fleet"] is True
    assert sel["agent_ids"] == ["ag-1", "ag-2"]
    assert sel["target_key"] == "tag:web:2"    # count baked into the target
    assert sel["count"] == 2
    assert sel["org_id"] == "default"
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest servers/projectachilles-actions-mcp/tests/test_resolve.py -v -k "by_tag or selection"`
Expected: FAIL — `ImportError: cannot import name 'resolve_agents_by_tag'`

- [ ] **Step 3: Implement in `resolve.py`**

Add a tag regex near `_UUID_RE`:

```python
_TAG_RE = re.compile(r"^[A-Za-z0-9._:@-]{1,64}$")
_MAX_FLEET = 200
```

Append after `resolve_agent`:

```python
async def resolve_agents_by_tag(pa: Any, tag: str) -> dict[str, Any]:
    """tag -> {agent_ids, hostnames, org_id} for every agent carrying it.

    Refuses (>_MAX_FLEET) rather than silently run on a capped subset — a
    hidden blast-radius cap is unacceptable for an attack-simulation launcher.
    """
    t = tag.strip()
    if not t or not _TAG_RE.match(t):
        raise ResolveFailed(
            guidance(
                f"tag '{t or '(empty)'}' is missing or has unsupported characters",
                "Use a tag as shown in the ProjectAchilles console "
                "(letters, digits, . _ : @ -).",
            )
        )
    try:
        resp = await pa.get("/agent/admin/agents", params={"tag": t, "limit": _MAX_FLEET})
    except ProjectAchillesError as e:
        raise _mapped(e, "agent tag lookup") from e
    data = resp.get("data") if isinstance(resp, dict) else None
    data = data if isinstance(data, dict) else {}
    agents = data.get("agents") if isinstance(data.get("agents"), list) else []
    total = data.get("total")
    if (isinstance(total, int) and not isinstance(total, bool) and total > _MAX_FLEET) or (
        total is None and len(agents) >= _MAX_FLEET
    ):
        raise ResolveFailed(
            guidance(
                f"Tag '{t}' matches more than {_MAX_FLEET} agents — refusing to fan out",
                f"Narrow the tag so it selects at most {_MAX_FLEET} hosts, then retry.",
            )
        )
    if not agents:
        raise ResolveFailed(
            guidance(
                f"No agents carry tag '{t}'",
                "Check the tag in the ProjectAchilles console (agent tags).",
            )
        )
    agent_ids = [str(a.get("id")) for a in agents if isinstance(a, dict) and a.get("id")]
    hostnames = [str(a.get("hostname") or "?") for a in agents if isinstance(a, dict)]
    # org_id once from the first agent's detail (the admin list strips it).
    org_id = ""
    if agent_ids:
        try:
            detail = await pa.get(f"/agent/admin/agents/{agent_ids[0]}")
        except ProjectAchillesError as e:
            raise _mapped(e, "agent org lookup") from e
        d2 = detail.get("data") if isinstance(detail, dict) else None
        if isinstance(d2, dict):
            org_id = str(d2.get("org_id") or "")
    return {"agent_ids": agent_ids, "hostnames": hostnames, "org_id": org_id}


async def resolve_selection(pa: Any, hostname: str, tag: str) -> dict[str, Any]:
    """Normalize host-or-tag targeting. Exactly one of hostname/tag must be set."""
    h, t = hostname.strip(), tag.strip()
    if bool(h) == bool(t):
        raise ResolveFailed(
            guidance(
                "Set exactly one of hostname or tag",
                "hostname targets ONE host; tag targets every agent carrying "
                "that tag (a fleet).",
            )
        )
    if h:
        a = await resolve_agent(pa, h)
        return {
            "agent_ids": [a["agent_id"]],
            "hostnames": [a["hostname"]],
            "org_id": a["org_id"],
            "target_key": a["hostname"],
            "label": a["hostname"],
            "count": 1,
            "is_fleet": False,
        }
    fleet = await resolve_agents_by_tag(pa, t)
    n = len(fleet["agent_ids"])
    return {
        "agent_ids": fleet["agent_ids"],
        "hostnames": fleet["hostnames"],
        "org_id": fleet["org_id"],
        "target_key": f"tag:{t}:{n}",
        "label": f"tag '{t}' ({n} host{'s' if n != 1 else ''})",
        "count": n,
        "is_fleet": True,
    }
```

- [ ] **Step 4: Run tests, lint, type-check**

Run: `uv run pytest servers/projectachilles-actions-mcp/tests/test_resolve.py -v && uv run ruff check servers/projectachilles-actions-mcp && uv run mypy .`
Expected: all PASS (existing resolve tests green), clean

- [ ] **Step 5: Commit**

```bash
git add servers/projectachilles-actions-mcp/f0_pa_actions_mcp/resolve.py servers/projectachilles-actions-mcp/tests/test_resolve.py
git commit -m "feat(pa-actions): resolve_agents_by_tag and host-or-tag selection"
```

---

### Task 2: `run_test` host-or-tag (tools.py)

**Files:**
- Modify: `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py` (`run_test`; add `_selection_evidence` helper)
- Test: `servers/projectachilles-actions-mcp/tests/test_run_test.py` (append)

**Interfaces:**
- Consumes: Task 1 `resolve_selection`. `run_test` signature gains `tag: str = ""`.

- [ ] **Step 1: Write the failing tests** — append to `tests/test_run_test.py`:

```python
TAGGED = {"data": {"agents": [
    {"id": "ag-1", "hostname": "web-01", "status": "active"},
    {"id": "ag-2", "hostname": "web-02", "status": "active"},
], "total": 2}}
TAG_DETAIL = {"data": {"id": "ag-1", "org_id": "org-1", "hostname": "web-01"}}
TAG_TARGET = f"{UUID}@tag:web:2"


def _mock_tag_reads(router):
    router.get(f"{BASE}/api/browser/tests/{UUID}").mock(
        return_value=httpx.Response(200, json={"test": TEST_RECORD}))
    router.get(f"{BASE}/api/tests/builds/{UUID}").mock(
        return_value=httpx.Response(200, json=BUILD))
    router.get(f"{BASE}/api/agent/admin/agents").mock(
        return_value=httpx.Response(200, json=TAGGED))
    router.get(f"{BASE}/api/agent/admin/agents/ag-1").mock(
        return_value=httpx.Response(200, json=TAG_DETAIL))


@pytest.mark.asyncio
async def test_run_test_both_host_and_tag_guides_no_gate(tmp_path):
    with respx.mock(assert_all_called=False) as router:
        _mock_reads(router)
        post = router.post(f"{BASE}/api/agent/admin/tasks")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await run_test(pa, _gate(tmp_path), UUID, "web-01", tag="web")
    assert post.called is False
    assert "exactly one" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_run_test_tag_intent_lists_hosts_and_count(tmp_path):
    with respx.mock(assert_all_called=False) as router:
        _mock_tag_reads(router)
        router.post(f"{BASE}/api/agent/admin/tasks")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await run_test(pa, _gate(tmp_path), UUID, "", tag="web")
    f = findings[0]
    assert "Pending action" in f.title
    joined = " ".join(e.value for e in f.evidence)
    assert "web-01" in joined and "web-02" in joined
    assert any(e.key == "host_count" and e.value == "2" for e in f.evidence)
    assert TAG_TARGET in f.recommended_action.summary  # count-bound target


@pytest.mark.asyncio
async def test_run_test_tag_valid_token_posts_all_agent_ids(tmp_path):
    with respx.mock() as router:
        _mock_tag_reads(router)
        post = router.post(f"{BASE}/api/agent/admin/tasks").mock(
            return_value=httpx.Response(201, json={"data": {"task_ids": ["t1", "t2"]}}))
        store = TokenStore(str(tmp_path / "pending"))
        token = store.issue("projectachilles.run_test", TAG_TARGET)
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await run_test(pa, _gate(tmp_path), UUID, "", "web", token)
    assert post.call_count == 1
    body = json.loads(post.calls[0].request.content)
    assert body["agent_ids"] == ["ag-1", "ag-2"]
    assert body["org_id"] == "org-1"
    assert "2 host" in findings[0].title or "2 tasks" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_run_test_tag_drift_in_count_refuses(tmp_path):
    # Token issued for N=2; the tag now resolves to N=3 -> target mismatch -> refusal.
    grown = {"data": {"agents": [
        {"id": "ag-1", "hostname": "web-01"}, {"id": "ag-2", "hostname": "web-02"},
        {"id": "ag-3", "hostname": "web-03"},
    ], "total": 3}}
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/api/browser/tests/{UUID}").mock(
            return_value=httpx.Response(200, json={"test": TEST_RECORD}))
        router.get(f"{BASE}/api/tests/builds/{UUID}").mock(
            return_value=httpx.Response(200, json=BUILD))
        router.get(f"{BASE}/api/agent/admin/agents").mock(
            return_value=httpx.Response(200, json=grown))
        router.get(f"{BASE}/api/agent/admin/agents/ag-1").mock(
            return_value=httpx.Response(200, json=TAG_DETAIL))
        post = router.post(f"{BASE}/api/agent/admin/tasks")
        store = TokenStore(str(tmp_path / "pending"))
        token = store.issue("projectachilles.run_test", TAG_TARGET)  # N=2 target
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await run_test(pa, _gate(tmp_path), UUID, "", "web", token)
    assert post.called is False
    assert "not taken" in findings[0].title
    # token for the N=2 target survives (a new N=3 approval is required)
    assert TokenStore(str(tmp_path / "pending")).consume(
        "projectachilles.run_test", TAG_TARGET, token)


@pytest.mark.asyncio
async def test_run_test_tag_bounds_host_evidence_to_15(tmp_path):
    many = {"data": {"agents": [
        {"id": f"a{i}", "hostname": f"h{i}"} for i in range(40)], "total": 40}}
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/api/browser/tests/{UUID}").mock(
            return_value=httpx.Response(200, json={"test": TEST_RECORD}))
        router.get(f"{BASE}/api/tests/builds/{UUID}").mock(
            return_value=httpx.Response(200, json=BUILD))
        router.get(f"{BASE}/api/agent/admin/agents").mock(
            return_value=httpx.Response(200, json=many))
        router.get(f"{BASE}/api/agent/admin/agents/a0").mock(
            return_value=httpx.Response(200, json={"data": {"id": "a0", "org_id": "o", "hostname": "h0"}}))
        router.post(f"{BASE}/api/agent/admin/tasks")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await run_test(pa, _gate(tmp_path), UUID, "", tag="web")
    host_ev = [e for e in findings[0].evidence if e.key.startswith("host_")
               and e.key != "host_count"]
    assert len(host_ev) <= 15
    assert any("more" in e.value.lower() for e in findings[0].evidence)
```

(`json`, `UUID`, `TEST_RECORD`, `BUILD`, `_mock_reads`, `_gate`, `_cfg`, `TokenStore`, `BASE` already imported/defined in this file.)

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest servers/projectachilles-actions-mcp/tests/test_run_test.py -v -k "tag or both_host"`
Expected: FAIL — `run_test()` has no `tag` parameter.

- [ ] **Step 3: Implement — refactor `run_test` to use `resolve_selection`**

Add `resolve_selection` to the `.resolve` import. Add `tag: str = ""` to `run_test`'s signature (after `hostname`). Add a shared helper above `run_test`:

```python
_MAX_HOSTS_SHOWN = 15


def _selection_evidence(sel: dict[str, Any]) -> list[Evidence]:
    """Bounded host evidence for a selection (one host or a fleet)."""
    ev: list[Evidence] = [Evidence(key="host_count", value=str(sel["count"]))]
    for i, h in enumerate(sel["hostnames"][:_MAX_HOSTS_SHOWN]):
        ev.append(Evidence(key=f"host_{i + 1}", value=str(h)))
    extra = sel["count"] - _MAX_HOSTS_SHOWN
    if extra > 0:
        ev.append(Evidence(key="hosts_more", value=f"{extra} more not shown"))
    return ev
```

Replace `run_test`'s resolution + target + entity + evidence + body block:

```python
async def run_test(
    pa: Any,
    gate: GatedAction,
    test_id: str,
    hostname: str = "",
    tag: str = "",
    confirmation_token: str = "",
    actor: str = "mcp-operator",
) -> list[Finding]:
    """Run a validation test now on ONE host (hostname) or a FLEET (tag) — gated.

    Set exactly one of hostname/tag. No token -> intent only."""
    try:
        test = await resolve_test(pa, test_id)
        binary = await resolve_build(pa, test["test_uuid"])
        sel = await resolve_selection(pa, hostname, tag)
    except ResolveFailed as e:
        return [e.finding]
    target = f"{test['test_uuid']}@{sel['target_key']}"
    entity = (
        Entity(kind=EntityKind.host, id=sel["agent_ids"][0], name=sel["hostnames"][0])
        if not sel["is_fleet"]
        else Entity(kind=EntityKind.tenant, id=sel["target_key"], name=sel["label"])
    )
    evidence = [
        Evidence(key="test_name", value=test["test_name"]),
        Evidence(key="test_uuid", value=test["test_uuid"]),
        Evidence(key="binary_name", value=binary),
        *_selection_evidence(sel),
    ]
    if not confirmation_token and not gate.has_approval(target):
        gate.record_request(target)
        return [
            _intent(
                gate.name, target,
                f"run test '{test['test_name']}' on {sel['label']}",
                entity, evidence, gate.confirm_mode,
            )
        ]
    body = {
        "org_id": sel["org_id"],
        "agent_ids": sel["agent_ids"],
        "test_uuid": test["test_uuid"],
        "test_name": test["test_name"],
        "binary_name": binary,
        "metadata": test["metadata"],
    }
    try:
        result = await gate.execute_async(
            target=target, actor=actor, token=confirmation_token,
            run=lambda: pa.post("/agent/admin/tasks", json=body),
        )
    except GateDenied as e:
        return [_refusal(gate.name, target, e)]
    except ProjectAchillesError as e:
        return _after_gate_error(e, gate.name, target, "run test")
    task_ids = (result.get("data") or {}).get("task_ids") or []
    return [
        Finding(
            source=_SOURCE,
            finding_type=FindingType.action,
            severity=Severity.info,
            title=f"Action completed: run test '{test['test_name']}' on "
            f"{sel['label']} ({len(task_ids)} task"
            f"{'s' if len(task_ids) != 1 else ''})",
            entity=entity,
            evidence=[
                *evidence,
                *[Evidence(key="task_id", value=str(t)) for t in task_ids[:10]],
            ],
            recommended_action=RecommendedAction(
                summary=f"Submitted {len(task_ids)} task(s) on {sel['label']}; they "
                "run asynchronously. Ask me later and I'll check with get_task_status "
                "(or list_test_executions on the read server for per-host results).",
                gated_action=gate.name,
                confidence="high",
            ),
        )
    ]
```

- [ ] **Step 4: Run tests, lint, type-check**

Run: `uv run pytest servers/projectachilles-actions-mcp/tests/test_run_test.py -v && uv run ruff check servers/projectachilles-actions-mcp && uv run mypy .`
Expected: all PASS — including every pre-existing single-host `run_test` test (the `hostname`-only path resolves to `sel` with `target_key == hostname`, so `target` and body are unchanged). Clean.

- [ ] **Step 5: Commit**

```bash
git add servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py servers/projectachilles-actions-mcp/tests/test_run_test.py
git commit -m "feat(pa-actions): run_test targets one host or a fleet by tag"
```

---

### Task 3: `schedule_test` host-or-tag (tools.py)

**Files:**
- Modify: `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py` (`schedule_test`)
- Test: `servers/projectachilles-actions-mcp/tests/test_schedule_test.py` (append)

**Interfaces:** Consumes Task 1 `resolve_selection`, Task 2 `_selection_evidence`. `schedule_test` signature gains `tag: str = ""`.

- [ ] **Step 1: Write the failing tests** — append to `tests/test_schedule_test.py`:

```python
TAGGED = {"data": {"agents": [
    {"id": "ag-1", "hostname": "web-01"}, {"id": "ag-2", "hostname": "web-02"},
], "total": 2}}
TAG_DETAIL = {"data": {"id": "ag-1", "org_id": "org-1", "hostname": "web-01"}}
TAG_TARGET = f"{UUID}@tag:web:2"


def _mock_tag_reads(router):
    router.get(f"{BASE}/api/browser/tests/{UUID}").mock(
        return_value=httpx.Response(200, json={"test": TEST_RECORD}))
    router.get(f"{BASE}/api/tests/builds/{UUID}").mock(
        return_value=httpx.Response(200, json=BUILD))
    router.get(f"{BASE}/api/agent/admin/agents").mock(
        return_value=httpx.Response(200, json=TAGGED))
    router.get(f"{BASE}/api/agent/admin/agents/ag-1").mock(
        return_value=httpx.Response(200, json=TAG_DETAIL))


@pytest.mark.asyncio
async def test_schedule_test_tag_intent_lists_count(tmp_path):
    with respx.mock(assert_all_called=False) as router:
        _mock_tag_reads(router)
        router.post(f"{BASE}/api/agent/admin/schedules")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await schedule_test(
                pa, _gate(tmp_path), UUID, "", "daily", "02:30", tag="web")
    f = findings[0]
    assert "Pending action" in f.title
    assert any(e.key == "host_count" and e.value == "2" for e in f.evidence)
    assert TAG_TARGET in f.recommended_action.summary


@pytest.mark.asyncio
async def test_schedule_test_tag_valid_token_posts_all_agent_ids(tmp_path):
    with respx.mock() as router:
        _mock_tag_reads(router)
        post = router.post(f"{BASE}/api/agent/admin/schedules").mock(
            return_value=httpx.Response(201, json={"data": {
                "id": "sched-1", "status": "active", "next_run_at": None}}))
        store = TokenStore(str(tmp_path / "pending"))
        token = store.issue("projectachilles.schedule_test", TAG_TARGET)
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await schedule_test(
                pa, _gate(tmp_path), UUID, "", "daily", "02:30",
                tag="web", confirmation_token=token)
    assert post.call_count == 1
    body = json.loads(post.calls[0].request.content)
    assert body["agent_ids"] == ["ag-1", "ag-2"]
    assert "Action completed" in findings[0].title


@pytest.mark.asyncio
async def test_schedule_test_both_host_and_tag_guides(tmp_path):
    with respx.mock(assert_all_called=False) as router:
        _mock_reads(router)
        post = router.post(f"{BASE}/api/agent/admin/schedules")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await schedule_test(
                pa, _gate(tmp_path), UUID, "web-01", "daily", "02:30", tag="web")
    assert post.called is False
    assert "exactly one" in findings[0].title.lower()
```

(`_mock_reads` is the existing single-host mock helper in this file; `json`/`UUID`/`TEST_RECORD`/`BUILD`/`_gate`/`_cfg`/`TokenStore`/`BASE` already present.)

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest servers/projectachilles-actions-mcp/tests/test_schedule_test.py -v -k "tag or both_host"`
Expected: FAIL — `schedule_test()` has no `tag` parameter.

- [ ] **Step 3: Implement — refactor `schedule_test` to use `resolve_selection`**

Add `tag: str = ""` after `hostname` in `schedule_test`'s signature. Replace its resolution + target + entity + evidence + body block to mirror `run_test`'s selection pattern, keeping the `_schedule_config` call and schedule fields:

```python
async def schedule_test(
    pa: Any,
    gate: GatedAction,
    test_id: str,
    hostname: str = "",
    schedule: str = "",
    run_time: str = "",
    run_date: str = "",
    day: str = "",
    day_of_month: int = 0,
    tag: str = "",
    confirmation_token: str = "",
    actor: str = "mcp-operator",
) -> list[Finding]:
    """Schedule a validation test on ONE host (hostname) or a FLEET (tag) — gated.

    Set exactly one of hostname/tag. No token -> intent only."""
    try:
        cfg = _schedule_config(schedule, run_time, run_date, day, day_of_month)
        test = await resolve_test(pa, test_id)
        binary = await resolve_build(pa, test["test_uuid"])
        sel = await resolve_selection(pa, hostname, tag)
    except ResolveFailed as e:
        return [e.finding]
    target = f"{test['test_uuid']}@{sel['target_key']}"
    desc = _describe_schedule(schedule, run_time, run_date, day, day_of_month)
    entity = (
        Entity(kind=EntityKind.host, id=sel["agent_ids"][0], name=sel["hostnames"][0])
        if not sel["is_fleet"]
        else Entity(kind=EntityKind.tenant, id=sel["target_key"], name=sel["label"])
    )
    evidence = [
        Evidence(key="test_name", value=test["test_name"]),
        Evidence(key="test_uuid", value=test["test_uuid"]),
        Evidence(key="schedule", value=desc),
        *_selection_evidence(sel),
    ]
    if not confirmation_token and not gate.has_approval(target):
        gate.record_request(target)
        return [
            _intent(
                gate.name, target,
                f"schedule test '{test['test_name']}' on {sel['label']} ({desc})",
                entity, evidence, gate.confirm_mode,
            )
        ]
    body = {
        "org_id": sel["org_id"],
        "agent_ids": sel["agent_ids"],
        "test_uuid": test["test_uuid"],
        "test_name": test["test_name"],
        "binary_name": binary,
        "metadata": test["metadata"],
        "schedule_type": schedule,
        "schedule_config": cfg,
        "timezone": "UTC",
        "name": f"{test['test_name']} @ {sel['label']}",
    }
    try:
        result = await gate.execute_async(
            target=target, actor=actor, token=confirmation_token,
            run=lambda: pa.post("/agent/admin/schedules", json=body),
        )
    except GateDenied as e:
        return [_refusal(gate.name, target, e)]
    except ProjectAchillesError as e:
        return _after_gate_error(e, gate.name, target, "schedule test")
    sched = result.get("data") or {}
    return [
        Finding(
            source=_SOURCE,
            finding_type=FindingType.action,
            severity=Severity.info,
            title=f"Action completed: scheduled '{test['test_name']}' on "
            f"{sel['label']} ({desc})",
            entity=entity,
            evidence=[
                *evidence,
                Evidence(key="schedule_id", value=str(sched.get("id", ""))),
                Evidence(key="next_run_at", value=str(sched.get("next_run_at") or "—")),
            ],
            recommended_action=RecommendedAction(
                summary="Verify with list_schedules; pause/resume later with "
                "set_schedule_status.",
                gated_action=gate.name,
                confidence="high",
            ),
        )
    ]
```

Note the signature reorders `tag` before `confirmation_token`; update the server call site in Task 4 accordingly. Existing single-host `schedule_test` tests call with keyword args for the schedule fields, so keep `schedule`/`run_time` keyword-callable (they default to "" now — the exactly-one and `_schedule_config` guards still fire for a missing schedule/time, and existing tests pass `schedule=`, `run_time=`).

- [ ] **Step 4: Run tests, lint, type-check**

Run: `uv run pytest servers/projectachilles-actions-mcp/tests/test_schedule_test.py servers/projectachilles-actions-mcp/tests/test_schedule_status_and_cancel.py -v && uv run ruff check servers/projectachilles-actions-mcp && uv run mypy .`
Expected: all PASS (existing single-host schedule tests green — they pass hostname + keyword schedule args). Clean.

- [ ] **Step 5: Commit**

```bash
git add servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py servers/projectachilles-actions-mcp/tests/test_schedule_test.py
git commit -m "feat(pa-actions): schedule_test targets one host or a fleet by tag"
```

---

### Task 4: Server wiring — `tag` params + descriptions + evals

**Files:**
- Modify: `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/server.py` (`run_test`, `schedule_test` tool signatures/docstrings + call sites)
- Modify: `evals/projectachilles-actions/tasks.yaml` (add fleet-by-tag tasks)
- Test: `servers/projectachilles-actions-mcp/tests/test_server_registration.py` (the 6-tool assertion still holds; add a param check)

**Interfaces:** exposes `tag` on the two MCP tools; no tool-count change.

- [ ] **Step 1: Update the registration test**

In `tests/test_server_registration.py`, append:

```python
@pytest.mark.asyncio
async def test_run_and_schedule_expose_tag_param():
    tools = {t.name: t for t in await server.mcp.list_tools()}
    assert "tag" in tools["run_test"].inputSchema["properties"]
    assert "tag" in tools["schedule_test"].inputSchema["properties"]
```

Run: `uv run pytest servers/projectachilles-actions-mcp/tests/test_server_registration.py -v -k tag`
Expected: FAIL — `tag` not in the schema yet.

- [ ] **Step 2: Update `server.py`**

`run_test` tool:

```python
@mcp.tool()
async def run_test(
    test_id: str, hostname: str = "", tag: str = "", confirmation_token: str = ""
) -> list[dict[str, Any]]:
    """Run a ProjectAchilles validation test now on ONE host OR a FLEET (GATED WRITE).

    Target exactly one of: `hostname` (one exact agent), or `tag` (every agent
    carrying that tag — a fleet, fanned out in one action). test_id is the
    test's UUID. Call WITHOUT confirmation_token first to preview: the intent
    lists the hosts and count. For a fleet, the confirmation is bound to the
    host COUNT, so if the tag's membership changes before you confirm you must
    re-preview and re-approve. Requires PROJECTACHILLES_ALLOW_WRITE=true.
    """
    cfg = ProjectAchillesConfig.from_env()
    async with ProjectAchillesClient(cfg) as pa:
        return _render(
            await tools.run_test(
                pa, _gate("projectachilles.run_test", cfg),
                test_id, hostname, tag, confirmation_token, _ACTOR,
            )
        )
```

`schedule_test` tool — add `tag` (matching the tools-layer order `hostname, schedule, run_time, run_date, day, day_of_month, tag, confirmation_token`):

```python
@mcp.tool()
async def schedule_test(
    test_id: str,
    hostname: str = "",
    schedule: Literal["once", "daily", "weekly", "monthly"] = "daily",
    run_time: str = "",
    run_date: str = "",
    day: _Day = "",
    day_of_month: int = 0,
    tag: str = "",
    confirmation_token: str = "",
) -> list[dict[str, Any]]:
    """Schedule a ProjectAchilles validation test on ONE host OR a FLEET (GATED WRITE).

    Target exactly one of `hostname` or `tag` (a fleet). run_time is 24h HH:MM
    UTC. schedule=once also needs run_date (YYYY-MM-DD); weekly also needs day;
    monthly also needs day_of_month (1-31). Same count-bound confirmation as
    run_test for fleets.
    """
    cfg = ProjectAchillesConfig.from_env()
    async with ProjectAchillesClient(cfg) as pa:
        return _render(
            await tools.schedule_test(
                pa, _gate("projectachilles.schedule_test", cfg),
                test_id, hostname, schedule, run_time, run_date, day,
                day_of_month, tag, confirmation_token, _ACTOR,
            )
        )
```

- [ ] **Step 3: Add eval tasks** — append to `evals/projectachilles-actions/tasks.yaml`:

```yaml
- prompt: "Run the ProjectAchilles test 3f2a9c10-1111-4222-8333-444455556666 on every host tagged windows-endpoints."
  expect_tool: run_test
  expect_args: { tag: windows-endpoints }

- prompt: "Schedule test 3f2a9c10-1111-4222-8333-444455556666 daily at 02:30 on all hosts tagged prod-servers."
  expect_tool: schedule_test
  expect_args: { tag: prod-servers, schedule: daily }
```

- [ ] **Step 4: Run scoped tests + full suite + gates**

Run: `uv run pytest servers/projectachilles-actions-mcp evals -v && uv run ruff check . && uv run mypy .`
Expected: registration test passes (still 6 tools + tag params); eval-coverage passes (run_test/schedule_test already registered, new tasks reference existing tools). If `evals/test_combined.py` asserts a per-server task count, bump the projectachilles-actions count by 2 and its comment. Clean.

- [ ] **Step 5: Commit**

```bash
git add servers/projectachilles-actions-mcp/f0_pa_actions_mcp/server.py servers/projectachilles-actions-mcp/tests/test_server_registration.py evals/projectachilles-actions/tasks.yaml evals/test_combined.py
git commit -m "feat(pa-actions): expose tag param on run_test/schedule_test + fleet evals"
```

---

### Task 5: Docs — skill fleet section + README + .env

**Files:**
- Modify: `skills/projectachilles/run-validation-test/SKILL.md`
- Modify: `servers/projectachilles-actions-mcp/README.md`

- [ ] **Step 1: Skill fleet section** — read the Procedure; add a fleet subsection: target a `tag` instead of a `hostname` to run/schedule across every agent carrying it in one gated action; the intent preview lists the hosts and count; the confirmation is bound to that count, so if the fleet size changes before you approve you re-preview and re-approve; >200 hosts is refused (narrow the tag). Keep frontmatter (description ≤60 chars) untouched. Run `uv run pytest skills/test_skills_valid.py` after.

- [ ] **Step 2: README** — read the tools table/Setup; note `run_test`/`schedule_test` accept `hostname` OR `tag` (fleet), with count-bound confirmation.

- [ ] **Step 3: Full verification**

Run: `uv run pytest && uv run ruff check . && uv run mypy .`
Expected: ALL PASS, clean. `git status --short` shows no real `.env*` staged.

- [ ] **Step 4: Commit**

```bash
git add skills/projectachilles/run-validation-test/SKILL.md servers/projectachilles-actions-mcp/README.md
git commit -m "docs(pa): fleet-by-tag run/schedule guidance"
```

---

## Plan Self-Review (done at write time)

- **Spec coverage:** tag param + exactly-one (T2/T3 via `resolve_selection` T1); resolve_agents_by_tag + org-once + >200 refusal + 0/charset (T1); target `test@tag:<tag>:<N>` + drift-catch (T2 test proves refusal + token survival); bounded intent/result (T2 `_selection_evidence`, 15-cap test); single-host byte-unchanged (T2/T3 existing tests); server wiring + descriptions + evals (T4); docs (T5). Spec milestone 6 (live pi) is user-gated — not a task.
- **Type consistency:** `resolve_selection` returns the documented keys used identically in `run_test`/`schedule_test`; `target_key` = `hostname` (single) or `tag:<t>:<N>` (fleet); `_selection_evidence` shared; server call-site arg order matches the tools-layer signatures (`run_test(... hostname, tag, confirmation_token, actor)`, `schedule_test(... hostname, schedule, run_time, run_date, day, day_of_month, tag, confirmation_token, actor)`).
- **Backward-compat risk noted:** `schedule_test`'s signature inserts `tag` before `confirmation_token`; existing tests/call sites use keyword args for schedule fields, so positional drift is avoided — the server call site is updated in the same task (T4) that could otherwise mismatch. Flagged for the implementer.
