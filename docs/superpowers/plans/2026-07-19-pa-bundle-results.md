# ProjectAchilles Bundle Results + No-Poll Status Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `get_task_status` return the completed run's outcome (bundle rollup from the task record's pre-aggregated `result.bundle_results`), reword the status/launch findings so the model fires-and-reports instead of polling, and make `list_test_executions` roll up bundle runs instead of emitting one flat finding per control.

**Architecture:** Read/UX only, no gate change, no new tools. Change A + B live in the actions server's `tools.py` (`get_task_status`, `run_test`/`schedule_test` success summaries). Change C lives in the read server's `tools.py` (`list_test_executions`). The two servers use different data sources (task `bundle_results` vs analytics rows) so there is no shared helper.

**Tech Stack:** Python 3.11+, stdlib `json`, pytest + respx.

**Spec:** `docs/superpowers/specs/2026-07-19-pa-bundle-results-design.md` (committed 2916b95). Branch: `feat/pa-bundle-results` (checked out).

## Global Constraints

- **No new tools, no gate/schema change.** Read server stays 8 tools, actions server stays 6.
- **Small-model-safe:** bounded output (cap failing-control evidence at 15 with an "N more" note), summarized (one rollup finding per bundle run, not one per control), findings schema, flat args unchanged.
- **Defensive parsing:** `result` and `bundle_results` may be a JSON string or a dict; missing/malformed → a graceful finding, never a crash. Same defensive dict access used elsewhere in these files.
- **Backward compatible:** non-bundle single tests keep their existing outcome vocabulary; `list_test_executions`'s existing `days`/`limit` args, paginated endpoint call, and single-row security-vs-cyber-hygiene vocab (blocked/NOT blocked vs passed/not passed) are unchanged; existing tests stay green unless their asserted string is one of the reworded summaries.
- **Verified live field shapes (tpsgl):** task `result.bundle_results` = `{bundle_name, bundle_category, total_controls, passed_controls, failed_controls, overall_exit_code, controls:[{control_id, control_name, validator, compliant(bool), severity, techniques:[...], tactics:[...]}]}`. Analytics rows = `{bundle_name, is_bundle_control(bool), control_validator, control_id, test_name, is_protected(bool), hostname, severity, techniques, timestamp, category}`. Non-bundle task `result` has `exit_code` and no `bundle_results`.
- **Imports:** actions `tools.py` must add `Reference` to the findings import and `import json`; read `tools.py` already imports both.
- NO `tests/__init__.py`; verification per task = named pytest scope + `uv run ruff check .` + `uv run mypy .`. Commits conventional, no backticks in `-m`, specific files staged, never push.

---

### Task 1: `get_task_status` returns the completed run's outcome (actions)

**Files:**
- Modify: `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py` (imports; `get_task_status` completed branch; add helper `_bundle_rollup`)
- Test: `servers/projectachilles-actions-mcp/tests/test_read_tools.py` (append)

**Interfaces:**
- Produces: `get_task_status` unchanged signature `async get_task_status(pa, task_id) -> list[Finding]`; new module-private `_bundle_rollup(tid, host, test_name, result) -> Finding | None` (returns a rollup Finding when `result.bundle_results` is present, else None so the caller falls back to single-test/plain outcome).

- [ ] **Step 1: Write the failing tests** — append to `servers/projectachilles-actions-mcp/tests/test_read_tools.py`:

```python
import json


def _task_resp(status, result=None, host="LT-TPL-L50", test_name="Identity Endpoint Posture Bundle"):
    t = {"id": "task-1", "status": status, "agent_id": "ag-1",
         "agent_hostname": host, "payload": {"test_name": test_name}}
    if result is not None:
        t["result"] = result
    return {"data": t}


_BUNDLE_RESULT = {
    "bundle_name": "Identity Endpoint Posture Bundle",
    "bundle_category": "cyber-hygiene",
    "total_controls": 22, "passed_controls": 15, "failed_controls": 7,
    "overall_exit_code": 101,
    "controls": [
        {"control_id": "CH-IEP-001", "control_name": "Azure AD Joined",
         "validator": "Device Join Status", "compliant": True,
         "severity": "critical", "techniques": ["T1078.004"]},
        {"control_id": "CH-IEP-015", "control_name": "PRT Status",
         "validator": "Cloud Credential Protection", "compliant": False,
         "severity": "high", "techniques": ["T1550"]},
        {"control_id": "CH-IEP-017", "control_name": "Cloud Kerberos Trust",
         "validator": "Cloud Credential Protection", "compliant": False,
         "severity": "high", "techniques": ["T1558"]},
    ],
}


@pytest.mark.asyncio
async def test_get_task_status_completed_bundle_rolls_up_verdict():
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/tasks/task-1").mock(
            return_value=httpx.Response(200, json=_task_resp("completed", _BUNDLE_RESULT))
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await get_task_status(pa, "task-1")
    assert len(findings) == 1
    f = findings[0]
    assert "NON-COMPLIANT" in f.title
    assert "15/22" in f.title
    assert "LT-TPL-L50" in f.title
    assert f.severity in (Severity.medium, Severity.high)
    ev = {e.key: e.value for e in f.evidence}
    assert ev.get("passed") == "15" and ev.get("failed") == "7"
    # failing controls are surfaced; passing ones are not the focus
    joined = " ".join(e.value for e in f.evidence)
    assert "PRT Status" in joined and "Cloud Kerberos Trust" in joined
    assert "Azure AD Joined" not in joined  # a PASSING control is not listed
    assert {r.id for r in f.references} >= {"T1550", "T1558"}


@pytest.mark.asyncio
async def test_get_task_status_completed_bundle_result_as_json_string():
    # PA sometimes returns result / bundle_results as a JSON STRING.
    result_str = json.dumps({"exit_code": 101, "bundle_results": json.dumps(_BUNDLE_RESULT)})
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/tasks/task-1").mock(
            return_value=httpx.Response(200, json=_task_resp("completed", result_str))
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await get_task_status(pa, "task-1")
    assert "NON-COMPLIANT" in findings[0].title and "15/22" in findings[0].title


@pytest.mark.asyncio
async def test_get_task_status_completed_compliant_bundle_is_info():
    clean = {**_BUNDLE_RESULT, "passed_controls": 22, "failed_controls": 0,
             "overall_exit_code": 0,
             "controls": [{"control_id": "c", "control_name": "x", "validator": "v",
                           "compliant": True, "severity": "info", "techniques": []}]}
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/tasks/task-1").mock(
            return_value=httpx.Response(200, json=_task_resp("completed", clean))
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await get_task_status(pa, "task-1")
    assert "COMPLIANT" in findings[0].title and "NON-COMPLIANT" not in findings[0].title
    assert findings[0].severity == Severity.info


@pytest.mark.asyncio
async def test_get_task_status_completed_non_bundle_uses_exit_code():
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/tasks/task-2").mock(
            return_value=httpx.Response(200, json=_task_resp(
                "completed", {"exit_code": 0}, test_name="Some Single Test"))
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await get_task_status(pa, "task-2")
    assert len(findings) == 1
    assert "Some Single Test" in findings[0].title


@pytest.mark.asyncio
async def test_get_task_status_completed_malformed_result_is_graceful():
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/tasks/task-3").mock(
            return_value=httpx.Response(200, json=_task_resp("completed", "not-json{"))
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await get_task_status(pa, "task-3")
    assert len(findings) == 1
    assert "completed" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_get_task_status_bounds_failing_controls_to_15():
    many = {**_BUNDLE_RESULT, "total_controls": 40, "passed_controls": 0, "failed_controls": 40,
            "overall_exit_code": 1,
            "controls": [{"control_id": f"c{i}", "control_name": f"ctl{i}",
                          "validator": "V", "compliant": False, "severity": "high",
                          "techniques": []} for i in range(40)]}
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/tasks/task-4").mock(
            return_value=httpx.Response(200, json=_task_resp("completed", many))
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await get_task_status(pa, "task-4")
    control_ev = [e for e in findings[0].evidence if e.key.startswith("failing_control")]
    assert len(control_ev) <= 15
    assert any("more" in e.value.lower() for e in findings[0].evidence)
```

(`BASE`, `_cfg`, `ProjectAchillesClient`, `Severity`, `httpx`, `respx`, `pytest`, `get_task_status` are already imported in this test file.)

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest servers/projectachilles-actions-mcp/tests/test_read_tools.py -v -k "bundle or non_bundle or malformed or bounds"`
Expected: FAIL — completed branch still returns "Task task-1: completed" and points at list_test_executions.

- [ ] **Step 3: Implement in `f0_pa_actions_mcp/tools.py`**

Add `import json` under the existing imports, and add `Reference` to the findings import block:

```python
import json
```
```python
from f0_sectools_core.schema.findings import (
    Entity,
    EntityKind,
    Evidence,
    Finding,
    FindingType,
    RecommendedAction,
    Reference,
    Severity,
)
```

Add helpers above `get_task_status` (after `_TASK_DONE_BAD`):

```python
_HIGH_SEV = ("critical", "high")
_MAX_FAILING = 15


def _as_dict(value: Any) -> dict[str, Any]:
    """Accept a dict or a JSON string; return {} on anything else/malformed."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _bundle_rollup(tid: str, host: str, result: dict[str, Any]) -> Finding | None:
    """One rollup Finding from a completed task's pre-aggregated bundle_results,
    or None when the result is not a bundle (caller falls back to exit_code)."""
    br = _as_dict(result.get("bundle_results"))
    if not br:
        return None
    name = str(br.get("bundle_name") or "bundle")
    total = int(br.get("total_controls") or 0)
    passed = int(br.get("passed_controls") or 0)
    failed = int(br.get("failed_controls") or 0)
    controls = br.get("controls") if isinstance(br.get("controls"), list) else []
    failing = [c for c in controls if isinstance(c, dict) and not c.get("compliant")]
    non_compliant = failed > 0 or int(br.get("overall_exit_code") or 0) != 0
    if non_compliant:
        any_high = any(str(c.get("severity", "")).lower() in _HIGH_SEV for c in failing)
        sev = Severity.high if any_high else Severity.medium
        ftype = FindingType.misconfig
        verdict = "NON-COMPLIANT"
    else:
        sev, ftype, verdict = Severity.info, FindingType.posture, "COMPLIANT"
    ev = [
        Evidence(key="verdict", value=verdict),
        Evidence(key="passed", value=str(passed)),
        Evidence(key="failed", value=str(failed)),
        Evidence(key="total", value=str(total)),
    ]
    for i, c in enumerate(failing[:_MAX_FAILING]):
        ev.append(Evidence(
            key=f"failing_control_{i + 1}",
            value=f"{c.get('control_name', '?')} ({c.get('validator', '?')}) "
            f"— {c.get('severity', '?')}",
        ))
    if len(failing) > _MAX_FAILING:
        ev.append(Evidence(key="failing_controls_more",
                           value=f"{len(failing) - _MAX_FAILING} more not shown"))
    techniques = {
        str(t) for c in failing for t in (c.get("techniques") or []) if t
    }
    return Finding(
        source=_SOURCE,
        finding_type=ftype,
        severity=sev,
        title=f"{name} on {host}: {verdict} ({passed}/{total} controls passed)",
        entity=Entity(kind=EntityKind.host, id=host, name=host) if host else None,
        evidence=ev,
        references=[Reference(type="mitre", id=t) for t in sorted(techniques)],
    )
```

Replace `get_task_status`'s completed handling. After computing `t`, `status`, `payload`, replace the `sev`/`evidence`/`summary`/return block with:

```python
    host = str(t.get("agent_hostname") or "")
    test_name = str(payload.get("test_name") or "test")

    if status == "completed":
        result = _as_dict(t.get("result"))
        rollup = _bundle_rollup(tid, host, result)
        if rollup is not None:
            return [rollup]
        # Non-bundle single test: use the exit code.
        exit_code = result.get("exit_code")
        if exit_code == 0 or exit_code == "0":
            return [Finding(
                source=_SOURCE, finding_type=FindingType.posture, severity=Severity.info,
                title=f"{test_name} on {host}: passed",
                entity=Entity(kind=EntityKind.host, id=host, name=host) if host else None,
                evidence=[Evidence(key="status", value="completed"),
                          Evidence(key="exit_code", value=str(exit_code))],
            )]
        if exit_code is not None:
            return [Finding(
                source=_SOURCE, finding_type=FindingType.misconfig, severity=Severity.medium,
                title=f"{test_name} on {host}: not passed",
                entity=Entity(kind=EntityKind.host, id=host, name=host) if host else None,
                evidence=[Evidence(key="status", value="completed"),
                          Evidence(key="exit_code", value=str(exit_code))],
            )]
        # Completed but no parsable outcome — graceful, never a crash.
        return [Finding(
            source=_SOURCE, finding_type=FindingType.posture, severity=Severity.info,
            title=f"Task {tid} on {host}: completed (outcome unavailable)",
            entity=Entity(kind=EntityKind.rule, id=tid),
            evidence=[Evidence(key="status", value="completed"),
                      Evidence(key="test_name", value=test_name)],
            recommended_action=RecommendedAction(
                summary="The task finished but returned no parsable result payload.",
                confidence="medium"),
        )]

    # Not completed (pending/assigned/.../failed/expired): status only.
    sev = Severity.medium if status in _TASK_DONE_BAD else Severity.info
    evidence = [
        Evidence(key="status", value=status),
        Evidence(key="test_name", value=test_name),
        Evidence(key="agent_id", value=str(t.get("agent_id") or "?")),
    ]
    if t.get("error"):
        evidence.append(Evidence(key="error", value=str(t["error"])))
    return [Finding(
        source=_SOURCE,
        finding_type=FindingType.posture,
        severity=sev,
        title=f"Task {tid}: {status}",
        entity=Entity(kind=EntityKind.rule, id=tid),
        evidence=evidence,
        recommended_action=RecommendedAction(
            summary=(
                "Still running (async, often minutes). I will not check again until "
                "you ask — say 'check the test' later."
            ) if status not in _TASK_DONE_BAD else
            "This task did not complete; run_test again if you still need the result.",
            confidence="high",
        ),
    )]
```

- [ ] **Step 4: Run tests, lint, type-check**

Run: `uv run pytest servers/projectachilles-actions-mcp/tests/test_read_tools.py -v && uv run ruff check servers/projectachilles-actions-mcp && uv run mypy .`
Expected: new tests PASS; the pre-existing `get_task_status` tests may assert the OLD strings — if any fail because they asserted "completed"/"Poll again later", update those specific assertions to the new titles/summaries (the behavior is intentionally changed for completed tasks; a running-task assertion on "poll" must move to the new wording). Clean.

- [ ] **Step 5: Commit**

```bash
git add servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py servers/projectachilles-actions-mcp/tests/test_read_tools.py
git commit -m "feat(pa-actions): get_task_status returns the completed run's bundle rollup"
```

---

### Task 2: No-poll wording on the launch findings (actions)

**Files:**
- Modify: `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py` (`run_test` success summary ~line 180; `schedule_test` success summary ~line 350; `get_task_status` docstring)
- Modify: `servers/projectachilles-actions-mcp/f0_pa_actions_mcp/server.py` (`get_task_status` tool docstring)
- Test: `servers/projectachilles-actions-mcp/tests/test_run_test.py` (append)

**Interfaces:** none new — wording only.

- [ ] **Step 1: Write the failing test** — append to `tests/test_run_test.py`:

```python
@pytest.mark.asyncio
async def test_run_test_success_summary_is_fire_and_report(tmp_path):
    with respx.mock() as router:
        _mock_reads(router)
        router.post(f"{BASE}/api/agent/admin/tasks").mock(
            return_value=httpx.Response(201, json={"data": {"task_ids": ["task-1"]}})
        )
        store = TokenStore(str(tmp_path / "pending"))
        token = store.issue("projectachilles.run_test", TARGET)
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await run_test(pa, _gate(tmp_path), UUID, "web-01", token)
    summary = findings[0].recommended_action.summary.lower()
    assert "ask me later" in summary
    assert "poll" not in summary
    assert "track it" not in summary
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest servers/projectachilles-actions-mcp/tests/test_run_test.py -v -k fire_and_report`
Expected: FAIL — current summary says "Track it with get_task_status…".

- [ ] **Step 3: Implement — reword three strings**

`run_test` success finding (the `summary=` at ~line 181):
```python
                summary="Submitted as task "
                f"{task_ids[0] if task_ids else '(id pending)'}; it runs "
                "asynchronously (often minutes). Ask me later and I'll check once "
                "with get_task_status — do not poll.",
```

`schedule_test` success finding (~line 350) — keep its list_schedules pointer but drop any poll implication (it already says "Verify with list_schedules; pause/resume…"). Leave as-is; it does not invite polling. (No change needed unless it contains "poll"/"track" — it does not.)

`get_task_status` docstring in `tools.py` (line 538) → 
```python
    """One-shot status-and-result check for one task_id (read).

    If the task is still running, report that and STOP — do not call again until
    the user asks. On completion this returns the run's OUTCOME (bundle verdict
    or pass/not-passed), so there is no need to poll or to call the read server.
    """
```

`get_task_status` tool docstring in `server.py` → mirror the same "one-shot, do not poll; returns the outcome on completion" guidance (read the current text and replace the "poll"/"track" framing).

- [ ] **Step 4: Run tests, lint, type-check**

Run: `uv run pytest servers/projectachilles-actions-mcp -v && uv run ruff check servers/projectachilles-actions-mcp && uv run mypy .`
Expected: all PASS (including Task 1's tests), clean

- [ ] **Step 5: Commit**

```bash
git add servers/projectachilles-actions-mcp/f0_pa_actions_mcp/tools.py servers/projectachilles-actions-mcp/f0_pa_actions_mcp/server.py servers/projectachilles-actions-mcp/tests/test_run_test.py
git commit -m "feat(pa-actions): fire-and-report launch, no-poll get_task_status guidance"
```

---

### Task 3: `list_test_executions` bundle rollup (read server)

**Files:**
- Modify: `servers/projectachilles-mcp/f0_projectachilles_mcp/tools.py` (`list_test_executions`, ~lines 391-460)
- Test: `servers/projectachilles-mcp/tests/test_tools.py` (append)

**Interfaces:** unchanged signature `async list_test_executions(pa, days=7, limit=25) -> list[Finding]`.

- [ ] **Step 1: Write the failing tests** — append to `servers/projectachilles-mcp/tests/test_tools.py` (match the file's existing respx/base-URL helpers; use its module `BASE`/client fixture):

```python
def _exec_rows(rows):
    return {"data": rows, "pagination": {"totalItems": len(rows)}}


def _bundle_row(cid, name, validator, protected):
    return {
        "is_bundle_control": True, "bundle_name": "Identity Endpoint Posture Bundle",
        "control_id": cid, "control_validator": validator, "test_name": name,
        "is_protected": protected, "hostname": "LT-TPL-L50", "severity": "high",
        "techniques": ["T1078.004"] if not protected else [],
        "timestamp": "2026-07-19T03:00:10Z", "category": "cyber-hygiene",
    }


@pytest.mark.asyncio
async def test_list_test_executions_rolls_up_a_bundle_run():
    rows = [_bundle_row(f"CH-{i}", f"ctl{i}", "Cloud Credential Protection",
                        protected=(i > 6)) for i in range(22)]  # 7 failing (i=0..6)
    with respx.mock() as router:
        router.get(f"{BASE}/api/analytics/executions/paginated").mock(
            return_value=httpx.Response(200, json=_exec_rows(rows))
        )
        async with _client() as pa:
            findings = await list_test_executions(pa, days=7, limit=25)
    # exactly ONE rollup finding for the bundle run, not 22 flat rows
    bundle_findings = [f for f in findings if "Identity Endpoint Posture Bundle" in f.title]
    assert len(bundle_findings) == 1
    f = bundle_findings[0]
    assert "15/22" in f.title and "LT-TPL-L50" in f.title
    ev = {e.key: e.value for e in f.evidence}
    assert ev.get("failed") == "7"


@pytest.mark.asyncio
async def test_list_test_executions_mixes_bundle_and_single_rows():
    single = {
        "is_bundle_control": False, "test_name": "Brute Force SSH",
        "is_protected": False, "hostname": "web-01", "severity": "high",
        "techniques": ["T1110"], "timestamp": "2026-07-19T01:00:00Z",
        "category": "security",
    }
    rows = [_bundle_row("CH-1", "ctl1", "V", protected=True),
            _bundle_row("CH-2", "ctl2", "V", protected=False), single]
    with respx.mock() as router:
        router.get(f"{BASE}/api/analytics/executions/paginated").mock(
            return_value=httpx.Response(200, json=_exec_rows(rows))
        )
        async with _client() as pa:
            findings = await list_test_executions(pa, days=7, limit=25)
    titles = " || ".join(f.title for f in findings)
    assert "Identity Endpoint Posture Bundle on LT-TPL-L50" in titles  # rollup
    assert "Brute Force SSH" in titles                                  # single row kept
    # one rollup + one single = 2 findings
    assert len(findings) == 2
```

(Use the test file's existing `_client()` / `BASE` helpers; if the file names them differently, match those.)

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest servers/projectachilles-mcp/tests/test_tools.py -v -k "rolls_up or mixes_bundle"`
Expected: FAIL — currently emits 22 flat findings, no rollup title.

- [ ] **Step 3: Implement in `f0_projectachilles_mcp/tools.py`**

In `list_test_executions`, after `rows = _rows(d)[:limit]` (keep the fetch/error handling as-is), split bundle-control rows from the rest, roll up the bundle groups, and keep the existing per-row path for non-bundle rows. Replace the `for x in _rows(d)[:limit]:` loop with:

```python
    rows = _rows(d)[:limit]
    bundle_rows = [r for r in rows if r.get("is_bundle_control")]
    single_rows = [r for r in rows if not r.get("is_bundle_control")]
    out: list[Finding] = []

    # Roll up bundle-control rows: one finding per (bundle, host) run.
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for r in bundle_rows:
        key = (str(r.get("bundle_name") or r.get("test_name") or "bundle"),
               str(r.get("hostname") or ""))
        groups.setdefault(key, []).append(r)
    for (bname, host), ctrls in groups.items():
        total = len(ctrls)
        failing = [c for c in ctrls if not c.get("is_protected")]
        passed = total - len(failing)
        non_compliant = bool(failing)
        sev = (
            _SEV.get("high", Severity.high) if non_compliant else Severity.info
        )
        ftype = FindingType.misconfig if non_compliant else FindingType.posture
        verdict = "NON-COMPLIANT" if non_compliant else "COMPLIANT"
        ev = [
            Evidence(key="verdict", value=verdict),
            Evidence(key="passed", value=str(passed)),
            Evidence(key="failed", value=str(len(failing))),
            Evidence(key="total", value=str(total)),
        ]
        for i, c in enumerate(failing[:15]):
            ev.append(Evidence(
                key=f"failing_control_{i + 1}",
                value=f"{c.get('test_name', '?')} ({c.get('control_validator', '?')})",
            ))
        if len(failing) > 15:
            ev.append(Evidence(key="failing_controls_more",
                               value=f"{len(failing) - 15} more not shown"))
        techniques = {str(t) for c in failing for t in (c.get("techniques") or []) if t}
        ent = Entity(kind=EntityKind.host, id=host, name=host) if host else None
        out.append(Finding(
            source="projectachilles",
            finding_type=ftype,
            severity=sev,
            title=f"{bname} on {host}: {verdict} ({passed}/{total} controls passed)",
            entity=ent,
            evidence=ev,
            references=[Reference(type="mitre", id=t) for t in sorted(techniques)],
            observed_at=ctrls[0].get("timestamp"),
        ))

    # Non-bundle rows keep the existing per-row security/hygiene vocabulary.
    for x in single_rows:
```

Then the body of the existing per-row loop stays exactly as it was (host/name/category branching → append), operating over `single_rows`, ending with `return out`.

- [ ] **Step 4: Run tests, lint, type-check**

Run: `uv run pytest servers/projectachilles-mcp -v && uv run ruff check servers/projectachilles-mcp && uv run mypy .`
Expected: new tests PASS; the pre-existing single-row execution tests stay green (their rows have no `is_bundle_control`, so they flow through `single_rows` unchanged). Clean.

- [ ] **Step 5: Commit**

```bash
git add servers/projectachilles-mcp/f0_projectachilles_mcp/tools.py servers/projectachilles-mcp/tests/test_tools.py
git commit -m "feat(projectachilles): roll up bundle runs in list_test_executions"
```

---

### Task 4: Docs — skill no-poll + READMEs + read-server skill notes

**Files:**
- Modify: `skills/projectachilles/run-validation-test/SKILL.md`
- Modify: `servers/projectachilles-actions-mcp/README.md`
- Modify: `skills/projectachilles/defense-posture-review/SKILL.md`, `skills/projectachilles/coverage-gap-analysis/SKILL.md`

- [ ] **Step 1: `run-validation-test` skill** — read the Procedure; replace the verify/track step so it says: launching a test is fire-and-report (the run is async, minutes); do NOT poll — make at most one `get_task_status` call per user request, and `get_task_status` returns the run's outcome (bundle verdict or pass/not-passed) on completion, so there's no need to call the read server for the result. Add a Pitfalls bullet: "Never loop get_task_status waiting for completion — tell the user you'll check when they ask." Keep frontmatter (description ≤60 chars) untouched. Run `uv run pytest skills/test_skills_valid.py` after.

- [ ] **Step 2: pa-actions README** — read the Setup/tools description; note that `get_task_status` returns the run outcome on completion (bundle rollup or single-test pass/not-passed) and is one-shot (not for polling).

- [ ] **Step 3: read-server skills** — in `defense-posture-review` and `coverage-gap-analysis` (wherever `list_test_executions` is described), add a one-line note: bundle runs are rolled up into a single per-run COMPLIANT/NON-COMPLIANT finding (X/Y controls) rather than one finding per control.

- [ ] **Step 4: Full verification**

Run: `uv run pytest && uv run ruff check . && uv run mypy .`
Expected: ALL PASS, clean. `git status --short` shows no real `.env*` staged.

- [ ] **Step 5: Commit**

```bash
git add skills/projectachilles/run-validation-test/SKILL.md servers/projectachilles-actions-mcp/README.md skills/projectachilles/defense-posture-review/SKILL.md skills/projectachilles/coverage-gap-analysis/SKILL.md
git commit -m "docs(pa): no-poll status guidance and bundle-rollup result notes"
```

---

## Plan Self-Review (done at write time)

- **Spec coverage:** Change A = Task 1 (get_task_status bundle rollup + non-bundle + graceful + bounded); Change B = Task 2 (fire-and-report + no-poll wording across run_test/get_task_status docstrings); Change C = Task 3 (list_test_executions bundle grouping, single rows unchanged); docs = Task 4. Spec milestone 5 (live pi) is user-gated — not a task.
- **Type consistency:** `_as_dict`/`_bundle_rollup` used only in Task 1; `_MAX_FAILING=15` and the read server's inline `15` both bound failing-control evidence; `Reference` imported in both files (added to actions in Task 1). Evidence keys `verdict/passed/failed/total/failing_control_N/failing_controls_more` identical between the two servers' rollups (parallel shaping, independent code — acceptable per thin-server rule).
- **Known judgment points:** (a) some pre-existing `get_task_status` tests assert the OLD completed/poll strings — Task 1 Step 4 and Task 2 flag updating those specific assertions (behavior intentionally changed). (b) The read test file's client/base-URL fixture names may differ — Task 3 says match the file's existing helpers. (c) Line numbers may drift — anchor on the quoted code.
