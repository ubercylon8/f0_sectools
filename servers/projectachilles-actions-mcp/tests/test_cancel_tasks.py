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
    title = findings[0].title.lower()
    summary = findings[0].recommended_action.summary.lower()
    assert "task_id" in title or "either" in summary


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
async def test_cancel_tasks_enumeration_still_requests_201(tmp_path):
    with respx.mock(assert_all_called=False) as router:
        get = router.get(f"{BASE}/api/agent/admin/tasks").mock(return_value=_tasks(["t1"]))
        router.post(url__regex=rf"{BASE}/api/agent/admin/tasks/.+/cancel")
        async with ProjectAchillesClient(_cfg()) as pa:
            await cancel_tasks(pa, _gate(tmp_path), status="pending")
    assert "limit=201" in str(get.calls[0].request.url)  # NOT clamped to 100


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
    # Non-int total must NOT bypass the cap: the cap triggers on the actual
    # returned row count (201, over the 200 max) regardless of total's type.
    over = httpx.Response(200, json={"success": True, "data": {
        "tasks": [{"id": f"t{i}", "status": "pending"} for i in range(201)], "total": "lots"}})
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/api/agent/admin/tasks").mock(return_value=over)
        cancel = router.post(url__regex=rf"{BASE}/api/agent/admin/tasks/.+/cancel")
        async with ProjectAchillesClient(_cfg()) as pa:
            await cancel_tasks(pa, _gate(tmp_path), status="pending")
    assert cancel.called is False


@pytest.mark.asyncio
async def test_bulk_int_undercount_total_still_capped(tmp_path):
    # An int-but-wrong total (5) must not let 201 real rows sneak under the cap.
    over = httpx.Response(200, json={"success": True, "data": {
        "tasks": [{"id": f"t{i}", "status": "pending"} for i in range(201)], "total": 5}})
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/api/agent/admin/tasks").mock(return_value=over)
        cancel = router.post(url__regex=rf"{BASE}/api/agent/admin/tasks/.+/cancel")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await cancel_tasks(pa, _gate(tmp_path), status="pending")
    assert cancel.called is False
    assert "200" in (findings[0].title + findings[0].recommended_action.summary)


@pytest.mark.asyncio
async def test_bulk_truncated_page_refused(tmp_path):
    # total (150) disagrees with the returned page (100 rows) -> the server
    # truncated; binding the confirmation to 150 while only fetching 100 would
    # under-cancel silently, so refuse instead.
    truncated = httpx.Response(200, json={"success": True, "data": {
        "tasks": [{"id": f"t{i}", "status": "pending"} for i in range(100)], "total": 150}})
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/api/agent/admin/tasks").mock(return_value=truncated)
        cancel = router.post(url__regex=rf"{BASE}/api/agent/admin/tasks/.+/cancel")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await cancel_tasks(pa, _gate(tmp_path), status="pending")
    assert cancel.called is False
    assert "truncated" in findings[0].title.lower() or "inconsistent" in findings[0].title.lower()


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
async def test_bulk_mid_batch_403_is_audited_and_reported_as_interrupted(tmp_path):
    # t1/t2 cancel fine, t3 returns 403 -> the batch must stop WITHOUT raising
    # past execute_async (or the audit write in core/gating never fires: Rule 8).
    gate = _gate(tmp_path)
    store = TokenStore(str(tmp_path / "pending"))
    token = store.issue("projectachilles.cancel_tasks", "cancel:pending:*:3")
    with respx.mock as router:
        router.get(f"{BASE}/api/agent/admin/tasks").mock(return_value=_tasks(["t1", "t2", "t3"]))
        c1 = router.post(f"{BASE}/api/agent/admin/tasks/t1/cancel").mock(
            return_value=httpx.Response(200, json={"success": True, "data": {}}))
        c2 = router.post(f"{BASE}/api/agent/admin/tasks/t2/cancel").mock(
            return_value=httpx.Response(200, json={"success": True, "data": {}}))
        c3 = router.post(f"{BASE}/api/agent/admin/tasks/t3/cancel").mock(
            return_value=httpx.Response(403, json={"error": "forbidden"}))
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await cancel_tasks(pa, gate, status="pending", confirmation_token=token)
    assert c1.called and c2.called and c3.called
    finding = findings[0]
    assert len(findings) == 1  # not a bare permission-missing finding
    assert "interrupted" in finding.title.lower()
    assert any(ev.key == "cancelled" and ev.value == "2" for ev in finding.evidence)
    assert any(ev.key == "interrupted" for ev in finding.evidence)
    # Rule 8: every write action is audited, even a partial batch.
    audit_path = tmp_path / "audit.log"
    assert audit_path.is_file()
    audit_text = audit_path.read_text()
    assert audit_text.strip() != ""
    assert "cancel:pending:*:3" in audit_text


@pytest.mark.asyncio
async def test_bulk_mid_batch_transport_error_interrupted(tmp_path):
    # t1 cancels fine, t2 raises a transport error -> must not escape as an
    # exception; the audited interrupted path is used instead (Rule 8).
    gate = _gate(tmp_path)
    store = TokenStore(str(tmp_path / "pending"))
    token = store.issue("projectachilles.cancel_tasks", "cancel:pending:*:2")
    with respx.mock as router:
        router.get(f"{BASE}/api/agent/admin/tasks").mock(return_value=_tasks(["t1", "t2"]))
        c1 = router.post(f"{BASE}/api/agent/admin/tasks/t1/cancel").mock(
            return_value=httpx.Response(200, json={"success": True, "data": {}}))
        c2 = router.post(f"{BASE}/api/agent/admin/tasks/t2/cancel").mock(
            side_effect=httpx.ConnectError("boom"))
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await cancel_tasks(pa, gate, status="pending", confirmation_token=token)
    assert c1.called and c2.called
    finding = findings[0]
    assert len(findings) == 1
    assert any(ev.key == "cancelled" and ev.value == "1" for ev in finding.evidence)
    assert any(ev.key == "interrupted" for ev in finding.evidence)
    audit_path = tmp_path / "audit.log"
    assert audit_path.is_file()
    assert audit_path.read_text().strip() != ""


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
