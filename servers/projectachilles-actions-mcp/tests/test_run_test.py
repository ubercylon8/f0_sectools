"""run_test gate tests — most assertions are NEGATIVE SPACE (what did NOT happen)."""
from __future__ import annotations

import json

import httpx
import pytest
import respx
from f0_pa_actions_mcp.client import ProjectAchillesClient
from f0_pa_actions_mcp.tools import run_test
from f0_sectools_core.auth.config import ProjectAchillesConfig
from f0_sectools_core.gating.actions import ApprovalStore, AuditLog, GatedAction, TokenStore
from f0_sectools_core.schema.findings import FindingType

BASE = "https://org.agent.example.com"
UUID = "3f2a9c10-1111-4222-8333-444455556666"
TARGET = f"{UUID}@web-01"

TEST_RECORD = {
    "uuid": UUID, "name": "Brute Force SSH", "category": "credential-access",
    "subcategory": "brute-force", "severity": "high", "techniques": ["T1110"],
    "tactics": ["TA0006"], "threatActor": "APT29", "target": ["linux"],
    "complexity": "low", "tags": ["ssh"], "score": None, "integrations": [],
}
AGENTS = {"data": {"agents": [
    {"id": "ag-1", "org_id": "org-1", "hostname": "web-01", "status": "online"},
]}}
BUILD = {"data": {"exists": True, "filename": "brute_force_ssh"}}


def _cfg() -> ProjectAchillesConfig:
    return ProjectAchillesConfig(base_url=BASE, api_key="pa_test", allow_write=True)


def _gate(tmp_path, enabled: bool = True, confirm_mode: str = "token") -> GatedAction:
    return GatedAction(
        "projectachilles.run_test",
        enabled=enabled,
        audit=AuditLog(str(tmp_path / "audit.log")),
        token_store=TokenStore(str(tmp_path / "pending")),
        approvals=ApprovalStore(str(tmp_path / "gating")),
        confirm_mode=confirm_mode,
    )


def _mock_reads(router) -> None:
    router.get(f"{BASE}/api/browser/tests/{UUID}").mock(
        return_value=httpx.Response(200, json={"test": TEST_RECORD})
    )
    router.get(f"{BASE}/api/tests/builds/{UUID}").mock(
        return_value=httpx.Response(200, json=BUILD)
    )
    router.get(f"{BASE}/api/agent/admin/agents").mock(
        return_value=httpx.Response(200, json=AGENTS)
    )


@pytest.mark.asyncio
async def test_no_token_returns_intent_and_no_write_call(tmp_path):
    with respx.mock(assert_all_called=False) as router:
        _mock_reads(router)
        post = router.post(f"{BASE}/api/agent/admin/tasks")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await run_test(pa, _gate(tmp_path), UUID, "web-01")
    assert post.called is False                      # negative space
    assert len(findings) == 1
    f = findings[0]
    assert f.finding_type == FindingType.action
    assert "Pending action" in f.title
    assert f.recommended_action.gated_action == "projectachilles.run_test"
    # The intent must print the exact target string for confirm_action.py:
    assert TARGET in f.recommended_action.summary
    assert "--platform projectachilles" in f.recommended_action.summary


@pytest.mark.asyncio
async def test_flag_off_refuses_and_no_write_call(tmp_path):
    with respx.mock(assert_all_called=False) as router:
        _mock_reads(router)
        post = router.post(f"{BASE}/api/agent/admin/tasks")
        store = TokenStore(str(tmp_path / "pending"))
        token = store.issue("projectachilles.run_test", TARGET)
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await run_test(
                pa, _gate(tmp_path, enabled=False), UUID, "web-01", confirmation_token=token
            )
    assert post.called is False
    assert "not taken" in findings[0].title
    assert "PROJECTACHILLES_ALLOW_WRITE" in findings[0].recommended_action.summary


@pytest.mark.asyncio
async def test_wrong_target_token_refused(tmp_path):
    with respx.mock(assert_all_called=False) as router:
        _mock_reads(router)
        post = router.post(f"{BASE}/api/agent/admin/tasks")
        store = TokenStore(str(tmp_path / "pending"))
        token = store.issue("projectachilles.run_test", f"{UUID}@db-01")  # other host
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await run_test(pa, _gate(tmp_path), UUID, "web-01", confirmation_token=token)
    assert post.called is False
    assert "not taken" in findings[0].title


@pytest.mark.asyncio
async def test_valid_token_executes_posts_payload_and_audits(tmp_path):
    with respx.mock(assert_all_called=False) as router:
        _mock_reads(router)
        post = router.post(f"{BASE}/api/agent/admin/tasks").mock(
            return_value=httpx.Response(201, json={"data": {"task_ids": ["task-1"]}})
        )
        store = TokenStore(str(tmp_path / "pending"))
        token = store.issue("projectachilles.run_test", TARGET)
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await run_test(pa, _gate(tmp_path), UUID, "web-01", confirmation_token=token)
    assert post.call_count == 1
    body = json.loads(post.calls[0].request.content)
    assert body["org_id"] == "org-1"
    assert body["agent_ids"] == ["ag-1"]
    assert body["test_uuid"] == UUID
    assert body["test_name"] == "Brute Force SSH"
    assert body["binary_name"] == "brute_force_ssh"
    assert body["metadata"]["threat_actor"] == "APT29"
    assert "Action completed" in findings[0].title
    assert any(ev.value == "task-1" for ev in findings[0].evidence)
    assert (tmp_path / "audit.log").exists()          # audit line written
    # single-use: same token again is refused
    with respx.mock(assert_all_called=False) as router:
        _mock_reads(router)
        post2 = router.post(f"{BASE}/api/agent/admin/tasks")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings2 = await run_test(
                pa, _gate(tmp_path), UUID, "web-01", confirmation_token=token)
    assert post2.called is False
    assert "not taken" in findings2[0].title


@pytest.mark.asyncio
async def test_resolution_failure_returns_finding_and_never_consults_gate(tmp_path):
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/api/browser/tests/{UUID}").mock(
            return_value=httpx.Response(404, json={"error": "nope"})
        )
        post = router.post(f"{BASE}/api/agent/admin/tasks")
        store = TokenStore(str(tmp_path / "pending"))
        token = store.issue("projectachilles.run_test", TARGET)
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await run_test(pa, _gate(tmp_path), UUID, "web-01", confirmation_token=token)
    assert post.called is False
    assert "not found" in findings[0].title.lower()
    # token NOT consumed by a resolution failure:
    assert TokenStore(str(tmp_path / "pending")).consume(
        "projectachilles.run_test", TARGET, token
    )


@pytest.mark.asyncio
async def test_platform_403_after_token_maps_to_permission_finding(tmp_path):
    with respx.mock(assert_all_called=False) as router:
        _mock_reads(router)
        router.post(f"{BASE}/api/agent/admin/tasks").mock(
            return_value=httpx.Response(403, json={"error": "Missing permission"})
        )
        store = TokenStore(str(tmp_path / "pending"))
        token = store.issue("projectachilles.run_test", TARGET)
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await run_test(pa, _gate(tmp_path), UUID, "web-01", confirmation_token=token)
    assert "read-write" in (
        findings[0].title + findings[0].recommended_action.summary
    )


@pytest.mark.asyncio
async def test_run_test_intent_records_pending_request(tmp_path):
    with respx.mock(assert_all_called=False) as router:
        _mock_reads(router)
        router.post(f"{BASE}/api/agent/admin/tasks")
        gate = _gate(tmp_path)
        async with ProjectAchillesClient(_cfg()) as pa:
            await run_test(pa, gate, UUID, "web-01")
    pending = gate.approvals.list_pending()
    assert len(pending) == 1
    assert pending[0]["target"] == TARGET


@pytest.mark.asyncio
async def test_run_test_same_call_after_approval_executes(tmp_path):
    with respx.mock() as router:
        _mock_reads(router)
        post = router.post(f"{BASE}/api/agent/admin/tasks").mock(
            return_value=httpx.Response(201, json={"data": {"task_ids": ["task-1"]}})
        )
        gate = _gate(tmp_path)
        gate.approvals.approve("projectachilles.run_test", TARGET)
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await run_test(pa, gate, UUID, "web-01")
    assert post.call_count == 1
    assert "Action completed" in findings[0].title
    entry = json.loads((tmp_path / "audit.log").read_text().strip())
    assert entry["method"] == "approval"


@pytest.mark.asyncio
async def test_run_test_approval_for_other_host_still_intent(tmp_path):
    with respx.mock(assert_all_called=False) as router:
        _mock_reads(router)
        post = router.post(f"{BASE}/api/agent/admin/tasks")
        gate = _gate(tmp_path)
        gate.approvals.approve("projectachilles.run_test", f"{UUID}@db-01")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await run_test(pa, gate, UUID, "web-01")
    assert post.called is False
    assert "Pending action" in findings[0].title


@pytest.mark.asyncio
async def test_run_test_chat_mode_intent_text(tmp_path):
    with respx.mock(assert_all_called=False) as router:
        _mock_reads(router)
        router.post(f"{BASE}/api/agent/admin/tasks")
        gate = _gate(tmp_path, confirm_mode="chat")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await run_test(pa, gate, UUID, "web-01")
    summary = findings[0].recommended_action.summary
    assert "approved" in summary.lower()
    assert TARGET in summary  # the model is told to echo this exact target


@pytest.mark.asyncio
async def test_run_test_chat_echo_executes(tmp_path):
    with respx.mock() as router:
        _mock_reads(router)
        post = router.post(f"{BASE}/api/agent/admin/tasks").mock(
            return_value=httpx.Response(201, json={"data": {"task_ids": ["task-1"]}})
        )
        gate = _gate(tmp_path, confirm_mode="chat")
        async with ProjectAchillesClient(_cfg()) as pa:
            # The model echoes the target string as the confirmation.
            findings = await run_test(pa, gate, UUID, "web-01", confirmation_token=TARGET)
    assert post.call_count == 1
    assert "Action completed" in findings[0].title
    entry = json.loads((tmp_path / "audit.log").read_text().strip())
    assert entry["method"] == "chat-confirm"


@pytest.mark.asyncio
async def test_run_test_chat_wrong_echo_still_denied(tmp_path):
    with respx.mock(assert_all_called=False) as router:
        _mock_reads(router)
        post = router.post(f"{BASE}/api/agent/admin/tasks")
        gate = _gate(tmp_path, confirm_mode="chat")
        async with ProjectAchillesClient(_cfg()) as pa:
            wrong_target = f"{UUID}@wrong-host"
            findings = await run_test(pa, gate, UUID, "web-01",
                                      confirmation_token=wrong_target)
    assert post.called is False
    assert "not taken" in findings[0].title


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
            findings = await run_test(pa, _gate(tmp_path), UUID, "web-01", confirmation_token=token)
    summary = findings[0].recommended_action.summary.lower()
    assert "ask me later" in summary
    assert "poll" not in summary
    assert "track it" not in summary


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
            findings = await run_test(pa, _gate(tmp_path), UUID, "", tag="web",
                                      confirmation_token=token)
    assert post.call_count == 1
    body = json.loads(post.calls[0].request.content)
    assert body["agent_ids"] == ["ag-1", "ag-2"]
    assert body["org_id"] == "org-1"
    assert "2 host" in findings[0].title or "2 tasks" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_run_test_tag_drift_in_count_refuses(tmp_path):
    # Token issued for N=2; the tag now resolves to N=3 -> target mismatch -> refusal.
    # Drift -> refusal + no write; the stale token is spent, forcing fresh approval for N=3.
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
            findings = await run_test(pa, _gate(tmp_path), UUID, "", tag="web",
                                      confirmation_token=token)
    assert post.called is False
    assert "not taken" in findings[0].title
    # The drift attempt burned the token (single-use, unlink-before-validate);
    # the operator must re-preview and re-approve for the new fleet size.
    assert TokenStore(str(tmp_path / "pending")).consume(
        "projectachilles.run_test", TAG_TARGET, token) is False


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
            return_value=httpx.Response(200, json={"data": {"id": "a0", "org_id": "o",
                                                            "hostname": "h0"}}))
        router.post(f"{BASE}/api/agent/admin/tasks")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await run_test(pa, _gate(tmp_path), UUID, "", tag="web")
    host_ev = [e for e in findings[0].evidence if e.key.startswith("host_")
               and e.key != "host_count"]
    assert len(host_ev) <= 15
    assert any("more" in e.value.lower() for e in findings[0].evidence)
