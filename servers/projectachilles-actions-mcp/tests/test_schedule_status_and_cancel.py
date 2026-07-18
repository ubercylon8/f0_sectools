"""set_schedule_status + cancel_task gate tests."""
from __future__ import annotations

import json

import httpx
import pytest
import respx
from f0_pa_actions_mcp.client import ProjectAchillesClient
from f0_pa_actions_mcp.tools import cancel_task, set_schedule_status
from f0_sectools_core.auth.config import ProjectAchillesConfig
from f0_sectools_core.gating.actions import AuditLog, GatedAction, TokenStore

BASE = "https://org.agent.example.com"


def _cfg() -> ProjectAchillesConfig:
    return ProjectAchillesConfig(base_url=BASE, api_key="pa_test", allow_write=True)


def _gate(tmp_path, name: str, enabled: bool = True) -> GatedAction:
    return GatedAction(
        name,
        enabled=enabled,
        audit=AuditLog(str(tmp_path / "audit.log")),
        token_store=TokenStore(str(tmp_path / "pending")),
    )


@pytest.mark.asyncio
async def test_pause_no_token_returns_intent_no_call(tmp_path):
    with respx.mock(assert_all_called=False) as router:
        patch = router.patch(f"{BASE}/api/agent/admin/schedules/sched-1")
        gate = _gate(tmp_path, "projectachilles.set_schedule_status")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await set_schedule_status(pa, gate, "sched-1", "paused")
    assert patch.called is False
    assert "Pending action" in findings[0].title
    assert "sched-1:paused" in findings[0].recommended_action.summary


@pytest.mark.asyncio
async def test_pause_token_bound_to_status_not_reusable_for_resume(tmp_path):
    with respx.mock(assert_all_called=False) as router:
        patch = router.patch(f"{BASE}/api/agent/admin/schedules/sched-1")
        gate = _gate(tmp_path, "projectachilles.set_schedule_status")
        store = TokenStore(str(tmp_path / "pending"))
        token = store.issue("projectachilles.set_schedule_status", "sched-1:paused")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await set_schedule_status(pa, gate, "sched-1", "active", token)
    assert patch.called is False                 # pause token can't resume
    assert "not taken" in findings[0].title


@pytest.mark.asyncio
async def test_pause_valid_token_patches_status(tmp_path):
    with respx.mock() as router:
        patch = router.patch(f"{BASE}/api/agent/admin/schedules/sched-1").mock(
            return_value=httpx.Response(200, json={"data": {
                "id": "sched-1", "status": "paused", "next_run_at": None,
            }})
        )
        gate = _gate(tmp_path, "projectachilles.set_schedule_status")
        store = TokenStore(str(tmp_path / "pending"))
        token = store.issue("projectachilles.set_schedule_status", "sched-1:paused")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await set_schedule_status(pa, gate, "sched-1", "paused", token)
    assert patch.call_count == 1
    assert json.loads(patch.calls[0].request.content) == {"status": "paused"}
    assert "Action completed" in findings[0].title
    assert any(ev.key == "status" and ev.value == "paused" for ev in findings[0].evidence)


@pytest.mark.asyncio
async def test_empty_schedule_id_guides_without_gate(tmp_path):
    gate = _gate(tmp_path, "projectachilles.set_schedule_status")
    async with ProjectAchillesClient(_cfg()) as pa:
        findings = await set_schedule_status(pa, gate, "  ", "paused")
    assert "schedule_id" in findings[0].title


@pytest.mark.asyncio
async def test_bad_charset_schedule_id_guides_without_gate(tmp_path):
    gate = _gate(tmp_path, "projectachilles.set_schedule_status")
    with respx.mock(assert_all_called=False):
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await set_schedule_status(pa, gate, "sched;rm -rf", "paused")
    assert len(findings) == 1
    assert "unsupported characters" in findings[0].title


@pytest.mark.asyncio
async def test_bad_charset_task_id_guides_without_gate(tmp_path):
    gate = _gate(tmp_path, "projectachilles.cancel_task")
    with respx.mock(assert_all_called=False):
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await cancel_task(pa, gate, "$(curl evil)")
    assert len(findings) == 1
    assert "unsupported characters" in findings[0].title


@pytest.mark.asyncio
async def test_cancel_no_token_returns_intent(tmp_path):
    with respx.mock(assert_all_called=False) as router:
        post = router.post(f"{BASE}/api/agent/admin/tasks/task-1/cancel")
        gate = _gate(tmp_path, "projectachilles.cancel_task")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await cancel_task(pa, gate, "task-1")
    assert post.called is False
    assert "Pending action" in findings[0].title


@pytest.mark.asyncio
async def test_cancel_valid_token_posts_and_reports_status(tmp_path):
    with respx.mock() as router:
        post = router.post(f"{BASE}/api/agent/admin/tasks/task-1/cancel").mock(
            return_value=httpx.Response(200, json={"data": {
                "id": "task-1", "status": "expired",
            }})
        )
        gate = _gate(tmp_path, "projectachilles.cancel_task")
        store = TokenStore(str(tmp_path / "pending"))
        token = store.issue("projectachilles.cancel_task", "task-1")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await cancel_task(pa, gate, "task-1", token)
    assert post.call_count == 1
    assert "Action completed" in findings[0].title


@pytest.mark.asyncio
async def test_cancel_terminal_task_400_becomes_finding(tmp_path):
    with respx.mock() as router:
        post = router.post(f"{BASE}/api/agent/admin/tasks/task-1/cancel").mock(
            return_value=httpx.Response(400, json={"error": "task already terminal"})
        )
        gate = _gate(tmp_path, "projectachilles.cancel_task")
        store = TokenStore(str(tmp_path / "pending"))
        token = store.issue("projectachilles.cancel_task", "task-1")
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await cancel_task(pa, gate, "task-1", token)
    assert post.call_count == 1
    assert len(findings) == 1
    assert "rejected" in findings[0].title.lower()
