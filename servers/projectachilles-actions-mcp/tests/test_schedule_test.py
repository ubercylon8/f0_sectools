"""schedule_test: flat-arg validation, config mapping, gate flow."""
from __future__ import annotations

import json

import httpx
import pytest
import respx
from f0_pa_actions_mcp.client import ProjectAchillesClient
from f0_pa_actions_mcp.resolve import ResolveFailed
from f0_pa_actions_mcp.tools import _schedule_config, schedule_test
from f0_sectools_core.auth.config import ProjectAchillesConfig
from f0_sectools_core.gating.actions import AuditLog, GatedAction, TokenStore

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


def _gate(tmp_path, enabled: bool = True) -> GatedAction:
    return GatedAction(
        "projectachilles.schedule_test",
        enabled=enabled,
        audit=AuditLog(str(tmp_path / "audit.log")),
        token_store=TokenStore(str(tmp_path / "pending")),
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


# ── _schedule_config mapping (pure function) ────────────────────────────────

def test_config_once():
    assert _schedule_config("once", "14:30", "2026-08-01", "", 0) == {
        "date": "2026-08-01", "time": "14:30"
    }


def test_config_daily():
    assert _schedule_config("daily", "02:30", "", "", 0) == {"time": "02:30"}


def test_config_weekly_sunday_is_zero():
    assert _schedule_config("weekly", "23:00", "", "sunday", 0) == {
        "days": [0], "time": "23:00"
    }


def test_config_weekly_monday_is_one():
    assert _schedule_config("weekly", "23:00", "", "monday", 0) == {
        "days": [1], "time": "23:00"
    }


def test_config_monthly():
    assert _schedule_config("monthly", "06:00", "", "", 15) == {
        "dayOfMonth": 15, "time": "06:00"
    }


@pytest.mark.parametrize(
    "args",
    [
        ("once", "14:30", "", "", 0),            # once without run_date
        ("once", "14:30", "08/01/2026", "", 0),  # bad date format
        ("weekly", "23:00", "", "", 0),          # weekly without day
        ("monthly", "06:00", "", "", 0),         # monthly without day_of_month
        ("monthly", "06:00", "", "", 32),        # day_of_month out of range
        ("daily", "2:30 AM", "", "", 0),         # bad time format
        ("daily", "25:00", "", "", 0),           # bad hour
        ("daily", "02:30", "2026-08-01", "", 0), # stray run_date for daily
        ("daily", "02:30", "", "monday", 0),     # stray day for daily
    ],
)
def test_config_invalid_combos_raise_guidance(args):
    with pytest.raises(ResolveFailed):
        _schedule_config(*args)


# ── gate flow ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_invalid_args_never_touch_network_or_gate(tmp_path):
    with respx.mock():   # NO routes mocked: any call would error
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await schedule_test(
                pa, _gate(tmp_path), UUID, "web-01", "weekly", "23:00"
            )
    assert "day" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_no_token_returns_intent_with_schedule_description(tmp_path):
    with respx.mock() as router:
        _mock_reads(router)
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await schedule_test(
                pa, _gate(tmp_path), UUID, "web-01", "weekly", "23:00", day="sunday"
            )
    f = findings[0]
    assert "Pending action" in f.title
    assert any(ev.key == "schedule" and "weekly" in ev.value for ev in f.evidence)
    assert TARGET in f.recommended_action.summary


@pytest.mark.asyncio
async def test_valid_token_posts_schedule_payload(tmp_path):
    with respx.mock() as router:
        _mock_reads(router)
        post = router.post(f"{BASE}/api/agent/admin/schedules").mock(
            return_value=httpx.Response(201, json={"data": {
                "id": "sched-1", "status": "active",
                "next_run_at": "2026-07-19T23:00:00Z",
            }})
        )
        store = TokenStore(str(tmp_path / "pending"))
        token = store.issue("projectachilles.schedule_test", TARGET)
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await schedule_test(
                pa, _gate(tmp_path), UUID, "web-01", "weekly", "23:00",
                day="sunday", confirmation_token=token,
            )
    assert post.call_count == 1
    body = json.loads(post.calls[0].request.content)
    assert body["schedule_type"] == "weekly"
    assert body["schedule_config"] == {"days": [0], "time": "23:00"}
    assert body["timezone"] == "UTC"
    assert body["org_id"] == "org-1"
    assert body["agent_ids"] == ["ag-1"]
    assert body["test_name"] == "Brute Force SSH"
    assert body["binary_name"] == "brute_force_ssh"
    assert "Action completed" in findings[0].title
    assert any(ev.value == "sched-1" for ev in findings[0].evidence)


@pytest.mark.asyncio
async def test_flag_off_refuses_schedule(tmp_path):
    with respx.mock() as router:
        _mock_reads(router)
        store = TokenStore(str(tmp_path / "pending"))
        token = store.issue("projectachilles.schedule_test", TARGET)
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await schedule_test(
                pa, _gate(tmp_path, enabled=False), UUID, "web-01", "daily",
                "02:30", confirmation_token=token,
            )
    assert "not taken" in findings[0].title
