"""Ungated reads: list_schedules and get_task_status."""
from __future__ import annotations

import json

import httpx
import pytest
import respx
from f0_pa_actions_mcp.client import ProjectAchillesClient
from f0_pa_actions_mcp.tools import get_task_status, list_schedules
from f0_sectools_core.auth.config import ProjectAchillesConfig
from f0_sectools_core.schema.findings import FindingType, Severity

BASE = "https://org.agent.example.com"


def _cfg() -> ProjectAchillesConfig:
    return ProjectAchillesConfig(base_url=BASE, api_key="pa_test")


SCHEDULES = {"data": [
    {"id": "sched-1", "name": "BF nightly", "test_name": "Brute Force SSH",
     "schedule_type": "daily", "status": "active",
     "next_run_at": "2026-07-19T02:30:00Z", "agent_ids": ["ag-1"]},
    {"id": "sched-2", "name": None, "test_name": "Ransomware Sim",
     "schedule_type": "weekly", "status": "paused",
     "next_run_at": None, "agent_ids": ["ag-1", "ag-2"]},
]}


@pytest.mark.asyncio
async def test_list_schedules_one_finding_per_schedule():
    with respx.mock() as router:
        route = router.get(f"{BASE}/api/agent/admin/schedules").mock(
            return_value=httpx.Response(200, json=SCHEDULES)
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await list_schedules(pa)
    assert route.calls[0].request.url.params.get("status") is None
    assert len(findings) == 2
    assert "BF nightly" in findings[0].title
    assert any(ev.key == "next_run_at" for ev in findings[0].evidence)
    assert any(ev.key == "agent_count" and ev.value == "2" for ev in findings[1].evidence)


@pytest.mark.asyncio
async def test_list_schedules_status_filter_passed_through():
    with respx.mock() as router:
        route = router.get(f"{BASE}/api/agent/admin/schedules").mock(
            return_value=httpx.Response(200, json={"data": []})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await list_schedules(pa, status="paused")
    assert route.calls[0].request.url.params["status"] == "paused"
    assert len(findings) == 1                     # honest empty summary finding
    assert "0" in findings[0].title


@pytest.mark.asyncio
async def test_get_task_status_completed_is_info():
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/tasks/task-1").mock(
            return_value=httpx.Response(200, json={"data": {
                "id": "task-1", "status": "completed", "agent_id": "ag-1",
                "payload": {"test_name": "Brute Force SSH"},
            }})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await get_task_status(pa, "task-1")
    f = findings[0]
    assert f.severity == Severity.info
    assert "completed" in f.title
    assert any(ev.key == "test_name" and "Brute Force" in ev.value for ev in f.evidence)


@pytest.mark.asyncio
async def test_get_task_status_failed_is_medium():
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/tasks/task-2").mock(
            return_value=httpx.Response(200, json={"data": {
                "id": "task-2", "status": "failed", "error": "timeout",
                "payload": {"test_name": "Ransomware Sim"},
            }})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await get_task_status(pa, "task-2")
    assert findings[0].severity == Severity.medium


@pytest.mark.asyncio
async def test_get_task_status_404_is_graceful():
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/tasks/gone").mock(
            return_value=httpx.Response(404, json={"error": "Task not found"})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await get_task_status(pa, "gone")
    assert len(findings) == 1
    assert "404" in findings[0].title


@pytest.mark.asyncio
async def test_get_task_status_empty_id_guides():
    async with ProjectAchillesClient(_cfg()) as pa:
        findings = await get_task_status(pa, " ")
    assert "task_id" in findings[0].title


def _task_resp(
    status,
    result=None,
    host="LT-TPL-L50",
    test_name="Identity Endpoint Posture Bundle",
):
    t = {
        "id": "task-1",
        "status": status,
        "agent_id": "ag-1",
        "agent_hostname": host,
        "payload": {"test_name": test_name},
    }
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
    f = findings[0]
    assert "Some Single Test" in f.title
    assert f.title.endswith(": passed")
    assert f.severity == Severity.info
    assert f.finding_type == FindingType.posture


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


@pytest.mark.asyncio
async def test_get_task_status_bundle_nonnumeric_counts_is_graceful():
    # Nonnumeric total_controls should not crash; and since controls is populated,
    # the trustworthy count is DERIVED from controls (not left as a bogus "N/0").
    broken = {**_BUNDLE_RESULT, "total_controls": "nope"}
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/tasks/task-5").mock(
            return_value=httpx.Response(200, json=_task_resp("completed", broken))
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await get_task_status(pa, "task-5")
    assert len(findings) == 1
    f = findings[0]
    assert "NON-COMPLIANT" in f.title  # Still rolled up despite broken count
    # _BUNDLE_RESULT.controls has 3 entries, 2 failing -> derived total=3, passed=1
    assert "1/3" in f.title
    ev = {e.key: e.value for e in f.evidence}
    assert ev.get("total") == "3" and ev.get("failed") == "2" and ev.get("passed") == "1"


@pytest.mark.asyncio
async def test_get_task_status_bundle_missing_counts_but_failing_control_is_noncompliant():
    # No total_controls/passed_controls/failed_controls/overall_exit_code keys at
    # all — only a controls list with one failing entry. The verdict must still be
    # NON-COMPLIANT (never fall back to COMPLIANT just because the count fields
    # are absent), and the N/M in the title must reflect the real controls list.
    bundle = {
        "bundle_name": "Identity Endpoint Posture Bundle",
        "controls": [
            {"control_id": "c1", "control_name": "OK Control", "validator": "V",
             "compliant": True, "severity": "info", "techniques": []},
            {"control_id": "c2", "control_name": "X", "validator": "V",
             "compliant": False, "severity": "critical", "techniques": ["T1"]},
        ],
    }
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/tasks/task-7").mock(
            return_value=httpx.Response(200, json=_task_resp("completed", bundle))
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await get_task_status(pa, "task-7")
    assert len(findings) == 1
    f = findings[0]
    assert "NON-COMPLIANT" in f.title
    assert "1/2" in f.title
    assert f.severity == Severity.high
    assert f.finding_type == FindingType.misconfig


@pytest.mark.asyncio
async def test_get_task_status_completed_non_bundle_failed_uses_exit_code():
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/tasks/task-6").mock(
            return_value=httpx.Response(200, json=_task_resp(
                "completed", {"exit_code": 1}, test_name="Some Single Test"))
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await get_task_status(pa, "task-6")
    assert len(findings) == 1
    f = findings[0]
    assert "not passed" in f.title
    assert "Some Single Test" in f.title
    assert f.finding_type.value == "misconfig"
    assert f.severity == Severity.medium


@pytest.mark.asyncio
async def test_get_task_status_empty_bundle_falls_through_to_exit_code():
    # Edge case: bundle_results with empty controls and no signal should
    # fall through to the exit_code verdict path, not report COMPLIANT.
    empty_bundle_fail = {
        "exit_code": 1,
        "bundle_results": {
            "bundle_name": "B",
            "controls": [],
        }
    }
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/tasks/task-empty-fail").mock(
            return_value=httpx.Response(200, json=_task_resp(
                "completed", empty_bundle_fail, test_name="Identity Bundle"))
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await get_task_status(pa, "task-empty-fail")
    assert len(findings) == 1
    f = findings[0]
    assert "not passed" in f.title
    assert "Identity Bundle" in f.title
    assert "COMPLIANT" not in f.title
    assert f.finding_type == FindingType.misconfig
    assert f.severity == Severity.medium

    # Companion: empty bundle with exit_code=0 should report passed
    empty_bundle_pass = {
        "exit_code": 0,
        "bundle_results": {
            "bundle_name": "B",
            "controls": [],
        }
    }
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/tasks/task-empty-pass").mock(
            return_value=httpx.Response(200, json=_task_resp(
                "completed", empty_bundle_pass, test_name="Identity Bundle"))
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            findings = await get_task_status(pa, "task-empty-pass")
    assert len(findings) == 1
    f = findings[0]
    assert f.title.endswith(": passed")
    assert f.finding_type == FindingType.posture
    assert f.severity == Severity.info
