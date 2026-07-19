"""Resolution tests: test/build/agent lookups fail gracefully BEFORE the gate."""
from __future__ import annotations

import httpx
import pytest
import respx
from f0_pa_actions_mcp.client import ProjectAchillesClient
from f0_pa_actions_mcp.resolve import (
    ResolveFailed,
    resolve_agent,
    resolve_agents_by_tag,
    resolve_build,
    resolve_selection,
    resolve_test,
)
from f0_sectools_core.auth.config import ProjectAchillesConfig

BASE = "https://org.agent.example.com"
UUID = "3f2a9c10-1111-4222-8333-444455556666"

TEST_RECORD = {
    "uuid": UUID,
    "name": "Brute Force SSH",
    "category": "credential-access",
    "subcategory": "brute-force",
    "severity": "high",
    "techniques": ["T1110"],
    "tactics": ["TA0006"],
    "threatActor": "APT29",
    "target": ["linux"],
    "complexity": "low",
    "tags": ["ssh"],
    "score": None,
    "integrations": [],
}


def _cfg() -> ProjectAchillesConfig:
    return ProjectAchillesConfig(base_url=BASE, api_key="pa_test")


@pytest.mark.asyncio
async def test_resolve_test_returns_uuid_name_and_snake_case_metadata():
    with respx.mock() as router:
        router.get(f"{BASE}/api/browser/tests/{UUID}").mock(
            return_value=httpx.Response(200, json={"test": TEST_RECORD})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            t = await resolve_test(pa, UUID)
    assert t["test_uuid"] == UUID
    assert t["test_name"] == "Brute Force SSH"
    md = t["metadata"]
    assert md["threat_actor"] == "APT29"          # camelCase -> snake_case
    assert md["techniques"] == ["T1110"]
    assert md["score"] is None
    # Zod TaskTestMetadataSchema requires ALL keys when metadata is present:
    for key in (
        "category", "subcategory", "severity", "techniques", "tactics",
        "threat_actor", "target", "complexity", "tags", "score", "integrations",
    ):
        assert key in md


@pytest.mark.asyncio
async def test_resolve_test_non_uuid_fails_with_guidance():
    async with ProjectAchillesClient(_cfg()) as pa:
        with pytest.raises(ResolveFailed) as ei:
            await resolve_test(pa, "brute force")
    assert "uuid" in ei.value.finding.title.lower()


@pytest.mark.asyncio
async def test_resolve_test_404_fails_with_not_found_finding():
    with respx.mock() as router:
        router.get(f"{BASE}/api/browser/tests/{UUID}").mock(
            return_value=httpx.Response(404, json={"error": "not found"})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            with pytest.raises(ResolveFailed) as ei:
                await resolve_test(pa, UUID)
    assert "not found" in ei.value.finding.title.lower()


@pytest.mark.asyncio
async def test_resolve_build_returns_filename():
    with respx.mock() as router:
        router.get(f"{BASE}/api/tests/builds/{UUID}").mock(
            return_value=httpx.Response(
                200,
                json={"success": True, "data": {"exists": True, "filename": "brute_force_ssh"}},
            )
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            assert await resolve_build(pa, UUID) == "brute_force_ssh"


@pytest.mark.asyncio
async def test_resolve_build_not_built_is_200_exists_false():
    with respx.mock() as router:
        router.get(f"{BASE}/api/tests/builds/{UUID}").mock(
            return_value=httpx.Response(200, json={"success": True, "data": {"exists": False}})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            with pytest.raises(ResolveFailed) as ei:
                await resolve_build(pa, UUID)
    assert "not built" in ei.value.finding.title.lower()


AGENTS = {
    "success": True,
    "data": {
        "agents": [
            {"id": "ag-1", "org_id": "org-1", "hostname": "web-01", "status": "online"},
            {"id": "ag-2", "org_id": "org-1", "hostname": "db-01", "status": "online"},
        ]
    },
}


@pytest.mark.asyncio
async def test_resolve_agent_exact_case_insensitive_match():
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/agents").mock(
            return_value=httpx.Response(200, json=AGENTS)
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            a = await resolve_agent(pa, "WEB-01")
    assert a == {"agent_id": "ag-1", "org_id": "org-1", "hostname": "web-01"}


@pytest.mark.asyncio
async def test_resolve_agent_org_id_from_detail_when_list_strips_it():
    # Live shape (verified 2026-07-18): the admin LIST endpoint strips org_id,
    # but the single-agent DETAIL endpoint keeps it. resolve_agent must fall
    # back to detail so the write payload's org_id is never empty (else the
    # backend 400s on "org_id is required").
    stripped = {"data": {"agents": [
        {"id": "ag-1", "hostname": "web-01", "status": "active"},  # no org_id
    ]}}
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/agents").mock(
            return_value=httpx.Response(200, json=stripped)
        )
        router.get(f"{BASE}/api/agent/admin/agents/ag-1").mock(
            return_value=httpx.Response(
                200, json={"data": {"id": "ag-1", "org_id": "default", "hostname": "web-01"}}
            )
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            a = await resolve_agent(pa, "web-01")
    assert a == {"agent_id": "ag-1", "org_id": "default", "hostname": "web-01"}


@pytest.mark.asyncio
async def test_resolve_agent_no_match_lists_guidance():
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/agents").mock(
            return_value=httpx.Response(200, json=AGENTS)
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            with pytest.raises(ResolveFailed) as ei:
                await resolve_agent(pa, "gone-99")
    assert "gone-99" in ei.value.finding.title


@pytest.mark.asyncio
async def test_resolve_agent_ambiguous_lists_candidates():
    dup = {
        "success": True,
        "data": {"agents": [
            {"id": "ag-1", "org_id": "org-1", "hostname": "web-01"},
            {"id": "ag-9", "org_id": "org-1", "hostname": "web-01"},
        ]},
    }
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/agents").mock(
            return_value=httpx.Response(200, json=dup)
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            with pytest.raises(ResolveFailed) as ei:
                await resolve_agent(pa, "web-01")
    ev = ei.value.finding.evidence
    assert {e.value for e in ev} >= {"ag-1", "ag-9"}


@pytest.mark.asyncio
async def test_resolve_agent_empty_hostname_guides():
    async with ProjectAchillesClient(_cfg()) as pa:
        with pytest.raises(ResolveFailed):
            await resolve_agent(pa, "  ")


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
async def test_resolve_agents_by_tag_non_int_total_still_refuses_at_limit():
    # When total is a non-int (string or float), the guard must fall back to
    # the len(agents) >= _MAX_FLEET check and refuse. This verifies the safety:
    # if the backend ever returns total as a non-int, we don't silently proceed
    # on the limit-capped agents list.
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/agents").mock(
            return_value=httpx.Response(200, json={"data": {
                "agents": [{"id": f"a{i}", "hostname": f"h{i}"} for i in range(200)],
                "total": "512",  # string, not int
            }})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            with pytest.raises(ResolveFailed) as ei:
                await resolve_agents_by_tag(pa, "everything")
    assert "narrow" in ei.value.finding.title.lower() or "narrow" in \
        ei.value.finding.recommended_action.summary.lower()


@pytest.mark.asyncio
async def test_resolve_agents_by_tag_non_int_total_float_refuses_at_limit():
    # Same test: if total is a float (e.g. 512.0), the guard must fall back to
    # the len(agents) >= _MAX_FLEET check and refuse.
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/agents").mock(
            return_value=httpx.Response(200, json={"data": {
                "agents": [{"id": f"a{i}", "hostname": f"h{i}"} for i in range(200)],
                "total": 512.0,  # float, not int
            }})
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            with pytest.raises(ResolveFailed) as ei:
                await resolve_agents_by_tag(pa, "everything")
    assert "narrow" in ei.value.finding.title.lower() or "narrow" in \
        ei.value.finding.recommended_action.summary.lower()


@pytest.mark.asyncio
async def test_resolve_agents_by_tag_id_and_host_lists_stay_aligned():
    # When tag response includes a record with no id, both agent_ids and hostnames
    # must drop it to stay aligned (no index mismatch).
    mixed = {"data": {"agents": [
        {"id": "ag-1", "hostname": "h1"},
        {"hostname": "h-noid"},  # missing id — must be dropped from BOTH lists
        {"id": "ag-3", "hostname": "h3"},
    ], "total": 3}}
    with respx.mock() as router:
        router.get(f"{BASE}/api/agent/admin/agents").mock(
            return_value=httpx.Response(200, json=mixed)
        )
        router.get(f"{BASE}/api/agent/admin/agents/ag-1").mock(
            return_value=httpx.Response(200, json=DETAIL)
        )
        async with ProjectAchillesClient(_cfg()) as pa:
            r = await resolve_agents_by_tag(pa, "mixed")
    assert len(r["agent_ids"]) == len(r["hostnames"])  # aligned
    assert r["agent_ids"] == ["ag-1", "ag-3"]  # id-less record dropped
    assert r["hostnames"] == ["h1", "h3"]  # corresponding hostname also dropped


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
