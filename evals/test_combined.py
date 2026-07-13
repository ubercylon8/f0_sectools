"""Offline tests for the combined-registry (multi-server) eval.

No live model: tool schemas come from the real servers (local, no network),
and scoring is exercised with canned data.
"""
from __future__ import annotations

import pytest

from evals.run import (
    ToolCall,
    aggregate_by_origin,
    combined_tasks,
    combined_tool_schemas,
    run_suite,
)


@pytest.mark.asyncio
async def test_combined_registry_unions_all_34_tools():
    tools = await combined_tool_schemas()
    names = [t["function"]["name"] for t in tools]
    assert len(names) == 34, f"expected 34 tools, got {len(names)}"
    assert len(set(names)) == 34, "tool names must be unique across servers"
    # spot-check one tool from each server is present
    for expected in (
        "isolate_host",
        "list_risky_users",
        "query_telemetry",
        "get_defense_score",
        "list_assets",
    ):
        assert expected in names


def test_collision_guard_is_reachable():
    # The guard is a plain name-uniqueness check; assert the logic that backs it.
    # (A real collision can't be constructed without a duplicate-named server, so
    # we test the invariant the union relies on: all current names are unique.)
    import asyncio
    tools = asyncio.run(combined_tool_schemas())
    names = [t["function"]["name"] for t in tools]
    assert sorted(names) == sorted(set(names))


@pytest.mark.asyncio
async def test_combined_registry_raises_on_duplicate_name(monkeypatch):
    """Force every server to expose the same tool name so the union hits the
    duplicate-name branch, and assert combined_tool_schemas raises instead of
    silently deduplicating or overwriting."""
    import evals.run as run

    async def fake(server):
        return [{"type": "function", "function": {"name": "dup", "parameters": {}}}]

    monkeypatch.setattr(run, "server_tool_schemas", fake)
    with pytest.raises(ValueError):
        await run.combined_tool_schemas()


def test_combined_tasks_tagged_with_origin_and_include_probes():
    import yaml
    tasks = combined_tasks()
    # 12 defender + 8 entra + 8 limacharlie + 8 projectachilles + 8 intune + 8 tenable
    # = 52, plus probes.
    # Distinguish by checking against native task prompts.
    native_prompts = set()
    for server in ["defender", "entra", "limacharlie", "projectachilles", "intune", "tenable"]:
        with open(f"evals/{server}/tasks.yaml") as fh:
            native = yaml.safe_load(fh)
        native_prompts.update(t["prompt"] for t in (native or []))
    per_server = [t for t in tasks if t["prompt"] in native_prompts]
    assert len(per_server) == 52
    probes = [t for t in tasks if t["prompt"] not in native_prompts]
    assert len(probes) >= 6, "expected the cross-platform probe set"
    assert all("origin" in t and "prompt" in t and "expect_tool" in t for t in tasks)


@pytest.mark.asyncio
async def test_run_suite_records_calls():
    tasks = [{"prompt": "a", "expect_tool": "list_incidents", "origin": "defender"}]

    class _Fake:
        async def call(self, prompt, tools):
            return ToolCall("query_telemetry", {})  # wrong tool (misroute)

    report = await run_suite([], tasks, _Fake(), runs=2)
    assert report["tasks"][0]["calls"] == ["query_telemetry", "query_telemetry"]


def test_aggregate_by_origin_groups_and_counts_misroutes():
    tasks = [
        {"prompt": "a", "expect_tool": "list_incidents", "origin": "defender"},
        {"prompt": "b", "expect_tool": "get_secure_score", "origin": "defender"},
        {"prompt": "c", "expect_tool": "get_defense_score", "origin": "projectachilles"},
    ]
    report = {
        "tasks": [
            {"tool_rate": 0.0, "args_rate": 0.0, "calls": ["query_telemetry"]},  # misrouted
            {"tool_rate": 1.0, "args_rate": 1.0, "calls": ["get_secure_score"]},
            {"tool_rate": 1.0, "args_rate": 1.0, "calls": ["get_defense_score"]},
        ],
        "overall_tool_rate": 2 / 3, "overall_args_rate": 2 / 3,
    }
    agg = aggregate_by_origin(tasks, report)
    assert agg["defender"]["tool_rate"] == 0.5
    assert agg["defender"]["n"] == 2
    assert agg["defender"]["misroutes"] == {"query_telemetry": 1}
    assert agg["projectachilles"]["tool_rate"] == 1.0
    assert agg["projectachilles"]["misroutes"] == {}


def test_format_combined_report_shows_origins_and_misroutes():
    from evals.run import format_combined_report

    report = {"overall_tool_rate": 0.75, "overall_args_rate": 0.5, "tasks": []}
    agg = {
        "defender": {"tool_rate": 0.5, "args_rate": 0.5, "n": 2,
                     "misroutes": {"query_telemetry": 1}},
        "projectachilles": {"tool_rate": 1.0, "args_rate": 1.0, "n": 1, "misroutes": {}},
    }
    text = format_combined_report("gpt-oss:20b-c128k", report, agg)
    assert "defender" in text
    assert "query_telemetry" in text  # the misroute target is shown
    assert "75%" in text  # overall tool-selection
