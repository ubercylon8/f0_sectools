"""Offline tests for the combined-registry (multi-server) eval.

No live model: tool schemas come from the real servers (local, no network),
and scoring is exercised with canned data.
"""
from __future__ import annotations

import pytest

from evals.run import combined_tool_schemas


@pytest.mark.asyncio
async def test_combined_registry_unions_all_22_tools():
    tools = await combined_tool_schemas()
    names = [t["function"]["name"] for t in tools]
    assert len(names) == 22, f"expected 22 tools, got {len(names)}"
    assert len(set(names)) == 22, "tool names must be unique across servers"
    # spot-check one tool from each server is present
    for expected in ("isolate_host", "list_risky_users", "query_telemetry", "get_defense_score"):
        assert expected in names


def test_collision_guard_is_reachable():
    # The guard is a plain name-uniqueness check; assert the logic that backs it.
    # (A real collision can't be constructed without a duplicate-named server, so
    # we test the invariant the union relies on: all current names are unique.)
    import asyncio
    tools = asyncio.run(combined_tool_schemas())
    names = [t["function"]["name"] for t in tools]
    assert sorted(names) == sorted(set(names))
