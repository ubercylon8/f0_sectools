"""Eval coverage guard.

The full small-model eval harness (driving a local model) is a future plan. Until
then these tests keep the eval task sets honest:

* the YAML is well-formed,
* every task names a tool that actually exists on its server, and
* every registered tool has at least one eval task (so a newly-added tool can't
  ship without a callability task).
"""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest
import yaml

EVALS = Path(__file__).parent

# (eval directory name, server module exposing `mcp`)
SERVERS = [
    ("defender", "f0_defender_mcp.server"),
    ("entra", "f0_entra_mcp.server"),
    ("limacharlie", "f0_limacharlie_mcp.server"),
    ("projectachilles", "f0_projectachilles_mcp.server"),
    ("intune", "f0_intune_mcp.server"),
    ("tenable", "f0_tenable_mcp.server"),
]


def _load_tasks(name: str) -> list[dict]:
    return yaml.safe_load((EVALS / name / "tasks.yaml").read_text())


async def _tool_names(module: str) -> set[str]:
    server = importlib.import_module(module)
    return {t.name for t in await server.mcp.list_tools()}


@pytest.mark.parametrize(("name", "module"), SERVERS)
def test_tasks_are_well_formed(name: str, module: str):
    tasks = _load_tasks(name)
    assert isinstance(tasks, list) and tasks, f"{name}: tasks.yaml must be a non-empty list"
    for t in tasks:
        assert isinstance(t.get("prompt"), str) and t["prompt"], f"{name}: task missing prompt"
        assert isinstance(t.get("expect_tool"), str) and t["expect_tool"], (
            f"{name}: missing expect_tool"
        )
        if "expect_args" in t:
            assert isinstance(t["expect_args"], dict)
        if "expect_args_contains" in t:
            assert isinstance(t["expect_args_contains"], dict)


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "module"), SERVERS)
async def test_eval_coverage_matches_registered_tools(name: str, module: str):
    real = await _tool_names(module)
    referenced = {t["expect_tool"] for t in _load_tasks(name)}
    assert referenced <= real, f"{name}: eval tasks name unknown tools {referenced - real}"
    assert real <= referenced, f"{name}: tools without an eval task {real - referenced}"
