"""Offline contract test for the agentic (multi-step) eval harness. No Ollama."""
from __future__ import annotations

import pytest

from evals.agentic import (
    SCENARIOS_DIR,
    SKILLS_DIR,
    load_scenario,
    make_mock_fn,
    run_scenario,
    score_run,
)
from evals.agentic_scorecard import render_agentic_md
from evals.run import AgentRun, ModelClient


class FakeModelClient(ModelClient):
    """A ModelClient whose _post_chat replays a scripted list of assistant messages
    instead of hitting the network. Each entry is an OpenAI `message` dict."""

    def __init__(self, scripted: list[dict]) -> None:
        super().__init__("http://fake/v1", "fake-model")
        self._scripted = list(scripted)

    async def _post_chat(self, messages, tools):  # type: ignore[override]
        return self._scripted.pop(0)


def _tool_msg(name: str, args: str = "{}") -> dict:
    return {"content": "", "tool_calls": [
        {"id": f"c_{name}", "function": {"name": name, "arguments": args}}]}


def _final(text: str) -> dict:
    return {"content": text, "tool_calls": []}


@pytest.mark.asyncio
async def test_run_agent_captures_trajectory_and_feeds_mocks():
    calls_seen = []

    def mock_fn(name, args):
        calls_seen.append(name)
        return [{"note": f"result for {name}"}]

    client = FakeModelClient([_tool_msg("list_incidents"),
                              _tool_msg("get_sensor"),
                              _final("web-01 shows T1110; user is risky.")])
    async with client:
        run = await client.run_agent("SYS", "triage it", tools=[], mock_fn=mock_fn)

    assert isinstance(run, AgentRun)
    assert run.trajectory == ["list_incidents", "get_sensor"]
    assert calls_seen == ["list_incidents", "get_sensor"]  # mocks were invoked
    assert "web-01" in run.final_answer
    assert run.error is None
    assert run.steps == 2  # two tool-call turns before the final answer


@pytest.mark.asyncio
async def test_run_agent_halts_at_max_steps():
    # a model that never stops calling tools
    client = FakeModelClient([_tool_msg("x")] * 20)
    async with client:
        run = await client.run_agent("SYS", "go", tools=[], mock_fn=lambda n, a: [{}], max_steps=3)
    assert run.error == "max_steps reached"
    assert len(run.trajectory) == 3


def _scenario() -> dict:
    return {
        "skill": "intune/coverage-gap-review",
        "task": "Which devices are stale or non-compliant?",
        "required_tools": ["get_compliance_summary", "list_stale_devices", "list_managed_devices"],
        "goal_keywords": ["stale", "unencrypt"],
        "mocks": {"get_compliance_summary": [{"x": 1}]},
    }


def test_make_mock_fn_returns_canned_then_graceful():
    fn = make_mock_fn(_scenario())
    assert fn("get_compliance_summary", {}) == [{"x": 1}]
    # a tool with no mock → graceful, non-crashing
    assert fn("list_stale_devices", {})[0]["note"].startswith("no mock")


def test_score_run_full_coverage_and_goal():
    run = AgentRun(
        trajectory=["get_compliance_summary", "list_stale_devices", "list_managed_devices"],
        final_answer="3 stale devices and several unencrypted ones.", steps=4, error=None)
    s = score_run(_scenario(), run)
    assert s["coverage"] == 1.0 and s["goal_reached"] and s["passed"]


def test_score_run_partial_coverage_fails():
    run = AgentRun(trajectory=["get_compliance_summary"],  # missing 2 required tools
                   final_answer="stale and unencrypt", steps=2, error=None)
    s = score_run(_scenario(), run)
    assert s["coverage"] == pytest.approx(1 / 3) and not s["passed"]


def test_score_run_goal_missed_fails():
    run = AgentRun(
        trajectory=["get_compliance_summary", "list_stale_devices", "list_managed_devices"],
        final_answer="everything looks fine",  # no goal keywords
        steps=4, error=None)
    s = score_run(_scenario(), run)
    assert s["coverage"] == 1.0 and not s["goal_reached"] and not s["passed"]


@pytest.mark.asyncio
async def test_run_scenario_end_to_end_scoring():
    """Offline integration test: FakeModelClient drives the real intune scenario's
    3 required tools then answers, through run_scenario (which also exercises
    combined_tool_schemas() — offline, reads server tool modules, no network)."""
    scenario = load_scenario(SCENARIOS_DIR / "intune-coverage-gap-review.yaml")
    client = FakeModelClient([
        _tool_msg("get_compliance_summary"),
        _tool_msg("list_stale_devices"),
        _tool_msg("list_managed_devices"),
        _final("306 devices are stale and some remain unencrypted."),
    ])
    async with client:
        scored = await run_scenario(client, scenario)

    assert scored["coverage"] == 1.0
    assert scored["goal_reached"]
    assert scored["passed"]


_SCENARIO_FILES = sorted(SCENARIOS_DIR.glob("*.yaml"))


def test_scenarios_exist():
    assert len(_SCENARIO_FILES) == 3


@pytest.mark.parametrize("path", _SCENARIO_FILES, ids=lambda p: p.stem)
def test_scenario_valid(path):
    s = load_scenario(path)
    for key in ("skill", "task", "required_tools", "goal_keywords", "mocks"):
        assert s.get(key), f"{path.name}: missing '{key}'"
    # the skill's SKILL.md exists and has a Procedure
    assert (SKILLS_DIR / s["skill"] / "SKILL.md").exists(), f"{path.name}: skill not found"
    # every required tool has a mock (so a full run is deterministic)
    for tool in s["required_tools"]:
        assert tool in s["mocks"], f"{path.name}: required tool '{tool}' has no mock"


@pytest.mark.parametrize("path", _SCENARIO_FILES, ids=lambda p: p.stem)
def test_goal_keywords_grounded_in_mocks_not_task(path):
    """Each goal keyword must appear in the mock tool OUTPUT and NOT in the task
    prompt — so goal-reached measures fact-derivation from tools, not echoing the
    question. (Guards the intune-scenario parroting bug found in review.)"""
    from evals.agentic import _synonyms
    s = load_scenario(path)
    mocks = str(s["mocks"]).lower()
    task = s["task"].lower()
    for concept in s["goal_keywords"]:
        syns = _synonyms(concept)
        # the concept must be reachable: at least one synonym appears in the mock output
        assert any(syn.lower() in mocks for syn in syns), (
            f"{path.name}: concept {concept!r} not grounded in any mock"
        )
        # and not parroteable: no synonym appears in the task prompt
        for syn in syns:
            assert syn.lower() not in task, (
                f"{path.name}: goal synonym '{syn}' is in the task (parroting risk)"
            )


def test_render_agentic_md_matrix():
    results = {
        "base_url": "http://localhost:11434/v1", "runs": 1, "date": "2026-07-12",
        "models": [{"tag": "granite4:tiny-h-c128k", "display": "Granite 4 Tiny"}],
        "skills": ["intune-coverage-gap-review"],
        "cells": {
            "granite4:tiny-h-c128k::intune-coverage-gap-review":
                {"coverage": 1.0, "goal_rate": 1.0, "runs": 1},
        },
    }
    md = render_agentic_md(results)
    assert "Granite 4 Tiny" in md
    assert "intune-coverage-gap-review" in md
    assert "100% / 100%" in md


def test_render_agentic_md_has_speed_footprint_table():
    results = {
        "base_url": "http://localhost:11434/v1", "runs": 1, "date": "2026-07-12",
        "models": [{"tag": "granite4:tiny-h-c128k", "display": "Granite 4 Tiny"}],
        "skills": ["intune-coverage-gap-review"],
        "cells": {
            "granite4:tiny-h-c128k::intune-coverage-gap-review":
                {"coverage": 1.0, "goal_rate": 1.0, "runs": 1, "latency_s": 4.2},
        },
        "perf": {"granite4:tiny-h-c128k": {"vram_gb": 6.1}},
    }
    md = render_agentic_md(results)
    assert "## Speed & footprint" in md
    assert "4.2s" in md          # median s/skill from the cell latency
    assert "6.1 GB" in md        # resident VRAM


def test_score_run_concept_group_matches_any_synonym():
    """A goal 'concept' can be a list of synonyms; the concept is satisfied if the
    answer contains ANY of them (fixes phrasing brittleness, e.g. 'flagged' for 'risky')."""
    scenario = {"required_tools": ["a"],
                "goal_keywords": ["web-01", ["risky", "high-risk", "flagged"]]}
    # answer says 'flagged', never the literal 'risky' — concept still captured
    run = AgentRun(trajectory=["a"],
                   final_answer="host web-01: the user is flagged for impossible travel.",
                   steps=1, error=None)
    s = score_run(scenario, run)
    assert s["goal_reached"] and s["passed"]


def test_score_run_concept_group_all_synonyms_absent_fails():
    scenario = {"required_tools": ["a"], "goal_keywords": [["risky", "flagged"]]}
    run = AgentRun(trajectory=["a"], final_answer="everything looks fine", steps=1, error=None)
    assert not score_run(scenario, run)["goal_reached"]
